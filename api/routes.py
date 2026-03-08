from flask import Blueprint, jsonify, request
import logging
import time
import ipaddress as ipaddr
from scanner import NetworkScanner
from scanner.utils import ping_once, reverse_dns, get_mac_address, get_vendor, classify_status, guess_device_type
from scanner.device import DeviceInfo

api_bp = Blueprint('api', __name__)
logger = logging.getLogger(__name__)
scanner = NetworkScanner()

@api_bp.route('/subnets', methods=['GET'])
def get_subnets():
    try:
        subs = scanner.candidate_subnets()
        logger.info(f"Found {len(subs)} subnets")
        return jsonify({"subnets": subs})
    except Exception as e:
        logger.error(f"Error getting subnets: {e}")
        return jsonify({"error": str(e)}), 500

@api_bp.route('/scan', methods=['GET'])
def start_scan():
    cidr = request.args.get('cidr')
    mode = request.args.get('deep', 'false').lower()
    limit = int(request.args.get('limit', 254))
    
    if not cidr:
        return jsonify({"error": "CIDR parameter is required"}), 400
    
    try:
        start_time = time.time()
        
        # Define scan parameters based on mode
        ports = None
        grab_banners = False
        deep_scan_bool = False
        
        if mode == 'true' or mode == 'standard':
            ports = scanner.config.COMMON_PORTS
            deep_scan_bool = True
        elif mode == 'advanced':
            ports = sorted(list(set(scanner.config.COMMON_PORTS + scanner.config.WEB_PORTS + scanner.config.IOT_PORTS)))
            grab_banners = True
            deep_scan_bool = True
        elif mode == 'iot':
            ports = scanner.config.IOT_PORTS
            grab_banners = True
            deep_scan_bool = True
        elif mode == 'quick':
            deep_scan_bool = False
            
        def scan_work():
            # We bypass the default scan_cidr to inject our custom ports/banners
            from scanner.utils import guess_os # Changed from .utils to scanner.utils
            try:
                net = ipaddr.ip_network(cidr, strict=False)
            except Exception: return []
            targets = [str(ip) for i, ip in enumerate(net.hosts()) if i < limit]
            results = []
            
            def single_work(ip):
                st, lat, ttl = ping_once(ip)
                if st == "down": return None
                host = reverse_dns(ip)
                mac = get_mac_address(ip)
                vendor = get_vendor(mac)
                
                open_ports, banners = ([], {})
                if deep_scan_bool:
                    open_ports, banners = scanner.scan_ports(ip, ports=ports, grab_banners=grab_banners)
                
                status_meta = classify_status(lat)
                device_type = guess_device_type(host, mac, open_ports, ttl)
                os_guess = guess_os(ttl)
                return DeviceInfo(
                    ip=ip, hostname=host, latency=lat, mac_address=mac, vendor=vendor,
                    open_ports=open_ports, status=status_meta["label"],
                    statusColor=status_meta["color"], last_seen=time.time(),
                    device_type=device_type, banners=banners, os_guess=os_guess
                ).to_dict()

            with concurrent.futures.ThreadPoolExecutor(max_workers=scanner.config.MAX_WORKERS) as ex:
                for item in ex.map(single_work, targets):
                    if item: results.append(item)
            return sorted(results, key=lambda x: ipaddr.ip_address(x['ip']))

        devices = scan_work()
        scan_time = round(time.time() - start_time, 2)
        
        return jsonify({
            "devices": devices,
            "count": len(devices),
            "scan_time": scan_time,
            "cidr": cidr
        })
    except Exception as e:
        logger.error(f"Scan error: {e}")
        return jsonify({"error": str(e)}), 500

@api_bp.route('/device/<ip>', methods=['GET'])
def get_device_detail(ip):
    try:
        ipaddr.ip_address(ip)
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400
    try:
        from scanner.utils import guess_os
        st, lat, ttl = ping_once(ip)
        if st == "down":
            return jsonify({"error": "Device unreachable"}), 404
        host = reverse_dns(ip)
        mac = get_mac_address(ip)
        vendor = get_vendor(mac) if mac else None
        open_ports, banners = scanner.scan_ports(ip, grab_banners=True)
        status_meta = classify_status(lat)
        device_type = guess_device_type(host, mac, open_ports, ttl)
        os_guess = guess_os(ttl)
        device = DeviceInfo(
            ip=ip, hostname=host, latency=lat, mac_address=mac, vendor=vendor,
            open_ports=open_ports, status=status_meta["label"],
            statusColor=status_meta["color"], last_seen=time.time(), 
            device_type=device_type, banners=banners, os_guess=os_guess
        )
        return jsonify(device.to_dict())
    except Exception as e:
        logger.error(f"Error getting device details: {e}")
        return jsonify({"error": str(e)}), 500

@api_bp.route('/device/<ip>/wol', methods=['POST'])
def wol_device(ip):
    try:
        data = request.json
        mac = data.get('mac') if data else None
        if not mac:
            mac = get_mac_address(ip)
        if not mac:
            return jsonify({"error": "No MAC address available for Wake on LAN"}), 404
            
        import socket, struct
        # Parse MAC
        mac_clean = mac.replace(':', '').replace('-', '')
        if len(mac_clean) != 12:
            return jsonify({"error": "Invalid MAC address format"}), 400
            
        mac_bytes = bytes.fromhex(mac_clean)
        magic_packet = b'\xff' * 6 + mac_bytes * 16
        
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(magic_packet, ('255.255.255.255', 9))
        
        return jsonify({"message": f"WOL packet sent to {mac}"})
    except Exception as e:
        logger.error(f"Error sending WOL to {ip}: {e}")
        return jsonify({"error": str(e)}), 500

@api_bp.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "timestamp": time.time(), "version": "2.1"})

@api_bp.route('/speedtest', methods=['GET'])
def run_speedtest():
    try:
        # Simple simulated speedtest or basic latency check
        # For a real speedtest, you'd need the 'speedtest-cli' library
        import socket
        start = time.time()
        socket.gethostbyname('google.com')
        latency = round((time.time() - start) * 1000, 2)
        return jsonify({
            "latency": latency,
            "server": "Google DNS",
            "status": "online"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api_bp.route('/lookup/<mac>', methods=['GET'])
def lookup_mac(mac):
    # Public API wrapper for OUI lookup
    try:
        import requests
        res = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        if res.status_code == 200:
            return jsonify({"mac": mac, "vendor": res.text})
        return jsonify({"error": "Not found"}), 404
    except:
        # Fallback to internal
        from scanner.utils import get_vendor
        v = get_vendor(mac)
        return jsonify({"mac": mac, "vendor": v or "Unknown"})
