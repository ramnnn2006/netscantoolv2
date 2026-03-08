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
def scan_network():
    try:
        cidr = request.args.get("cidr")
        deep_scan = request.args.get("deep", "false").lower() == "true"
        limit = int(request.args.get("limit", 254))
        if not cidr:
            subs = scanner.candidate_subnets()
            cidr = subs[0]["cidr"] if subs else "192.168.1.0/24"
        logger.info(f"Scanning {cidr} (deep={deep_scan}, limit={limit})")
        start_time = time.time()
        data = scanner.scan_cidr(cidr, limit_hosts=limit, deep_scan=deep_scan)
        scan_time = time.time() - start_time
        logger.info(f"Scan completed in {scan_time:.2f}s, found {len(data)} devices")
        return jsonify({"cidr": cidr, "count": len(data), "scan_time": round(scan_time, 2), "devices": data})
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
        st, lat = ping_once(ip)
        if st == "down":
            return jsonify({"error": "Device unreachable"}), 404
        host = reverse_dns(ip)
        mac = get_mac_address(ip)
        vendor = get_vendor(mac) if mac else None
        open_ports = scanner.scan_ports(ip)
        status_meta = classify_status(lat)
        device_type = guess_device_type(host, mac, open_ports)
        device = DeviceInfo(
            ip=ip, hostname=host, latency=lat, mac_address=mac, vendor=vendor,
            open_ports=open_ports, status=status_meta["label"],
            statusColor=status_meta["color"], last_seen=time.time(), device_type=device_type
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
    return jsonify({"status": "healthy", "timestamp": time.time(), "version": "2.0"})
