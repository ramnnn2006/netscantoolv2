import ipaddress
import socket
import concurrent.futures
import time
import logging
from config import Config
from .utils import run_command, ping_once, reverse_dns, get_mac_address, get_vendor, classify_status, guess_device_type
from .device import DeviceInfo

logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self):
        self.config = Config()

    def list_local_ipv4s(self):
        import psutil
        rows = []
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                if any(iface.startswith(p) for p in self.config.EXCLUDE_INTERFACES):
                    continue
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address != "127.0.0.1":
                        ip_str = addr.address
                        netmask = addr.netmask
                        if netmask:
                            # Calculate CIDR prefix from netmask
                            cidr = sum(bin(int(x)).count('1') for x in netmask.split('.'))
                        else:
                            cidr = 24
                        rows.append((iface, ip_str, cidr))
        except Exception as e:
            logger.error(f"Failed to list local IPs: {e}")
        return rows

    def candidate_subnets(self):
        subs = []
        seen = set()
        for iface, ip_str, cidr in self.list_local_ipv4s():
            for prefix in [24, cidr]:
                net = ipaddress.ip_network(f"{ip_str}/{prefix}", strict=False)
                key = (str(net.network_address), net.prefixlen)
                if key not in seen:
                    seen.add(key)
                    subs.append({
                        "iface": iface,
                        "cidr": str(net),
                        "gateway_hint": str(net.network_address + 1),
                        "network_size": net.num_addresses - 2
                    })
        return subs

    def scan_ports(self, ip, ports=None, timeout=0.3, grab_banners=False):
        if ports is None:
            ports = self.config.COMMON_PORTS
        open_ports = []
        banners = {}
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                banner = None
                if result == 0 and grab_banners:
                    try:
                        if port == 80: sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()[:100]
                    except: pass
                sock.close()
                return (port, banner) if result == 0 else (None, None)
            except Exception:
                return (None, None)
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            results = list(executor.map(check_port, ports))
            for p, b in results:
                if p is not None:
                    open_ports.append(p)
                    if b: banners[str(p)] = b
        return sorted(open_ports), banners

    def scan_cidr(self, cidr, limit_hosts=254, max_workers=100, deep_scan=False):
        from .utils import guess_os
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except Exception as e:
            logger.error(f"Invalid CIDR: {e}")
            return []
        targets = [str(ip) for i, ip in enumerate(net.hosts()) if i < limit_hosts]
        rows = []
        def work(ip):
            st, lat, ttl = ping_once(ip)
            if st == "down":
                return None
            host = reverse_dns(ip)
            mac = get_mac_address(ip)
            vendor = get_vendor(mac)
            open_ports, banners = self.scan_ports(ip, grab_banners=deep_scan) if deep_scan else ([], {})
            status_meta = classify_status(lat)
            device_type = guess_device_type(host, mac, open_ports, ttl)
            os_guess = guess_os(ttl)
            return DeviceInfo(
                ip=ip, hostname=host, latency=lat, mac_address=mac, vendor=vendor,
                open_ports=open_ports, status=status_meta["label"],
                statusColor=status_meta["color"], last_seen=time.time(), 
                device_type=device_type, banners=banners, os_guess=os_guess
            )
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            for item in ex.map(work, targets):
                if item:
                    rows.append(item.to_dict())
        rows.sort(key=lambda x: ipaddress.ip_address(x['ip']))
        return rows
