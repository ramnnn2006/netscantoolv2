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

    def scan_ports(self, ip, ports=None, timeout=0.3):
        if ports is None:
            ports = self.config.COMMON_PORTS
        open_ports = []
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                return port if result == 0 else None
            except Exception:
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(check_port, ports)
            open_ports = [p for p in results if p is not None]
        return sorted(open_ports)

    def scan_cidr(self, cidr, limit_hosts=254, max_workers=100, deep_scan=False):
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except Exception as e:
            logger.error(f"Invalid CIDR: {e}")
            return []
        targets = [str(ip) for i, ip in enumerate(net.hosts()) if i < limit_hosts]
        rows = []
        def work(ip):
            st, lat = ping_once(ip)
            if st == "down":
                return None
            host = reverse_dns(ip)
            mac = get_mac_address(ip)
            vendor = get_vendor(mac)
            open_ports = self.scan_ports(ip) if deep_scan else []
            status_meta = classify_status(lat)
            device_type = guess_device_type(host, mac, open_ports)
            return DeviceInfo(
                ip=ip, hostname=host, latency=lat, mac_address=mac, vendor=vendor,
                open_ports=open_ports, status=status_meta["label"],
                statusColor=status_meta["color"], last_seen=time.time(), device_type=device_type
            )
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            for item in ex.map(work, targets):
                if item:
                    rows.append(item.to_dict())
        rows.sort(key=lambda x: ipaddress.ip_address(x['ip']))
        return rows
