import subprocess
import re
import socket
from functools import lru_cache
import logging
import platform
logger = logging.getLogger(__name__)
LATENCY_RE = re.compile(r"time[=<]([0-9.]+)\s*ms", re.I)
TTL_RE = re.compile(r"TTL=([0-9]+)", re.I)

def run_command(cmd, timeout=2):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 1, "", "timeout")

def ping_once(ip):
    try:
        is_win = platform.system().lower() == "windows"
        cmd = ["ping", "-n", "1", "-w", "1000", ip] if is_win else ["ping", "-c", "1", "-W", "1", ip]
        proc = run_command(cmd)
        if proc.returncode == 0:
            out = proc.stdout + proc.stderr
            m_lat = LATENCY_RE.search(out)
            m_ttl = TTL_RE.search(out)
            latency = float(m_lat.group(1)) if m_lat else None
            ttl = int(m_ttl.group(1)) if m_ttl else None
            return "up", latency, ttl
        return "down", None, None
    except Exception as e:
        logger.debug(f"Ping failed for {ip}: {e}")
        return "down", None, None

def get_banner(ip, port, timeout=1.0):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        if port == 80:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner[:100] if banner else None
    except Exception:
        return None

@lru_cache(maxsize=256)
def reverse_dns(ip, timeout=0.5):
    sock_to = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(sock_to)

def get_mac_address(ip):
    is_win = platform.system().lower() == "windows"
    try:
        if is_win:
            result = run_command(["arp", "-a", ip], timeout=1)
            if result.returncode == 0:
                match = re.search(r"([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})", result.stdout)
                if match:
                    return match.group(1).replace("-", ":").upper()
        else:
            result = run_command(["ip", "neigh", "show", ip], timeout=1)
            if result.returncode == 0:
                match = re.search(r"([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})", result.stdout)
                if match:
                    return match.group(1).upper()
            result = run_command(["arp", "-n", ip], timeout=1)
            if result.returncode == 0:
                match = re.search(r"([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})", result.stdout)
                if match:
                    return match.group(1).upper()
    except Exception as e:
        logger.debug(f"Failed to get MAC for {ip}: {e}")
    return None

VENDOR_DATABASE = {
    '00:50:56': 'VMware', '00:0C:29': 'VMware', '08:00:27': 'VirtualBox', '52:54:00': 'QEMU/KVM',
    'DC:A6:32': 'Raspberry Pi', 'B8:27:EB': 'Raspberry Pi', 'E4:5F:01': 'Raspberry Pi',
    '00:1B:44': 'Apple', '28:CF:E9': 'Apple', '3C:07:54': 'Apple', '88:66:5A': 'Apple',
    '00:50:F2': 'Microsoft', '00:15:5D': 'Microsoft', '28:18:78': 'Google', 'F4:F5:D8': 'Google',
}

def get_vendor(mac):
    if not mac:
        return None
    return VENDOR_DATABASE.get(mac[:8].upper())

def classify_status(lat_ms):
    if lat_ms is None:
        return {"label": "Unreachable", "color": "red"}
    if lat_ms < 30:
        return {"label": "Excellent", "color": "green"}
    if lat_ms < 80:
        return {"label": "Good", "color": "lightgreen"}
    if lat_ms < 150:
        return {"label": "Fair", "color": "yellow"}
    if lat_ms < 300:
        return {"label": "Poor", "color": "orange"}
    return {"label": "Critical", "color": "red"}

def guess_os(ttl):
    if not ttl: return "Unknown"
    if ttl <= 64: return "Linux/Unix"
    if ttl <= 128: return "Windows"
    if ttl <= 255: return "Cisco/Network Device"
    return "Unknown"

def guess_device_type(hostname, mac, open_ports, ttl):
    hostname_lower = (hostname or '').lower()
    if any(x in hostname_lower for x in ['router', 'gateway']) or ttl == 255:
        return 'Router'
    if any(x in hostname_lower for x in ['printer', 'print']) or 9100 in open_ports:
        return 'Printer'
    if any(x in hostname_lower for x in ['camera', 'cam']) or 554 in open_ports:
        return 'Camera'
    if 80 in open_ports or 443 in open_ports:
        if 'linux' in hostname_lower: return 'Linux Server'
        return 'Web Server'
    if 445 in open_ports or 3389 in open_ports: return 'Windows Station'
    if 22 in open_ports: return 'Linux/SSH Device'
    return 'Generic Device'
