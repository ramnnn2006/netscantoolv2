import subprocess
import re
import socket
from functools import lru_cache
import logging
import platform
logger = logging.getLogger(__name__)
LATENCY_RE = re.compile(r"time[=<]([0-9.]+)\s*ms", re.I)

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
            m = LATENCY_RE.search(proc.stdout) or LATENCY_RE.search(proc.stderr)
            latency = float(m.group(1)) if m else None
            return "up", latency
        return "down", None
    except Exception as e:
        logger.debug(f"Ping failed for {ip}: {e}")
        return "down", None

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

def guess_device_type(hostname, mac, open_ports):
    if not hostname and not mac and not open_ports:
        return None
    hostname_lower = (hostname or '').lower()
    if any(x in hostname_lower for x in ['router', 'gateway']):
        return 'Router'
    if any(x in hostname_lower for x in ['printer', 'print']):
        return 'Printer'
    if any(x in hostname_lower for x in ['camera', 'cam']):
        return 'Camera'
    if 3389 in open_ports:
        return 'Windows'
    if 22 in open_ports and 80 not in open_ports:
        return 'Linux/Unix'
    if set([80, 443]).issubset(open_ports):
        return 'Web Server'
    return 'Unknown'
