from dataclasses import dataclass, asdict
from typing import Optional, List

@dataclass
class DeviceInfo:
    ip: str
    hostname: Optional[str]
    latency: Optional[float]
    mac_address: Optional[str]
    vendor: Optional[str]
    open_ports: List[int]
    status: str
    statusColor: str
    last_seen: float
    device_type: Optional[str] = None
    banners: Optional[dict] = None
    os_guess: Optional[str] = None

    def to_dict(self):
        d = asdict(self)
        d['latency'] = round(d['latency'], 1) if d['latency'] else None
        return d
