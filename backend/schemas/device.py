from typing import Optional
from pydantic import BaseModel


class DeviceCreate(BaseModel):
    mac_address: str
    device_model: str
    owner: Optional[str] = None
    availability: str
    reporting_manager: str
    team: str
    ip_address: str
    location: str
    lease: str


class DeviceEdit(BaseModel):
    availability: str
    reporting_manager: str
    team: str
    ip_address: str
    location: str
