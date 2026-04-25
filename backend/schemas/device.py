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
    project: Optional[str] = None
    console: Optional[str] = None
    power: Optional[str] = None


class DeviceEdit(BaseModel):
    availability: str
    reporting_manager: str
    team: str
    ip_address: str
    location: str
    project: Optional[str] = None
    console: Optional[str] = None
    power: Optional[str] = None
