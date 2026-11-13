import ipaddress
import re
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# Linux IFNAMSIZ-1. Must start alphanumeric so a name can never be parsed as a CLI option.
_IFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$")
MIN_PREFIX_V4 = 16  # refuse to arp-scan more than 65k addresses by mistake


class ScannerSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    interfaces: Annotated[list[str], Field(max_length=16)] = []
    networks: Annotated[list[str], Field(max_length=16)] = []
    scan_interval_seconds: Annotated[int, Field(ge=30, le=86400)] = 300
    offline_threshold_seconds: Annotated[int, Field(ge=60, le=604800)] = 900
    always_connected_offline_threshold_seconds: Annotated[int, Field(ge=60, le=604800)] = 300
    new_device_window_hours: Annotated[int, Field(ge=1, le=720)] = 24
    # raw sightings are for debugging and "source history"; events and sessions are the long-term record
    observation_retention_days: Annotated[int, Field(ge=1, le=365)] = 7
    arp_scan_enabled: bool = True
    neighbor_discovery_enabled: bool = True
    adguard_discovery_enabled: bool = False
    service_discovery_enabled: bool = True  # mDNS + SSDP model names

    @field_validator("interfaces")
    @classmethod
    def _interfaces(cls, v: list[str]) -> list[str]:
        for name in v:
            if not _IFACE_RE.match(name):
                raise ValueError(f"invalid interface name: {name!r}")
        return list(dict.fromkeys(v))

    @field_validator("networks")
    @classmethod
    def _networks(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for raw in v:
            try:
                net = ipaddress.ip_network(raw.strip(), strict=False)
            except ValueError as e:
                raise ValueError(f"invalid CIDR: {raw!r}") from e
            if net.version != 4:
                raise ValueError("only IPv4 networks are supported")
            if net.prefixlen < MIN_PREFIX_V4:
                raise ValueError(f"{net} is too large (minimum prefix /{MIN_PREFIX_V4})")
            out.append(str(net))
        return list(dict.fromkeys(out))

    @model_validator(mode="after")
    def _thresholds(self):
        if self.offline_threshold_seconds < self.scan_interval_seconds:
            raise ValueError("offline_threshold_seconds must be >= scan_interval_seconds")
        return self


class AppSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scanner: ScannerSettings = ScannerSettings()


class DetectedNetworkOut(BaseModel):
    interface: str
    cidr: str


class SettingsOut(BaseModel):
    settings: AppSettings
    detected_networks: list[DetectedNetworkOut]
    # True when more than one candidate exists, so the user must pick explicitly
    detection_ambiguous: bool
