"""Best-effort device type from vendor and hostname. A hint only: hostnames are chosen by the device
itself, so this must never feed a trust decision. Returns None rather than guess weakly."""

import re

# Ordered: first match wins. Hostname rules run before vendor rules.
_HOSTNAME = [
    ("phone", r"iphone|android|galaxy|pixel|oneplus|redmi|xiaomi-?phone"),
    ("tablet", r"ipad|tablet|kindle"),
    ("printer", r"printer|laserjet|officejet|deskjet|epson|brother|canon-?(mf|lbp)|\bmfp\b"),
    ("tv", r"\btv\b|-tv|bravia|roku|chromecast|firetv|appletv|android-?tv|webos"),
    ("nas", r"\bnas\b|synology|diskstation|qnap|readynas"),
    ("iot", r"esp[-_]?\d|esp32|esp8266|shelly|tasmota|sonoff|wled|homeassistant"),
    ("computer", r"desktop|laptop|macbook|imac|thinkpad|\bpc\b|workstation|raspberrypi"),
    ("speaker", r"sonos|echo|homepod|alexa|google-?home|nest-?(mini|audio)"),
    ("camera", r"cam\b|camera|ipcam|reolink|hikvision|dahua"),
]
_VENDOR = [
    ("network", r"ubiquiti|tp-?link|netgear|mikrotik|cisco|aruba|zyxel|d-link|avm|fritz|asus(tek)? ?computer.*router"),
    ("speaker", r"sonos"),
    ("computer", r"raspberry pi|intel corporate|dell|lenovo|hewlett|micro-star"),
    ("iot", r"espressif|tuya|shelly|allterco|sonoff|itead"),
    ("printer", r"canon|epson|brother|xerox|lexmark|kyocera|ricoh"),
    ("tv", r"roku|vizio|tcl|hisense"),
    ("camera", r"hikvision|dahua|reolink|axis comm"),
]
_HOST = [(t, re.compile(p, re.I)) for t, p in _HOSTNAME]
_VEND = [(t, re.compile(p, re.I)) for t, p in _VENDOR]


def guess(vendor: str | None, hostname: str | None, model: str | None = None) -> str | None:
    for text, rules in ((f"{hostname or ''} {model or ''}".strip(), _HOST), (vendor, _VEND)):
        if text:
            for kind, rx in rules:
                if rx.search(text):
                    return kind
    return None
