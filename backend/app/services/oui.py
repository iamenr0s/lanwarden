"""Offline MAC vendor lookup from the IEEE registries.

IEEE assigns 24-bit blocks (MA-L, `oui.csv`), 28-bit blocks (MA-M, `mam.csv`) and 36-bit blocks (MA-S,
`oui36.csv`); the longest matching prefix wins. The CSVs are read from `LANWARDEN_OUI_DIR`, else `/opt/oui`
(downloaded when the image is built), else `/usr/share/ieee-data` (Debian's `ieee-data`); the arp-scan text
file is the last resort and has 24-bit prefixes only. No network access at runtime. A missing file just
means no vendor.
"""

import csv
import os
from functools import lru_cache

PRIVATE_MAC = "Private MAC"
_DIRS = ("/opt/oui", "/usr/share/ieee-data")
_TXT = "/usr/share/arp-scan/ieee-oui.txt"
_CSVS = ("oui.csv", "mam.csv", "oui36.csv")
_PREFIX_LENGTHS = (9, 7, 6)  # hex digits of an MA-S, MA-M and MA-L assignment


def is_locally_administered(mac: str | None) -> bool:
    """Locally-administered bit set: a phone's per-network "private" address, or a spoofed one."""
    try:
        return bool(mac and int(mac[:2], 16) & 0x02)
    except ValueError:
        return False


def _load_csvs(directory: str) -> dict[str, str]:
    table: dict[str, str] = {}
    for name in _CSVS:
        try:
            with open(os.path.join(directory, name), encoding="utf-8", errors="replace", newline="") as fh:
                for row in csv.reader(fh):
                    # IEEE lists "Private" for organisations that asked not to be named: that is unknown, not a vendor
                    if len(row) >= 3 and row[0].startswith("MA-") and row[2].strip() and row[2].strip() != "Private":
                        table[row[1].strip().upper()] = row[2].strip()
        except OSError:
            continue
    return table


def _load_txt(path: str) -> dict[str, str]:
    table: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                prefix, sep, name = line.partition("\t")
                if sep and len(prefix) == 6 and not line.startswith("#"):
                    table[prefix.upper()] = name.strip()
    except OSError:
        pass
    return table


@lru_cache(maxsize=1)
def _table() -> dict[str, str]:
    for directory in (os.environ.get("LANWARDEN_OUI_DIR"), *_DIRS):
        if directory and (table := _load_csvs(directory)):
            return table
    return _load_txt(_TXT)


def lookup(mac: str | None) -> str | None:
    if not mac:
        return None
    if is_locally_administered(mac):
        return PRIVATE_MAC
    digits = mac.replace(":", "").replace("-", "").upper()
    table = _table()
    for n in _PREFIX_LENGTHS:
        if (vendor := table.get(digits[:n])) is not None:
            return vendor
    return None
