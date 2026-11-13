"""Download the IEEE registries (24/28/36-bit blocks) into a directory, at image build time.

    python fetch_oui.py /opt/oui

Never fails the build: a file that cannot be fetched or does not look like the registry is skipped, and
the app falls back to older data (see backend/app/services/oui.py).
"""
import os
import sys
import urllib.request

BASE = "https://standards-oui.ieee.org"
FILES = {"oui.csv": "oui/oui.csv", "mam.csv": "oui28/mam.csv", "oui36.csv": "oui36/oui36.csv"}
HEADER = b"Registry,Assignment,Organization Name"


def main(dest: str) -> None:
    os.makedirs(dest, exist_ok=True)
    for name, path in FILES.items():
        try:
            req = urllib.request.Request(f"{BASE}/{path}", headers={"User-Agent": "lanwarden-build"})  # noqa: S310  (fixed https URL)
            with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310  (fixed https URL)
                data = r.read(32 * 1024 * 1024)
            if not data.lstrip(b"\xef\xbb\xbf").startswith(HEADER) or len(data) < 100_000:
                raise ValueError("unexpected content")
            with open(os.path.join(dest, name), "wb") as fh:
                fh.write(data)
            print(f"fetched {name}: {len(data)} bytes")
        except Exception as e:  # noqa: BLE001
            print(f"warning: could not fetch {name} ({e}); using older bundled data", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1])
