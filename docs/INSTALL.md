# Install and configure

Open `http://<host>:8080` after starting and create the administrator account on first visit.

## Docker or Podman

One script picks Docker or Podman and uses plain `build` + `run` with the hardening flags:

```bash
scripts/run-container.sh build      # image only (lanwarden:latest)
scripts/run-container.sh            # build + start; also: logs, status, down
CONTAINER_ENGINE=podman scripts/run-container.sh   # force an engine
```

Published image (amd64 and arm64, built on every `v*.*.*` tag):

```bash
LANWARDEN_IMAGE=quay.io/iamenr0s/lanwarden:latest scripts/run-container.sh     # or docker.io/iamenr0s/lanwarden:latest
```

Released images are signed; see [SECURITY.md](SECURITY.md) to verify one.

Compose is optional (the script never uses it unless you set `USE_COMPOSE=1`):

```bash
docker compose up -d        # or: podman compose up -d / podman-compose up -d
```

Podman as a systemd service (survives reboots; rootful so arp-scan works), see
[deploy/lanwarden.container](../deploy/lanwarden.container):

```bash
sudo podman build --format docker -t lanwarden:latest .
sudo cp deploy/lanwarden.container /etc/containers/systemd/
sudo systemctl daemon-reload && sudo systemctl start lanwarden
```

### Container notes

* **Host networking** is required (arp-scan must share the host's LAN namespace); `ports:` is ignored.
  Change the port with `LANWARDEN_PORT`.
* **Rootless Podman cannot run arp-scan** (raw sockets on the host network need real root). LanWarden still
  discovers devices through the kernel neighbour table and the dashboard shows the arp-scan error. Run the script
  with `sudo`, or use the Quadlet unit, for full discovery.
* **Permissions:** `cap_drop: ALL` + `cap_add: NET_RAW`; `/usr/sbin/arp-scan` carries `cap_net_raw` as a file
  capability so the app runs unprivileged (uid 10001). The root filesystem is read-only; only the `lanwarden-data`
  volume is writable.
* Data lives in the named volume `lanwarden-data`. Back up: `podman|docker volume export lanwarden-data -o backup.tar`.

### Upgrading from GuardAlert

`GUARDALERT_*` variables are still honoured (`LANWARDEN_*` wins), an existing `guardalert.db` is kept, and
`scripts/run-container.sh` reuses a `guardalert-data` volume. Compose and the Quadlet unit now name the volume
`lanwarden-data`: copy your data over (`podman|docker volume export guardalert-data | ... volume import`) or edit the
volume name back. Webhook receivers must check the `X-LanWarden-Signature` header and `"source": "lanwarden"`.

## HTTPS and reverse proxy

LanWarden serves plain HTTP by default, which is reasonable on a trusted home LAN. Otherwise use built-in HTTPS:

```bash
LANWARDEN_TLS_MODE=selfsigned                 # generate a self-signed certificate in the data volume
LANWARDEN_TLS_NAMES=guard.home.lan,10.0.0.5   # extra names/IPs it should cover (the host's own addresses are added)
# or bring your own:
LANWARDEN_TLS_CERT=/path/cert.pem  LANWARDEN_TLS_KEY=/path/key.pem
```

With TLS on, the session cookie is `Secure` and HSTS is sent. A self-signed certificate gives encryption but not
identity: your browser warns until you trust it.

Or put it behind an HTTPS reverse proxy and tell LanWarden:

```bash
LANWARDEN_SECURE_COOKIES=true      # Secure cookie + HSTS
FORWARDED_ALLOW_IPS=<proxy ip>     # trust X-Forwarded-For from the proxy only (real client IPs for login throttling)
LANWARDEN_PORT=8080                # bind the proxy to this; firewall the port from everything else
```

Caddy: `lanwarden.example.lan { reverse_proxy 127.0.0.1:8080 }`

nginx:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

**First-run setup:** until the first admin exists, anyone who can reach the port can claim the account. Finish setup
right away, or set `LANWARDEN_SETUP_TOKEN=<long random string>` (the setup form then asks for it).

## Native install (Debian / Ubuntu / Raspberry Pi OS)

Mirrors what the Docker image does.

```bash
sudo apt install -y python3-venv arp-scan iproute2 libcap2-bin nodejs npm
sudo useradd --system --home /opt/lanwarden --shell /usr/sbin/nologin lanwarden
sudo mkdir -p /opt/lanwarden /var/lib/lanwarden && sudo chown lanwarden /var/lib/lanwarden
sudo cp -r backend/app backend/requirements.txt /opt/lanwarden/
(cd frontend && npm ci && npm run build) && sudo cp -r frontend/dist /opt/lanwarden/frontend_dist
sudo python3 -m venv /opt/lanwarden/venv
sudo /opt/lanwarden/venv/bin/pip install --require-hashes -r /opt/lanwarden/requirements.txt  # locked for Python 3.14 on Linux
sudo setcap cap_net_raw+ep "$(readlink -f /usr/sbin/arp-scan)"
```

`/etc/systemd/system/lanwarden.service`:

```ini
[Service]
User=lanwarden
WorkingDirectory=/opt/lanwarden
Environment=LANWARDEN_DATA_DIR=/var/lib/lanwarden LANWARDEN_FRONTEND_DIR=/opt/lanwarden/frontend_dist
UMask=0077
Environment=LANWARDEN_HOST=0.0.0.0 LANWARDEN_PORT=8080
ExecStart=/opt/lanwarden/venv/bin/python -m app
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=false
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## Configuration (environment)

| Variable | Default | Meaning |
|---|---|---|
| `LANWARDEN_DATA_DIR` | `data` (`/data` in Docker) | SQLite DB + generated secret key |
| `LANWARDEN_DATABASE_URL` | SQLite in data dir | any SQLAlchemy URL |
| `LANWARDEN_SECRET_KEY` | generated, stored 0600 | master key: encrypts stored secrets, signs sessions; min 16 characters |
| `LANWARDEN_SECRET_KEY_FILE` | unset | file holding the secret key (instead of the generated one in the data dir) |
| `LANWARDEN_DB_ENCRYPTION` | `off` | `sqlcipher` = encrypt the database file (needs the key from env or file) |
| `LANWARDEN_SECURE_COOKIES` | `false` | mark session cookie `Secure` |
| `LANWARDEN_SESSION_HOURS` | `168` | session lifetime |
| `LANWARDEN_HOST` / `LANWARDEN_PORT` | `127.0.0.1` / `8080` (the image sets `0.0.0.0`) | bind address and port for `python -m app` |
| `LANWARDEN_SETUP_TOKEN` | unset | required on the first-run setup form when set |
| `LANWARDEN_REQUIRE_MFA` | `false` | every account must enrol two-step verification |
| `LANWARDEN_TLS_MODE` | `off` | `selfsigned` = built-in HTTPS with a generated certificate |
| `LANWARDEN_TLS_CERT` / `LANWARDEN_TLS_KEY` | unset | your own certificate and key (built-in HTTPS) |
| `LANWARDEN_TLS_NAMES` | unset | extra DNS names/IPs for the self-signed certificate |
| `LANWARDEN_OUI_DIR` | `/opt/oui`, then `/usr/share/ieee-data` | directory with IEEE `oui.csv`, `mam.csv`, `oui36.csv` |
| `FORWARDED_ALLOW_IPS` | `127.0.0.1` | proxy addresses trusted for `X-Forwarded-For`/`-Proto` |

Scanner settings (networks, interfaces, thresholds) are edited in the UI (Settings) and stored in the database.
