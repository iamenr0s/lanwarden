# LanWarden — Design

Status: Phase 1 implemented. Later phases are specified here so the schema and
API do not need reshaping when they land.

## 1. What we take from Pi.Alert (ideas only — no code is copied; Pi.Alert is GPL-3)

| Pi.Alert concept | LanWarden equivalent |
|---|---|
| Multiple scan methods merged into one inventory | `DiscoveryProvider` interface, observations merged by the inventory engine |
| Device inventory with user-editable name/type/group/owner | `devices` with user-owned columns the scanner never writes |
| Sessions (connection/disconnection pairs) | `device_sessions` |
| Events (new device, connect, disconnect, IP change, down alert) | `events` with typed `event_type`, old/new value, source |
| "Always connected" devices + down alert | `always_connected` flag + configurable threshold, down/recovered events |
| New-device highlighting, "known" workflow | `is_known`, status `NEW`, Mark-as-known flow |
| Presence / concurrent-device charts | timeline built from sessions, devices-over-time from observations |
| E-mail reports | `NotificationProvider` abstraction (email, webhook first) |
| arp-scan as the primary method | `ArpScanProvider`, plus kernel neighbour table |

## 2. What we deliberately do NOT copy

* Pi-hole scan method (reads `pihole-FTL.db`) → replaced by the AdGuard Home API provider.
* dnsmasq lease-file parsing → AdGuard DHCP leases via API (`/dhcp/status`).
* PHP/lighttpd/AdminLTE front-end, one-file Python scanner, shell installer piping curl to bash.
* Internet-IP-change tracking (out of scope; can be a later provider).
* Settings in a Python config file edited by hand → settings in DB, edited in UI.
* Passwordless web UI → authenticated from the first run.

## 3. AdGuard Home API → LanWarden mapping

Source of truth: `openapi/openapi.yaml` in AdguardTeam/AdGuardHome (base path
`/control`, security scheme **HTTP Basic**). Only documented endpoints are used.

| Endpoint | Used for | Phase |
|---|---|---|
| `GET /status` | health card, version, DNS addresses, protection state, Test Connection | 3 |
| `GET /dhcp/status` | `leases[] {mac, ip, hostname, expires}` → observations with MAC (strong identity); `static_leases` → hostname hints | 3 |
| `GET /clients` | `clients[] {name, ids[]}` (ids are IP/CIDR/MAC/ClientID) → "AdGuard recognises this client"; `auto_clients[] {ip, name, source}` → runtime hostnames | 3 |
| `POST /clients/search` | exact lookup of one device by IP/MAC for the device AdGuard tab | 3 |
| `GET /querylog?limit&search&older_than` | `data[] {client, client_info.name, question.name, reason, time}` → recent domains, last DNS activity, IP-only observations | 3 |
| `GET /stats` | `num_dns_queries`, `num_blocked_filtering`, `top_clients` → per-client counts where present | 3 |

Not used: `/version.json` (triggers an update check against the internet; the
version comes from `/status`), anything that mutates AdGuard state.

Identity rules for AdGuard-sourced data:

* DHCP leases carry a MAC → can create/merge devices.
* Query-log / `auto_clients` entries carry only an IP → they may only *enrich or
  confirm presence of* a device already bound to that IP; they never create a
  device with a MAC and never merge two MAC-identified devices.
* AdGuard unavailable → the provider returns an error result, the scan run
  records it, other providers continue.

## 4. Architecture

```
React SPA ──HTTP/JSON──▶ FastAPI ──▶ services ──▶ SQLAlchemy ──▶ SQLite (PostgreSQL-ready)
                           │             ▲
                           │      Inventory engine (merge, presence, events, sessions)
                           │             ▲ DeviceObservation[]
                           │   ┌─────────┴──────────────────────────────┐
                           │   ArpScanProvider  NeighborProvider  AdGuardProvider
                           ▼
                   Scanner (background loop) ─▶ NotificationProvider (email, webhook)
```

Key rules:

* **Provider contract**: `async scan(ctx) -> ProviderResult(observations, error)`.
  A provider never touches the DB.
* **Merge rule**: identity = MAC when present, else IP-only match against a
  device *without* a MAC. An IP seen with a different MAC does not move the old
  device; the old device simply stops being seen at that IP
  (`device_addresses.last_seen` tracks this).
* **User-owned vs scanner-owned columns**: scanner writes `hostname`, `vendor`,
  `current_ip`, presence fields. User writes `friendly_name`, `vendor_override`,
  `device_type`, `device_group`, flags, notes. Scanner code has no code path that
  writes user columns, so manual values cannot be overwritten.
* **Status**: `is_online` = seen within `offline_threshold`. `status` =
  `UNKNOWN` (never seen), `NEW` (not known and within `new_device_window`),
  else `ONLINE`/`OFFLINE`. Pure function `services/presence.compute_status`.
* **Secrets**: AdGuard password is the only recoverable secret. It is encrypted
  at rest (Fernet, key derived from the instance secret key), never returned by
  any API (responses carry `password_set: bool`).
* **Auth**: single-admin, first-run setup, scrypt password hash, signed
  session cookie (`HttpOnly`, `SameSite=Strict`, `Secure` when
  `LANWARDEN_SECURE_COOKIES=true`), login throttling. No CORS; mutating
  endpoints take JSON only.
* **Subprocess**: `arp-scan` is invoked with an argument list (no shell); the
  interface and CIDR are validated first.

## 5. Database schema

All timestamps are UTC (`UTCDateTime` type: stored naive-UTC, returned aware).

```
users(id PK, username UNIQUE, password_hash, created_at)

devices(id PK, mac_address UNIQUE NULL IDX, current_ip IDX, hostname IDX,
        friendly_name, vendor, vendor_override, device_type, device_group IDX,
        status IDX, is_online, first_seen, last_seen IDX, last_connection,
        last_disconnection, is_known, is_favorite, always_connected,
        alert_enabled, is_ignored, is_trusted, notes, created_at, updated_at)

device_addresses(id PK, device_id FK, ip, first_seen, last_seen, source,
                 UNIQUE(device_id, ip), IDX(ip))
device_names(id PK, device_id FK, name, source, first_seen, last_seen,
             UNIQUE(device_id, name, source), IDX(name))
device_sessions(id PK, device_id FK, connected_at IDX, disconnected_at NULL,
                last_seen, source, IDX(device_id, connected_at))

events(id PK, device_id FK NULL, timestamp IDX, event_type IDX, old_value,
       new_value, source, metadata JSON, IDX(device_id, timestamp))
discovery_observations(id PK, observed_at IDX, source, mac IDX, ip IDX,
                       hostname, vendor, device_id FK NULL, metadata JSON)

settings(key PK, value JSON, updated_at)
notification_rules(id PK, name, provider, event_types JSON, config JSON,
                   enabled, created_at)
```

`discovery_observations` is pruned by a retention job (Phase 4) — it feeds
"devices over time" and provider debugging, not long-term history (events and
sessions are the long-term record).

## 6. REST API

All under `/api`, JSON, session-cookie auth unless noted. OpenAPI at
`/api/docs`, `/api/openapi.json`.

| Method | Path | Phase |
|---|---|---|
| GET | `/health` (unauthenticated) | 1 |
| GET | `/auth/state`, POST `/auth/setup`, `/auth/login`, `/auth/logout` | 1 |
| GET | `/status` — device counters | 1 (+adguard health in 3) |
| GET | `/devices` — `q,status,known,favorite,always_connected,group,type,sort,order,limit,offset` | 1 |
| GET/PATCH | `/devices/{id}` | 1 |
| GET | `/devices/{id}/events`, `/devices/{id}/sessions` | 1 (data from 4) |
| GET | `/devices/{id}/presence?range=24h|7d|30d|today` | 4 |
| GET | `/devices/{id}/network`, `/devices/{id}/adguard` | 3/4 |
| GET | `/events` — `device_id,event_type,since,until,q` | 1 |
| GET/PUT | `/settings` (+ detected network suggestions) | 1 |
| POST | `/scanner/run`, GET `/scanner/runs` | 2 |
| GET | `/integrations/adguard/status` | 3 |
| POST | `/integrations/adguard/test` | 3 |
| GET/PUT | `/integrations/adguard` (password write-only) | 3 |
| GET/POST/PATCH/DELETE | `/notifications/rules`, POST `/notifications/test` | 5 |
| GET | `/dashboard/*` analytics series | 6 |

## 7. Repository layout

See the tree in [DEVELOPMENT.md](DEVELOPMENT.md). Backend: `app/{api,core,db,models,schemas,services,
discovery,notifications,integrations}`; frontend: `src/{api,components,pages,
hooks,types}`.

## 8. Implementation plan

1. **Phase 1 (done)** skeleton, DB + migration, auth, devices/events/settings
   read/patch APIs, SPA (dashboard, devices, device detail, events, settings),
   Docker Compose.
2. **Phase 2 (done)** `DiscoveryProvider`, ArpScan + Neighbor providers, inventory
   engine (merge, status, events, sessions), background scan loop (a plain thread with
   reschedule-on-settings-change instead of APScheduler: one interval job needs no
   dependency), `POST /scanner/run`, `GET /scanner/runs` (last 20 runs, in memory).
   Podman support: compose file, `scripts/run-container.sh`, Quadlet unit.
3. **Phase 3 (done)** AdGuard client + provider, AdGuard settings/test/health API and page,
   device AdGuard tab. Refinement of §3: observations carry `presence`; DHCP leases and client
   names are identity-only (a lease outlives the device), the query log is presence evidence;
   IP-only evidence never creates devices. Event/session `source` columns widened to 128
   (migration 0002) because one event can name several providers.
4. **Phase 4 (done)** sessions and the full event set landed in Phase 2; here: `GET
   /devices/{id}/presence` (online intervals clipped from sessions; open sessions of online devices
   run to now) and `/devices/{id}/network` (address/hostname/source history), Presence and Network
   tabs, configurable observation retention (pruned on every scan).
5. **Phase 5 (done)** `NotificationProvider` (email, webhook), rules CRUD with encrypted
   secrets, post-scan dispatch of that scan's new events (one digest per rule), per-device alert
   switch, test endpoint, in-memory delivery log. Deliberately not done: retries/queueing
   (a failed send is logged and shown, not retried), per-rule device filters.
6. **Phase 6 (done)** `GET /api/dashboard?range=24h|7d|30d` (online/known series sampled from
   sessions, device-type distribution, recently disconnected), SVG charts, 30 s auto-refresh,
   theme switcher in the sidebar, empty states. Deliberately not done: a global "Network" page
   (per-device network history lives on the device page) and DNS statistics (the dashboard is
   about devices, not a DNS clone).
7. **Phase 7 (done)** security review ([SECURITY.md](SECURITY.md)): setup token, password change +
   session invalidation, docs behind login, security headers, enforced `umask 077`, react-router 7;
   route-coverage test (every API route must 401 without a session); coverage gaps closed
   (scheduler loop, migration downgrade, endpoints' filters); install docs for HTTPS proxying.
8. **Phase 8 (done)** closing the risks Phase 7 documented ([SECURITY.md](SECURITY.md)): login throttling
   moved to the database (`login_attempts`, migration 0003) with per-address and per-username limits;
   built-in optional TLS (`core/tls.py`, `python -m app`); optional TOTP MFA + recovery codes
   (`core/totp.py`, migration 0004, two-step `/auth/login` + `/auth/login/mfa`, `LANWARDEN_REQUIRE_MFA`,
   `reset-mfa`/`reset-password` CLI); `DEVICE_ANOMALY` detection in the inventory engine; bounded integer
   parameters (found by API fuzzing); `scripts/security-scan.sh` and CI. What cannot be fixed in software
   (ARP is unauthenticated; independent assurance needs someone else) is stated in SECURITY.md.
9. **Phase 9 (done)** hardware identification: offline OUI vendor lookup for every MAC (`services/oui.py`; provider
   vendor wins; locally-administered MACs labelled "Private MAC"), scanner-owned `devices.type_guess` (migration 0005,
   `services/devicetype.py`, hostname rules before vendor rules, None when evidence is weak), `effective_type =
   device_type or type_guess` used by the API, filter, sort and dashboard. `device_type` stays user-owned and is never
   written by a scan. Not done: model/OS/port detection (mDNS, SSDP, NetBIOS, nmap).
10. **Phase 10 (done)** model names: `MdnsProvider` and `SsdpProvider` (`discovery/services.py`, stdlib sockets + httpx,
    no new dependency), scanner-owned `devices.model` (migration 0006), model feeds `devicetype.guess`. Observations are
    IP-only and `presence=False`, so they can only enrich a device already known at that address. Providers declare
    `gives_evidence = False`, so a successful mDNS/SSDP answer never makes the scanner believe absences are proven.
    Replies are identified by UDP source address; the UPnP description is fetched only from the answering host (http,
    short timeout, no redirects, 64 KB cap) and read with regexes, not an XML parser. Queries originate from ports 5353
    and 1900 because a host firewall dropped unicast replies to random ports on the development machine.
11. **Phase 11 (done)** vendor data: `services/oui.py` reads IEEE's 24/28/36-bit registries (longest prefix wins; "Private"
    registrations are unknown); the image downloads them at build time (`scripts/fetch_oui.py`, non-fatal) into `/opt/oui`,
    with `/usr/share/ieee-data` and arp-scan's old text file as fallbacks. A router the 2024 arp-scan file did not know
    (Sagemcom) is identified from the current registry. `LANWARDEN_OUI_FILE` was replaced by `LANWARDEN_OUI_DIR`.
12. **Phase 12 (done)** secrets at rest: webhook URLs are encrypted and write-only (`WebhookProvider.secrets`, masked
    `url_hint`, legacy plaintext rows encrypted at startup); `SecretBox` v2 (HKDF-SHA256 per-purpose keys, `v2:`-prefixed tokens,
    legacy tokens still decrypt); key from env, `LANWARDEN_SECRET_KEY_FILE` or the data dir (min 16 characters);
    `python -m app rotate-key [--dry-run]`; optional whole-database encryption with SQLCipher (`sqlcipher3`, key derived from the
    master key, refuses to start with the key in the data dir) and `encrypt-db` / `decrypt-db`. MFA recovery codes cannot survive a
    rotation (one-way HMAC keyed by the secret key) and are cleared.
