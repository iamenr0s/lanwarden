<h1 align="center">LanWarden</h1>

<p align="center">
  <img src="docs/logo-small.png" alt="LanWarden logo" width="180">
</p>

<p align="center"><em>Self-hosted LAN device monitor with AdGuard Home integration.</em></p>

<p align="center">
  <a href="https://github.com/iamenr0s/lanwarden/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/iamenr0s/lanwarden/ci.yml?branch=main&label=CI"></a>
  <a href="https://github.com/iamenr0s/lanwarden/releases"><img alt="Release" src="https://img.shields.io/github/v/release/iamenr0s/lanwarden?include_prereleases"></a>
  <img alt="Last commit" src="https://img.shields.io/github/last-commit/iamenr0s/lanwarden">
  <img alt="Stars" src="https://img.shields.io/github/stars/iamenr0s/lanwarden?style=flat">
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="Status: pre-release" src="https://img.shields.io/badge/status-pre--release-orange">
</p>

<p align="center">
  <a href="docs/SECURITY.md"><img alt="Images signed with cosign" src="https://img.shields.io/badge/images-signed%20with%20cosign-2f80ed?logo=sigstore&logoColor=white"></a>
  <img alt="Trivy" src="https://img.shields.io/badge/scanned%20with-Trivy-1904DA?logo=aquasecurity&logoColor=white">
  <img alt="Semgrep" src="https://img.shields.io/badge/SAST-Semgrep-2DB1A0?logo=semgrep&logoColor=white">
  <a href="https://codecov.io/gh/iamenr0s/lanwarden"><img alt="Coverage" src="https://codecov.io/gh/iamenr0s/lanwarden/graph/badge.svg"></a>
  <img alt="gitleaks" src="https://img.shields.io/badge/secrets-gitleaks-blue">
  <a href="renovate.json"><img alt="Renovate" src="https://img.shields.io/badge/renovate-enabled-brightgreen?logo=renovate"></a>
</p>

<p align="center">
  <img alt="Python 3.14" src="https://img.shields.io/badge/python-3.14-3776AB?logo=python&logoColor=white">
  <img alt="FastAPI" src="https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white">
  <img alt="React" src="https://img.shields.io/badge/React-61DAFB?logo=react&logoColor=black">
  <img alt="TypeScript" src="https://img.shields.io/badge/TypeScript-3178C6?logo=typescript&logoColor=white">
  <img alt="Tailwind CSS" src="https://img.shields.io/badge/Tailwind_CSS-06B6D4?logo=tailwindcss&logoColor=white">
  <img alt="SQLite" src="https://img.shields.io/badge/SQLite-003B57?logo=sqlite&logoColor=white">
  <img alt="Docker" src="https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white">
  <img alt="Podman" src="https://img.shields.io/badge/Podman-892CA0?logo=podman&logoColor=white">
  <img alt="AdGuard Home" src="https://img.shields.io/badge/AdGuard_Home-integrated-68BC71?logo=adguard&logoColor=white">
</p>

LanWarden discovers the devices on your LAN or Wi-Fi, keeps a persistent inventory, tracks when each one is online,
and alerts you to unknown devices. It can also use **AdGuard Home** as an extra source of device names and DNS
activity. Inspired by the concepts of [Pi.Alert](https://github.com/pucherot/Pi.Alert) and written from scratch.

## Features

* Device discovery with arp-scan and the kernel neighbour table, merged into one inventory per MAC
* Presence timelines, IP and hostname history, and events for every change
* Vendor lookup (offline IEEE registry), automatic device type, and model names from mDNS and SSDP
* Email and webhook notifications, with spoofing and conflict detection
* AdGuard Home integration: DHCP leases, clients and query log
* Dashboard with charts; single admin with optional two-step verification, optional HTTPS and database encryption

Details: [docs/FEATURES.md](docs/FEATURES.md).

## Quick start

Needs Docker or Podman on the machine that sits on the LAN you want to watch.

```bash
git clone https://github.com/iamenr0s/lanwarden && cd lanwarden
scripts/run-container.sh        # builds and starts; also: logs, status, down
```

Or run the published image (amd64 and arm64):

```bash
LANWARDEN_IMAGE=quay.io/iamenr0s/lanwarden:latest scripts/run-container.sh     # or docker.io/iamenr0s/lanwarden:latest
```

Open `http://<host>:8080` and create the administrator account. Until you do, anyone who can reach the port can
claim it.

LanWarden uses host networking, so the port is set with `LANWARDEN_PORT`. Rootless Podman cannot run arp-scan; it
falls back to the neighbour table.

## Documentation

| | |
|---|---|
| [Install and configure](docs/INSTALL.md) | Compose, Podman service, HTTPS and reverse proxy, native install, environment variables |
| [Features](docs/FEATURES.md) | Scanning, dashboard, presence, notifications, AdGuard Home |
| [Secrets and recovery](docs/SECRETS.md) | Key handling, rotation, database encryption, two-step verification, lockout recovery |
| [Security](docs/SECURITY.md) | Threat model, controls, residual risks, verifying signed images |
| [Design](docs/DESIGN.md) | Architecture, schema, API |
| [Development](docs/DEVELOPMENT.md) | Running from source, tests, layout, publishing |

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the
local pipeline commands and pull request checklist. This project follows the
[Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).

## Security

See [docs/SECURITY.md](docs/SECURITY.md) — GitHub private vulnerability reporting, no
public issues for security bugs.

## License

This project is licensed under the [MIT License](LICENSE).

## Author Information

Author: iamenr0s
