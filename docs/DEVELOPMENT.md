# Development

```bash
# backend (Python 3.14; the image and CI use it)
cd backend && python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
pytest                                                    # tests with a 90% coverage floor
scripts/security-scan.sh                                  # tests, ruff/bandit, semgrep, gitleaks, pip-audit, npm audit, API fuzzing (+ trivy with score, ZAP if present)
scripts/lock-requirements.sh [--upgrade]                  # regenerate the hash-pinned backend/requirements.txt from requirements.in
LANWARDEN_DATA_DIR=../data uvicorn app.main:create_app --factory --port 8080 --reload

# frontend (separate terminal), proxies /api to :8080
cd frontend && npm install && npm run dev                 # http://localhost:5173
```

New migration after changing models (migrations run automatically at startup):

```bash
cd backend && PYTHONPATH=. LANWARDEN_DATABASE_URL=sqlite:///../data/lanwarden.db alembic revision --autogenerate -m "msg"
```

API docs: `http://localhost:8080/api/docs` (login required). Design, schema and API: [DESIGN.md](DESIGN.md).

## Layout

```
backend/app/
  api/           routers (auth, devices, events, scanner, system) + dependencies
  core/          env config, password hashing
  db/            engine/session, UTC datetime type, Alembic migrations
  models/        SQLAlchemy tables
  schemas/       Pydantic request/response models + input validation
  services/      inventory engine, scanner loop, presence/status, settings, network detection
  discovery/     DiscoveryProvider interface, arp_scan, neighbor
  notifications/ NotificationProvider interface, email, webhook
  integrations/  AdGuard Home API client
backend/tests/
frontend/src/    api/ components/ pages/ hooks/ lib/ types/
Dockerfile  docker-compose.yml  scripts/run-container.sh  deploy/  docs/
```

## Publishing the image (maintainers)

`.github/workflows/release.yml` runs the whole CI suite, builds `linux/amd64` + `linux/arm64`, refuses to publish if
the image has fixable HIGH/CRITICAL vulnerabilities, pushes to Docker Hub and Quay, and signs the pushed digest with
keyless cosign (plus a vulnerability attestation). One-time setup in the GitHub repository (Settings → Secrets and
variables → Actions):

| Kind | Name | Value |
|---|---|---|
| secret | `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN` | Docker Hub user and an access token (read/write) |
| secret | `QUAY_USERNAME`, `QUAY_TOKEN` | a Quay **robot account** (`namespace+name`) with write access, and its token |
| variable (optional) | `DOCKERHUB_NAMESPACE`, `QUAY_NAMESPACE` | if different from the GitHub owner (default `iamenr0s`) |

Create the empty `lanwarden` repository on Quay first (public for anonymous pulls). To release:
`git tag v0.1.0 && git push origin v0.1.0`; the image gets tags `0.1.0`, `0.1`, `latest` and the commit hash
(pre-releases such as `v0.2.0-rc1` do not move `latest`). *Run workflow* on the Actions tab does a dry run without
pushing or signing. To publish to only one registry, delete the other login step and image line in the workflow.
