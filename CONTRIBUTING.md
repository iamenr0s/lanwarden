# Contributing

Thanks for taking the time to contribute to LanWarden!

## Getting started

1. Fork the repository and create your branch from `main`.
2. Set up the backend and frontend as described in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) (Python 3.14, Node 26, Docker or Podman).

## Making changes

- Keep changes small and focused: one topic per pull request.
- Backend code lives in `backend/app`, the UI in `frontend/src`; the layout is in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) and the design in [docs/DESIGN.md](docs/DESIGN.md).
- Add or update tests with your change. The backend has a 90% coverage floor.
- After changing database models, add an Alembic migration (see [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)).
- Changing Python dependencies: edit `backend/requirements.in` and run `scripts/lock-requirements.sh` so the hash-pinned `requirements.txt` stays in sync.
- GitHub Actions are pinned to commit hashes (version in a comment); keep that when adding or updating one.

## Testing

Before opening a pull request, run the same checks CI runs:

```bash
cd backend && pytest                 # tests with the coverage floor
scripts/security-scan.sh             # ruff, bandit, semgrep, gitleaks, pip-audit, npm audit, API fuzzing (+ trivy)
cd frontend && npm run build         # type-checks and bundles
```

If you touch the image or the container script, also check that it builds and starts:

```bash
scripts/run-container.sh build && scripts/run-container.sh
```

## Submitting a pull request

1. Make sure the checks above pass locally.
2. Describe what changed and why, and how you tested it.
3. A maintainer will review your PR; CI must be green before merge.

## Reporting bugs and requesting features

Open an issue with the steps to reproduce, what you expected, and what happened (version or image tag, how you run it, Docker or Podman, and host OS).

For security problems, do not open a public issue; see [docs/SECURITY.md](docs/SECURITY.md#reporting-a-vulnerability).

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating you agree to abide by it.
