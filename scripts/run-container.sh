#!/usr/bin/env bash
# Build and run LanWarden with Docker or Podman, with or without a compose provider.
#
#   scripts/run-container.sh [build|up|down|logs|status]      (default: up)
#
# Engine:  docker if present, else podman. Force one with CONTAINER_ENGINE=podman.
# Compose: NOT used by default (plain `build` + `run` with the hardening flags).
#          Opt in with USE_COMPOSE=1 (docker compose / podman compose / podman-compose).
# Port:    LANWARDEN_PORT (default 8080).
# Passed through when set in your shell: LANWARDEN_SETUP_TOKEN (protects first-run setup),
#          LANWARDEN_SECURE_COOKIES=true (behind HTTPS), FORWARDED_ALLOW_IPS=<proxy ip> (behind a proxy),
#          LANWARDEN_REQUIRE_MFA=true (every account must enrol two-step verification),
#          LANWARDEN_TLS_MODE=selfsigned [LANWARDEN_TLS_NAMES=host.lan,10.0.0.5] (built-in HTTPS),
#          LANWARDEN_SECRET_KEY (or LANWARDEN_SECRET_KEY_FILE=/host/path, mounted read-only and readable by uid 10001)
#          keeps the encryption key out of the data volume; LANWARDEN_DB_ENCRYPTION=sqlcipher encrypts the database.
# Needs bash (arrays); re-run under it when started as `sh scripts/run-container.sh`.
[ -n "${BASH_VERSION:-}" ] || exec bash "$0" "$@"
set -euo pipefail
cd "$(dirname "$0")/.."

NAME=lanwarden
# LANWARDEN_IMAGE=quay.io/iamenr0s/lanwarden:latest uses a published image instead of building one.
IMAGE=${LANWARDEN_IMAGE:-lanwarden:latest}
VOLUME=lanwarden-data
LEGACY_NAME=guardalert  # the project's former name
PORT=${LANWARDEN_PORT:-8080}

if [ -n "${CONTAINER_ENGINE:-}" ]; then
  ENGINE=$CONTAINER_ENGINE
elif command -v docker >/dev/null 2>&1; then
  ENGINE=docker
elif command -v podman >/dev/null 2>&1; then
  ENGINE=podman
else
  echo "error: neither docker nor podman found in PATH" >&2
  exit 1
fi
command -v "$ENGINE" >/dev/null 2>&1 || { echo "error: $ENGINE not found" >&2; exit 1; }

# `docker` is often podman's compatibility shim, so ask the engine rather than trusting the name.
IS_PODMAN=0
if [ "$ENGINE" = podman ] || "$ENGINE" info 2>&1 | grep -qi conmon; then IS_PODMAN=1; fi

# Upgrading from the GuardAlert name: keep using the old data volume (the data is in it), and replace the
# old container (it would hold the port).
if ! "$ENGINE" volume inspect "$VOLUME" >/dev/null 2>&1 && "$ENGINE" volume inspect "$LEGACY_NAME-data" >/dev/null 2>&1; then
  VOLUME="$LEGACY_NAME-data"
  echo "note: reusing the existing data volume '$VOLUME' from before the rename" >&2
fi

# Plain `build` + `run` is the default. Compose is used only when explicitly requested.
COMPOSE=()
if [ "${USE_COMPOSE:-0}" = 1 ]; then
  if "$ENGINE" compose version >/dev/null 2>&1; then
    COMPOSE=("$ENGINE" compose)
  elif command -v podman-compose >/dev/null 2>&1; then
    COMPOSE=(podman-compose)
  elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
  else
    echo "error: USE_COMPOSE=1 but no compose provider found" >&2
    exit 1
  fi
fi

warn_rootless() {
  if [ "$IS_PODMAN" = 1 ] && [ "$(id -u)" != 0 ]; then
    cat >&2 <<'EOF'
note: rootless Podman cannot open raw sockets on the host network, so arp-scan will report an error.
      LanWarden still works through the kernel neighbour table. For full arp-scan discovery run this
      script as root (sudo scripts/run-container.sh) or use the rootful Quadlet unit in deploy/.
EOF
  fi
}

build() {
  if [ -n "${LANWARDEN_IMAGE:-}" ]; then "$ENGINE" pull "$IMAGE"; return; fi
  local fmt=()
  # Podman defaults to OCI images, which drop HEALTHCHECK; the docker format keeps it.
  [ "$IS_PODMAN" = 1 ] && fmt=(--format docker)
  "$ENGINE" build ${fmt[@]+"${fmt[@]}"} -t "$IMAGE" .
}

run_plain() {
  build
  local key_args=()
  if [ -n "${LANWARDEN_SECRET_KEY_FILE:-}" ]; then
    [ -r "$LANWARDEN_SECRET_KEY_FILE" ] || { echo "error: cannot read LANWARDEN_SECRET_KEY_FILE ($LANWARDEN_SECRET_KEY_FILE)" >&2; exit 1; }
    key_args=(-v "$(readlink -f "$LANWARDEN_SECRET_KEY_FILE"):/run/secrets/lanwarden_key:ro,Z" -e LANWARDEN_SECRET_KEY_FILE=/run/secrets/lanwarden_key)
  fi
  "$ENGINE" rm -f "$NAME" "$LEGACY_NAME" >/dev/null 2>&1 || true
  "$ENGINE" run -d --name "$NAME" --restart unless-stopped \
    --network host \
    --cap-drop ALL --cap-add NET_RAW \
    --read-only --tmpfs /tmp \
    -e "LANWARDEN_PORT=$PORT" \
    -e LANWARDEN_SETUP_TOKEN -e LANWARDEN_SECURE_COOKIES -e FORWARDED_ALLOW_IPS \
    -e LANWARDEN_REQUIRE_MFA -e LANWARDEN_TLS_MODE -e LANWARDEN_TLS_NAMES -e LANWARDEN_TLS_CERT -e LANWARDEN_TLS_KEY \
    -e LANWARDEN_SECRET_KEY -e LANWARDEN_DB_ENCRYPTION \
    ${key_args[@]+"${key_args[@]}"} \
    -v "$VOLUME:/data" \
    "$IMAGE"
}

case "${1:-up}" in
  build)
    build
    ;;
  up)
    warn_rootless
    echo "engine: $ENGINE (podman=$IS_PODMAN), compose: ${COMPOSE[*]:-not used}"
    if [ ${#COMPOSE[@]} -gt 0 ]; then
      LANWARDEN_PORT=$PORT "${COMPOSE[@]}" up -d --build
    else
      run_plain
    fi
    scheme=http
    if [ "${LANWARDEN_TLS_MODE:-off}" != off ] || [ -n "${LANWARDEN_TLS_CERT:-}" ]; then scheme=https; fi
    echo "LanWarden: $scheme://localhost:$PORT"
    ;;
  down)
    if [ ${#COMPOSE[@]} -gt 0 ]; then "${COMPOSE[@]}" down; else "$ENGINE" rm -f "$NAME"; fi
    echo "stopped; data volume '$VOLUME' kept (remove with: $ENGINE volume rm $VOLUME)"
    ;;
  logs)
    "$ENGINE" logs -f "$NAME"
    ;;
  status)
    "$ENGINE" ps --filter "name=^${NAME}\$"
    ;;
  *)
    echo "usage: $0 [build|up|down|logs|status]" >&2
    exit 2
    ;;
esac
