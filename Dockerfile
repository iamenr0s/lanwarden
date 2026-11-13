# Fully qualified image names: Podman can refuse or prompt on short names.
FROM docker.io/library/node:26-alpine AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM docker.io/library/python:3.15-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1

# arp-scan: discovery. iproute2: interface/network suggestions. libcap2-bin: setcap.
RUN apt-get update \
 && apt-get install -y --no-install-recommends arp-scan iproute2 libcap2-bin zlib1g \
 && rm -rf /var/lib/apt/lists/* \
 # lets the unprivileged app user open raw sockets, and only through this binary
 && setcap cap_net_raw+ep "$(readlink -f /usr/sbin/arp-scan)"

RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin lanwarden \
 && mkdir -p /data && chown lanwarden /data

WORKDIR /app
COPY backend/requirements.txt ./
# every package must match the hash recorded in requirements.txt (regenerate with scripts/lock-requirements.sh)
RUN pip install --require-hashes -r requirements.txt
# Current IEEE vendor registries (the distro's arp-scan copy is years old). A failed download is not fatal.
COPY scripts/fetch_oui.py /tmp/fetch_oui.py
RUN python /tmp/fetch_oui.py /opt/oui && rm /tmp/fetch_oui.py
# pip is not needed at runtime, and its vendored urllib3/msgpack/setuptools trip the CVE scan
RUN pip uninstall -y pip
COPY backend/app ./app
COPY --from=web /web/dist ./frontend_dist

ENV LANWARDEN_DATA_DIR=/data LANWARDEN_FRONTEND_DIR=/app/frontend_dist \
    LANWARDEN_HOST=0.0.0.0 LANWARDEN_PORT=8080
USER lanwarden
VOLUME /data
EXPOSE 8080

# scheme-aware: when the app terminates TLS itself the probe uses https (certificate not verified on loopback)
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import os,ssl,urllib.request as u; t=os.environ.get('LANWARDEN_TLS_MODE','off')!='off' or os.environ.get('LANWARDEN_TLS_CERT'); u.urlopen(('https' if t else 'http')+'://127.0.0.1:'+os.environ['LANWARDEN_PORT']+'/api/health', timeout=3, context=ssl._create_unverified_context() if t else None)"

# the app sets umask 077 itself (DB, secret key, TLS key are owner-only)
CMD ["python", "-m", "app"]
