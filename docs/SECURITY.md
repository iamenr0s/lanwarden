# LanWarden security review

Reviewed against the code as it stands (v0.1.0). Everything marked **verified** is covered by an
automated test or was observed running in the container; **by design** means a documented limitation,
not an oversight. Run `scripts/security-scan.sh` to repeat the automated checks.

## What is being protected, and from whom

LanWarden holds the inventory of your network, an AdGuard Home credential, SMTP/webhook secrets, and
an admin login. It runs with host networking and a raw-socket capability.

| Threat | Who |
|---|---|
| Claiming or guessing into the admin account | any device on the LAN |
| Hostile data: hostnames, DHCP/DNS names are chosen by the devices being monitored | any device on the LAN |
| A device impersonating another (MAC spoofing, IP conflicts) | any device on the LAN |
| Cross-site requests from a page the admin visits | the open web |
| Stolen session cookie, stolen password, or backup | malware, phishing, a shared machine |
| Reading the database or secrets on the host | other local users |
| Known-vulnerable dependencies | supply chain |

## Controls

| Requirement | Implementation | Status |
|---|---|---|
| Credentials never reach the frontend | AdGuard password, SMTP password and webhook secret are write-only; APIs return `password_set`-style booleans | verified (tests assert the secret is absent from every response) |
| No plaintext secrets at rest | Fernet (AES-128-CBC + HMAC), key derived from the instance secret key with HKDF-SHA256; covers AdGuard/SMTP passwords, **webhook URLs** (bearer tokens), webhook signing secrets and the TOTP secret; admin password is scrypt (N=2^14); recovery codes stored as keyed hashes; `rotate-key` re-encrypts everything under a new key | verified (DB contents asserted, also in the container) |
| Key kept apart from the data (opt-in) | `LANWARDEN_SECRET_KEY` / `LANWARDEN_SECRET_KEY_FILE` keep the key out of the data volume; minimum length 16, warning below 32 | verified (tests; in the container with a mounted key file the volume held no `secret_key`) |
| Encrypted database (opt-in) | SQLCipher via `LANWARDEN_DB_ENCRYPTION=sqlcipher`: the inventory (MACs, hostnames, vendors, IPs, notes, events) is unreadable in a stolen volume/backup; the key is derived from the master key and the app **refuses to start** if that key sits in the data dir | verified (seeded MAC/hostname/vendor strings absent from the file and its `-wal`, a plain-DB control contains them; wrong key refused; real container) |
| Secure session handling | signed cookie, `HttpOnly`, `SameSite=Strict`, `Secure` + HSTS when HTTPS is declared or built in, fresh session on login/setup/password or MFA change, 7-day lifetime | verified |
| Session revocation | changing the password or the MFA state invalidates every other session (the cookie carries a version derived from both) | verified |
| Brute-force resistance | failures are stored **in the database**, so lockouts survive restarts: per address 5 failures / 15 min start a lockout that doubles (30 s up to 15 min); per username 20 failures from any addresses start the same progression; applies to login, the MFA step, setup token, password change and MFA management; locked-out attempts are refused with `Retry-After` and are not recorded; unknown users cost the same as wrong passwords | verified (restart persistence also checked by restarting the container) |
| Multi-factor authentication | optional TOTP (RFC 6238) with 10 single-use recovery codes; two-step sign-in issues no session until the code is verified; a code works once; `LANWARDEN_REQUIRE_MFA=true` forces enrolment (data endpoints answer 403 until enrolled, and MFA cannot be switched off); `python -m app reset-mfa <user>` / `reset-password <user>` recover a locked-out operator | verified (RFC 6238 test vectors; end to end against an independent TOTP implementation in the container) |
| Transport security | optional built-in HTTPS: your own certificate, or `LANWARDEN_TLS_MODE=selfsigned` (ECDSA P-256, SANs = localhost + the host's addresses + `LANWARDEN_TLS_NAMES`, key mode 0600, auto-renewed); in-app warning when credentials would cross the network over plain HTTP | verified (real TLS handshake in tests and in the container: trusted with only the generated certificate, rejected otherwise, HSTS and Secure cookie present) |
| First-run takeover | optional `LANWARDEN_SETUP_TOKEN`, constant-time compare, throttled | verified |
| Authorization | every non-public route requires login; a test enumerates the OpenAPI schema and fails if any route answers anything but 401 without a session (30 routes today) | verified |
| CSRF | `SameSite=Strict` cookie, JSON-only bodies (form/text bodies are rejected with 422), no CORS | verified |
| Injection (SQL) | ORM everywhere; `LIKE` wildcards escaped; sort/filter fields are allow-listed; integer parameters are bounded | verified (injection strings and oversized integers tested; fuzzed) |
| Injection (OS) | `arp-scan`/`ip` run with fixed argv, never a shell; interface names must start alphanumeric, CIDRs are parsed and bounded (IPv4, >= /16) | verified |
| XSS | React escapes all output; no `dangerouslySetInnerHTML` (the QR code is built from SVG elements); CSP allows same-origin scripts only | verified |
| Email header injection | addresses with whitespace/CR/LF rejected; subject newlines stripped | verified |
| Secrets in logs/errors | errors are short and never include credentials or webhook URLs (often token-bearing) | verified |
| File permissions | `umask 077` set by the app: DB, WAL, `secret_key` and the TLS key are owner-only | verified |
| Container least privilege | non-root (uid 10001), `cap_drop ALL` + `NET_RAW`, read-only root, one data volume | verified (rootless Podman) |
| Impersonation detection | `DEVICE_ANOMALY` events for: one address claimed by several MACs in a scan (`ip_conflict`); a trusted device answering at several addresses (`mac_multi_ip`); a trusted device seen away from its DHCP lease (`identity_drift`); a trusted device's hostname changing (`hostname_changed`). De-duplicated for 6 h, shown on the dashboard, filterable in Events, available as a notification trigger; private/locally-administered MACs are marked | verified (unit tests; engine fed a conflicting scan inside the container) |
| API robustness | Schemathesis fuzzes every endpoint from the OpenAPI schema and fails on any 5xx | verified (about 12,000 generated requests, no server errors, after the fix below) |
| Dependencies | runtime Python packages are pinned to exact versions **with sha256 hashes** (`backend/requirements.txt`, generated from `requirements.in` by `scripts/lock-requirements.sh`) and the image installs them with `pip --require-hashes`, so a changed or substituted package fails the build; frontend: `package-lock.json` integrity hashes with `npm ci`. `pip-audit`: none known; `npm audit` (and `npm audit signatures`): none; `bandit`: nothing at medium or above | verified at review time |
| Static analysis, secrets | `semgrep` (Python, OWASP top ten, TypeScript, React rules): one informational finding, the intentional wildcard bind for multicast, suppressed with a stated reason; `gitleaks`: no secrets in the tree | verified at review time |

## Findings (all fixed)

1. **First-run takeover**: until the first admin existed, anyone reaching the port could create it. Added the optional setup token.
2. **No way to change the password, and no session revocation.** Added Settings -> Account; sessions now die when the password or MFA state changes.
3. **`/api/docs` and `/api/openapi.json` were public.** Now behind login.
4. **No security headers.** Added CSP, `X-Frame-Options`, `nosniff`, `Referrer-Policy`, `no-store` for the API, HSTS over HTTPS.
5. **File modes depended on how the process was launched.** The DB was world-readable under a default umask. The app now sets `umask 077` itself.
6. **Interface names such as `--help` passed validation** (argument injection into `arp-scan`). Fixed early; kept as a regression test.
7. **react-router advisories** (open redirect, SSR deserialisation). Not reachable here, but upgraded to 7.x so the audit is clean.
8. **A TLS error without a `reason` crashed the email error handler**; a Starlette status constant was deprecated. Both fixed.
9. **Oversized integers crashed the API with a 500** (`GET /api/devices?offset=9223372036854775808` raised a database `OverflowError`; the same applied to every ID path parameter). Found by the fuzzer, not by hand-written tests. All integer parameters are now bounded and answer 422.
10. **Login throttling was in memory and per IP** (reset on restart, one attacker behind a proxy locked everyone out). Now stored in the database with per-address and per-username limits.
11. **There was no recovery path for a lost password.** Added `python -m app reset-password` and `reset-mfa`.
12. **The authenticator URI percent-encoded the label's colon**, which some apps handle badly. It now uses the conventional `Issuer:account` form.

## Residual risks (read these)

* **Presence is still not authenticated.** `arp-scan` and the neighbour table trust whatever answers, and
  ARP has no way to prove who is speaking. The anomaly events catch the *inconsistencies* a spoofer or a
  misconfiguration tends to produce. They **cannot** catch a careful clone, for example one that takes over
  a MAC while the real device is switched off, and they can raise false alarms (an address reassigned a few
  seconds after the old holder's neighbour entry was confirmed). The real fix is at the network: 802.1X,
  port security, DHCP snooping with dynamic ARP inspection, static ARP for critical hosts, or VLANs.
* **The default is still plain HTTP.** HTTPS is built in but opt-in, because a certificate needs a trust
  decision that only you can make. A self-signed certificate gives encryption but not identity: until you
  trust it (or pin it) a browser cannot tell it from an impostor. On a shared network use a reverse proxy
  with a real certificate. The in-app banner warns whenever credentials would cross the network in clear.
* **MFA is TOTP, which can be phished** (a fake login page can relay a code in real time). It is also
  optional unless you set `LANWARDEN_REQUIRE_MFA=true`. There is no WebAuthn/passkey support, still a
  **single admin account**, no roles, and no audit log of admin actions.
* **Throttling trades availability for safety.** Twenty failures against one username from any addresses lock
  that username for up to 15 minutes, so someone who knows your username can keep you out of the web UI
  (the `reset-password` command lifts the lockout). Behind a reverse proxy the per-address limit is only
  meaningful if `FORWARDED_ALLOW_IPS` names the proxy.
* **Sessions last 7 days** with no idle timeout, and revocation is only by changing the password or MFA state.
* **The server fetches URLs an admin supplies** (AdGuard, webhooks), so an admin can make it contact
  internal hosts. That is inherent to the features; redirects are not followed and only http(s) is allowed.
* **mDNS and SSDP are unauthenticated multicast.** Any device can claim any model string. Replies are attributed to
  their UDP source address (addresses named inside a reply are ignored), parsed defensively (fuzz-style tests: truncated
  packets, pointer loops), and the only HTTP request made on a device's say-so goes to the host that answered, over plain
  http, without redirects, capped at 64 KB. A device can still make LanWarden issue one GET to a port and path of its own
  choosing on itself. Model strings are display-only, control characters stripped and length-limited.
* **Device type is a guess from attacker-influenced names.** A device can choose a hostname such as `printer` to be labelled
  that way. The type is display-only and never used for trust decisions or anomaly rules.
* **Hostile names reach notifications.** Device hostnames are attacker-influenced. Email is plain text and
  safe from injection, but webhook `text` containing Slack/Discord markup could render links in the
  receiving app.
* **Container privileges.** Host networking + `NET_RAW` is what makes scanning work; a compromise of
  the app would have raw-socket access on the host network. `no-new-privileges` cannot be set because the
  `arp-scan` file capability would stop working. Rootless Podman avoids the privilege but cannot run
  `arp-scan` at all.
* **CI actions are pinned to commit hashes** (version in a comment), and Dependabot proposes updates weekly
  (`.github/dependabot.yml`). The reason: a mutable tag can be moved; `aquasecurity/trivy-action`'s old unprefixed tags
  were part of a March 2026 supply-chain incident, so this workflow uses the `v0.36.0` release by hash. Reviewing a
  Dependabot PR is still a trust decision about the new code.
* **Pinning is not vetting.** Hashes stop a package changing after you locked it; they do not tell you the version
  you locked was clean. Updates are deliberate (`scripts/lock-requirements.sh --upgrade`): read the diff, run the tests
  and `scripts/security-scan.sh`. Dev tools (`requirements-dev.txt`) are version ranges, not hash-pinned, and the
  base image (`python:3.14-slim`) and the Debian packages in it are pinned by tag only, not by digest.
* **Image signature and scan score.** Released images (Docker Hub and Quay) are signed keyless with cosign by the
  release workflow, and carry a Trivy vulnerability attestation. The score (`scripts/vuln-score.sh`, 100 = no known
  fixable vulnerability) is this project's own weighting and informational; the HIGH/CRITICAL Trivy scan is the gate.
  A signature proves the image was built by this repository's workflow, not that its contents are free of bugs.
  Verify before you run it (replace `<tag>`):

  ```sh
  cosign verify quay.io/iamenr0s/lanwarden:<tag> \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp '^https://github.com/iamenr0s/lanwarden/\.github/workflows/release\.yml@refs/tags/v'
  cosign verify-attestation --type vuln quay.io/iamenr0s/lanwarden:<tag> \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp '^https://github.com/iamenr0s/lanwarden/\.github/workflows/release\.yml@refs/tags/v'
  ```
* **Backups.** By default the data volume holds the encrypted secrets *and* the key that decrypts them (and the TLS
  key); move the key out of it (`LANWARDEN_SECRET_KEY_FILE`) so a backup alone is not enough. An `encrypt-db` run leaves
  `lanwarden.db.bak` unencrypted until you delete it. Protect backups as secrets. Changing the key by hand makes stored secrets unreadable (they must be re-entered); use `python -m app rotate-key` instead.
* **Swagger UI** (opened from `/api/docs`, login required) loads its script from the jsDelivr CDN in your browser.
* **The CI workflow has not been run on GitHub** (it was written and its YAML validated locally; the same
  checks were run locally via `scripts/security-scan.sh`). `trivy` and the ZAP baseline were not available here.

## What automated assurance does and does not give you

Run by `scripts/security-scan.sh` and CI: unit/API tests (98% line coverage), `ruff` and `bandit` security
rules, `semgrep`, `gitleaks`, `pip-audit`, `npm audit`, Schemathesis fuzzing, and optionally `trivy` and an OWASP ZAP baseline.

It finds known-vulnerable packages, common coding mistakes, crashes on malformed input, and regressions.
It does **not** find logic flaws that return a normal-looking response, multi-step attacks, problems that need
a second user or a real network, or anything about your deployment. The fuzzer only asserts "no server
error", and ZAP's baseline is unauthenticated. **This is not a penetration test**, and a developer reviewing
their own code shares that code's blind spots. An independent test is the remaining step.

### Scope brief for an independent tester

* **Target:** the web app and API (HTTP or HTTPS, default port 8080) running from the published image with host
  networking, plus the container's privileges. Provide a throwaway instance with an admin account and, if you
  want authenticated testing, MFA both on and off.
* **Worth probing:** authentication and session handling (fixation, cookie flags, revocation after password or
  MFA changes); the MFA flow (code reuse and races, token tampering, recovery-code handling, brute force and
  throttle evasion, `X-Forwarded-For` spoofing when a proxy is configured); first-run setup; the AdGuard and
  webhook URL settings (SSRF, redirect handling); notification content built from attacker-controlled names;
  file permissions and secrets in the data volume; the container's capability set; the TLS configuration.
* **Out of scope:** AdGuard Home itself, your network equipment, denial of service against the host.

## Operator checklist

- [ ] HTTPS: built in (`LANWARDEN_TLS_MODE=selfsigned` or your own certificate) or a reverse proxy; behind a proxy set `LANWARDEN_SECURE_COOKIES=true` and `FORWARDED_ALLOW_IPS`; firewall the port.
- [ ] `LANWARDEN_SETUP_TOKEN` set before first start, or setup completed immediately.
- [ ] Long unique admin password; two-step verification enrolled (or `LANWARDEN_REQUIRE_MFA=true`); recovery codes stored offline.
- [ ] Notification rule for `Network anomaly`, and devices you vouch for marked **Trusted** (anomaly rules about identity apply to them).
- [ ] Volume / data directory backups encrypted and access-controlled.
- [ ] Run `scripts/security-scan.sh` (or enable CI) after dependency updates; rebuild the image periodically.
- [ ] Restrict who can reach the host's Docker/Podman socket: access to it bypasses everything above.

## Reporting a vulnerability

Open a private security advisory at <https://github.com/iamenr0s/lanwarden/security/advisories/new> (or contact the maintainer directly). Please do not
file public issues for undisclosed vulnerabilities.
