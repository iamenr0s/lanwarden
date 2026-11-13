# Secrets, encryption and account recovery

## What is stored how

The admin password is an scrypt **hash**. The AdGuard and SMTP passwords, **webhook URLs** (they are bearer tokens),
webhook signing secrets and the two-step secret are **encrypted** (AES via Fernet, key derived from the secret key
with HKDF). Recovery codes are keyed hashes. None of these ever comes back through the API.

By default the secret key is generated into the data volume (`secret_key`, mode 0600), so a copy of the volume holds
both the lock and its key. Three optional steps close that:

1. **Keep the key elsewhere.** Set `LANWARDEN_SECRET_KEY` (at least 16 characters, 32+ recommended) or point
   `LANWARDEN_SECRET_KEY_FILE` at a file (a Podman/Docker secret, or a root-only file; see the commented lines in
   [deploy/lanwarden.container](../deploy/lanwarden.container)). With the run script:
   `LANWARDEN_SECRET_KEY_FILE=/root/lanwarden.key scripts/run-container.sh`. The file is mounted read-only and must be
   readable by uid 10001 (rootful: `sudo chown 10001 key && sudo chmod 400 key`; rootless Podman:
   `podman unshare chown 10001:10001 key`). Generate one with
   `python3 -c 'import secrets; print(secrets.token_urlsafe(48))'`. Existing data keeps working if you move the *same*
   key out of the volume.
2. **Rotate it** when it may have leaked: run `docker exec lanwarden python -m app rotate-key --dry-run`, then
   `... rotate-key` (the new key comes from `LANWARDEN_NEW_SECRET_KEY` / `_FILE`, or is generated). All stored secrets
   are re-encrypted in one transaction. Every session ends and **MFA recovery codes are cleared** (regenerate them in
   Settings; the authenticator itself keeps working). Back up the data volume first. If the key lives in the data
   directory the tool replaces it; otherwise it prints where to put the new one.
3. **Encrypt the whole database** (SQLCipher) so MACs, hostnames, vendors, IPs, notes and events are unreadable in a
   stolen volume or backup: set `LANWARDEN_DB_ENCRYPTION=sqlcipher` **and** step 1 (LanWarden refuses to start
   otherwise). Convert an existing database with the app stopped: `python -m app encrypt-db`. It keeps the old file as
   `lanwarden.db.bak`, which is still **unencrypted**: delete it once you have checked LanWarden starts. `decrypt-db`
   reverses it. The database key is derived from the secret key, so rotating the key re-keys the file too.

This protects data *at rest*. Someone who compromises the running app or the host can read what the app can. Lose the
key and the encrypted database and secrets are gone: back the key up separately from the data.

## Two-step verification

Settings → Two-step verification: scan the QR code with any authenticator app, confirm a code, and save the 10
one-time recovery codes. Sign-in then needs the password **and** a code. Set `LANWARDEN_REQUIRE_MFA=true` to make it
mandatory (the data pages stay locked until you enrol).

## Locked out

Anyone with shell access to the server can recover an account:

```bash
docker exec -it lanwarden python -m app reset-mfa admin        # or: podman exec / python -m app on a native install
docker exec -it lanwarden python -m app reset-password admin   # prompts for the new password; also lifts lockouts
```
