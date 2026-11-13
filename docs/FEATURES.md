# Features

## How scanning works

* On startup (after 10 s) and then every *scan interval*, enabled providers run: **arp-scan** (active ARP sweep) and
  the **neighbour table** (`ip neigh`, live entries only). **Scan now** on the dashboard (or `POST /api/scanner/run`)
  triggers one immediately.
* Which network is scanned: the CIDRs you configure in Settings; else the networks of the interfaces you pick; else
  the single detected network. If several are detected nothing is scanned until you choose; the dashboard says so.
* Observations from all providers are merged per MAC. A device is **offline** only after being silent longer than the
  *offline threshold* (one missed scan is ignored). If *every* provider fails, nobody is marked offline.
* A reused IP never merges two devices; a MAC that moves IP raises *IP changed*.
* Manual fields (name, vendor override, type, group, flags, notes) are never overwritten.
* Events (discovered, connected, disconnected, IP/name changed, always-connected down/recovered) and per-device
  sessions are recorded. The host running LanWarden does not appear in its own ARP results.

## Dashboard

Summary cards (total, online, offline, new/unknown, always-connected down; each links to the matching filtered device
list), an online/offline ring, device types, devices over time (24 h hourly / 7 d 6-hourly / 30 d daily, built from
recorded sessions, so history starts when LanWarden began recording), the scan and AdGuard cards, and lists of
recently discovered and disconnected devices and recent events. It refreshes every 30 s while the tab is visible.
Charts are plain SVG and every one has a text equivalent. Ignored devices are excluded everywhere. Theme (dark / light
/ system) is in the sidebar.

## Presence and history

The device page has a **Presence** tab (Today / 24 hours / 7 days / 30 days): a timeline of the intervals the device
was online, with online time, availability % and connection count, built from the recorded sessions. "Today" starts at
your browser's local midnight, and a device first seen 9 days ago is judged over 9 days, not 30. The **Network** tab
lists the device's IP history, observed hostnames (and which source reported them), and which discovery sources have
seen it. Raw sightings are pruned after *Sighting retention* days (Settings, default 7); devices, events and sessions
are never pruned automatically.

## Hardware identification

Every device with a MAC gets a **vendor** from the IEEE registries (24-, 28- and 36-bit blocks, longest match wins),
read offline. The image downloads the current registries when it is built (`scripts/fetch_oui.py`; rebuild with
`--no-cache` to refresh them) and falls back to distro data if that fails. A vendor reported by arp-scan wins;
randomised MACs (the locally-administered bit) are labelled **Private MAC**. A **type** (phone, printer, tv, nas,
network, iot, computer, speaker, camera) is guessed from the hostname, then the vendor, and shown with "(auto)". Your
own Type on the device page always overrides the guess.

Limits: organisations registered as "Private" and devices with random MACs stay unidentified; the type is a hint, not
evidence. Point `LANWARDEN_OUI_DIR` at a directory holding IEEE's `oui.csv`, `mam.csv` and `oui36.csv` to use your
own copy.

**Model names** come from **mDNS** (DNS-SD TXT records) and **SSDP/UPnP** (`modelName`), shown as *Model* on the device
page and used for the type guess. Toggle both with *mDNS + SSDP* in Settings. They only describe devices the scan has
already found by MAC: an answer never creates a device and never counts as presence. Apple devices report identifiers
such as `J482AP`, not marketing names; only devices that answer within about three seconds are described. It needs
host networking and a host firewall that lets multicast answers through (queries are sent from ports 5353 and 1900).

## Notifications

Create rules on the **Notifications** page. A rule is a channel (**Email/SMTP** or **Webhook**) plus the events it
covers: *unknown device discovered*, *always-connected device offline*, *always-connected device recovered*, and
optionally *connected*, *disconnected*, *IP changed*, *name changed*. **Send test** checks a saved rule, and a
delivery log shows what was sent and why anything failed.

* **One digest per rule per scan.** Discovering 50 devices on the first scan sends one message listing them (text
  capped at 30 lines; webhooks always get the complete `events[]`).
* **Per-device switch.** A device with *Alerts enabled* off, or marked *Ignore*, never notifies (its events are still
  recorded).
* **Webhook** sends `POST` JSON `{source, title, text, events[]}`; `text` works with Slack-style incoming webhooks.
  With a signing secret the body is signed: `X-LanWarden-Signature: sha256=<hmac-sha256 hex of the raw body>`.
  Redirects are not followed.
* **Email** supports STARTTLS, SSL/TLS or none, with certificate verification on by default. Addresses containing
  whitespace or newlines are rejected.
* Delivery happens after the scan is committed, so a failed or slow notification never loses or delays scan results.
  Failures are logged and shown in the delivery log (kept in memory; there is no retry).
* More channels plug in by subclassing `NotificationProvider` in `backend/app/notifications/` (a config model, a list
  of secret fields, a `send` method) and registering it in `main.py`.

## Spoofing and conflict detection

ARP can't prove who is answering, so LanWarden flags inconsistencies (event type **Network anomaly**, also a
notification trigger and a dashboard card): one address claimed by two MACs at once, a trusted device answering at
several addresses, a trusted device seen away from its DHCP lease, a trusted device whose hostname changed. Mark
devices you vouch for as **Trusted** on their Settings tab to enable the identity checks. MACs with the
locally-administered bit get a *private MAC* tag. This is detection, not prevention; see [SECURITY.md](SECURITY.md)
for what would actually stop impersonation (802.1X, port security, DHCP snooping).

## AdGuard Home

Configure it on the **AdGuard** page (URL, username, password, Verify TLS, timeout), press **Test connection**, then
enable *AdGuard Home* under Settings → Discovery sources. AdGuard is optional: if it goes down, the dashboard card,
device tab and scan report a clear error while other providers carry on.

It reads only the documented API (HTTP Basic, base path `/control`): `/status`, `/dhcp/status`, `/clients`,
`/clients/search`, `/querylog`, `/stats`. Nothing in AdGuard is modified.

| AdGuard data | Used as |
|---|---|
| DHCP leases (MAC + IP + hostname) | **identity only**: names devices, or lists a never-seen device as *Unknown*. A lease never marks a device online or moves its IP |
| Clients / auto-clients | **names only** |
| Query log | **presence**: a client that queried DNS in the last scan window stays online even if ARP missed it |

IP-only evidence (query log, auto-clients) never creates a device, and only attaches to the single *online* device
currently at that IP. The device page has an **AdGuard** tab: whether AdGuard knows the client, last query, recent
domains and blocked counts, and AdGuard's own per-client total. The AdGuard password is encrypted at rest and never
returned by the API; testing with a changed URL never sends the stored password to the new address.
