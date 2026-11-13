def names(r):
    return sorted(d["display_name"] for d in r.json()["items"])


def test_list_and_filters(authed, seed):
    assert authed.get("/api/devices").json()["total"] == 3
    assert names(authed.get("/api/devices", params={"online": True})) == ["100%_odd", "laptop"]
    assert names(authed.get("/api/devices", params={"known": False})) == ["laptop"]
    assert names(authed.get("/api/devices", params={"always_connected": True})) == ["nas"]
    assert names(authed.get("/api/devices", params={"status": "NEW"})) == ["laptop"]


def test_search_fields_and_wildcards_are_literal(authed, seed):
    assert names(authed.get("/api/devices", params={"q": "synology"})) == ["nas"]
    assert names(authed.get("/api/devices", params={"q": "00:02"})) == ["nas"]
    assert names(authed.get("/api/devices", params={"q": "192.168.1.1"})) == ["laptop"]
    # '%' and '_' must not act as LIKE wildcards
    assert names(authed.get("/api/devices", params={"q": "%"})) == ["100%_odd"]
    assert authed.get("/api/devices", params={"q": "l_ptop"}).json()["total"] == 0


def test_sort_and_paging(authed, seed):
    r = authed.get("/api/devices", params={"sort": "name", "order": "asc", "limit": 2})
    assert [d["display_name"] for d in r.json()["items"]] == ["100%_odd", "laptop"]
    assert r.json()["total"] == 3
    assert authed.get("/api/devices", params={"sort": "password"}).status_code == 422


def test_patch_sets_user_fields_and_acknowledges_new(authed, seed):
    laptop = seed[0]
    r = authed.patch(f"/api/devices/{laptop}", json={
        "friendly_name": "  Work\x07 laptop ", "is_known": True, "always_connected": True, "notes": ""})
    body = r.json()
    assert r.status_code == 200
    assert body["friendly_name"] == "Work laptop"  # trimmed, control chars removed
    assert body["notes"] is None
    assert body["status"] == "ONLINE"  # NEW cleared once known
    assert body["display_name"] == "Work laptop"


def test_patch_rejects_scanner_owned_and_unknown_fields(authed, seed):
    for payload in ({"mac_address": "aa:aa:aa:aa:aa:aa"}, {"status": "ONLINE"}, {"is_known": None}):
        assert authed.patch(f"/api/devices/{seed[0]}", json=payload).status_code == 422


def test_404s(authed):
    assert authed.get("/api/devices/999").status_code == 404
    assert authed.patch("/api/devices/999", json={"is_favorite": True}).status_code == 404


def test_events_and_sessions(authed, seed):
    ev = authed.get(f"/api/devices/{seed[0]}/events").json()
    assert ev["total"] == 1 and ev["items"][0]["event_type"] == "DEVICE_DISCOVERED"
    assert ev["items"][0]["device_name"] == "laptop"
    assert authed.get(f"/api/devices/{seed[0]}/sessions").json() == []
    allv = authed.get("/api/events", params={"event_type": "DEVICE_DISCOVERED", "q": "laptop"}).json()
    assert allv["total"] == 1
    assert authed.get("/api/events", params={"event_type": "BOGUS"}).status_code == 422


def test_status_counts(authed, seed):
    d = authed.get("/api/status").json()["devices"]
    assert d == {"total": 3, "online": 2, "offline": 1, "new": 1, "unknown": 1, "always_connected_down": 1}
