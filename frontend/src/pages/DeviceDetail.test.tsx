import { fireEvent, screen, waitFor } from "@testing-library/react";
import { Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { calls, fail, makeDevice, makeEvent, mockApi, renderAt } from "../test-utils";
import DeviceDetail from "./DeviceDetail";

afterEach(() => vi.unstubAllGlobals());

const page = () =>
  renderAt(
    <Routes>
      <Route path="/devices/:id" element={<DeviceDetail />} />
    </Routes>,
    { route: "/devices/1" },
  );
const routes = (over: Record<string, unknown> = {}) => ({ "/devices/1": makeDevice(), ...over });
const open = async (tab: string, over: Record<string, unknown> = {}) => {
  mockApi(routes(over));
  page();
  fireEvent.click(await screen.findByRole("tab", { name: tab }));
};
const bodyOf = (api: ReturnType<typeof mockApi>, method: string) =>
  JSON.parse(String(api.mock.calls.find(([, i]) => i?.method === method)![1]?.body));

const presence = {
  range: "24h",
  start: "2026-01-10T00:00:00Z",
  end: "2026-01-11T00:00:00Z",
  segments: [{ start: "2026-01-10T06:00:00Z", end: "2026-01-10T12:00:00Z" }],
  session_count: 2,
  online_seconds: 6 * 3600,
  tracked_seconds: 24 * 3600,
  online_percent: 25,
};

describe("DeviceDetail: header and overview", () => {
  it("shows the device, its status and the details it knows", async () => {
    mockApi(routes({ "/devices/1": makeDevice({ display_name: "NAS", hostname: "nas", current_ip: "10.0.0.5", mac_address: "aa:bb", effective_vendor: "Synology", effective_type: "storage", model: "DS220" }) }));
    page();
    expect(await screen.findByRole("heading", { name: "NAS" })).toBeTruthy();
    expect(screen.getByText("nas · 10.0.0.5 · aa:bb · Synology")).toBeTruthy();
    expect(screen.getByRole("link", { name: "← Devices" }).getAttribute("href")).toBe("/devices");
    expect(screen.getByText("storage (auto)")).toBeTruthy(); // type came from a guess
    expect(screen.getByText("DS220")).toBeTruthy();
  });

  it("does not call a user-set type automatic, and handles a device with no details", async () => {
    mockApi(routes({ "/devices/1": makeDevice({ device_type: "nas", effective_type: "nas", hostname: null, current_ip: null, mac_address: null, effective_vendor: null }) }));
    page();
    expect(await screen.findByText("nas")).toBeTruthy();
    expect(screen.queryByText("nas (auto)")).toBeNull();
    expect(screen.getByText("No details observed yet")).toBeTruthy();
  });

  it("shows loading, then an error if the device cannot be loaded", async () => {
    mockApi(routes({ "/devices/1": fail(404, "Device not found") }));
    page();
    expect(screen.getByText("Loading…")).toBeTruthy();
    expect((await screen.findByRole("alert")).textContent).toBe("Device not found");
  });

  it("marks an unreviewed device as known", async () => {
    const api = mockApi(routes({ "/devices/1": makeDevice({ is_known: false, status: "NEW" }), "PATCH /devices/1": makeDevice({ is_known: true }) }));
    page();
    fireEvent.click(await screen.findByRole("button", { name: "Mark as known" }));
    await waitFor(() => expect(screen.queryByRole("button", { name: "Mark as known" })).toBeNull());
    expect(bodyOf(api, "PATCH")).toEqual({ is_known: true });
  });

  it("offers no 'Mark as known' for a known device and switches tabs", async () => {
    mockApi(routes());
    page();
    await screen.findByRole("heading", { name: "Host One" });
    expect(screen.queryByRole("button", { name: "Mark as known" })).toBeNull();
    const tabs = screen.getAllByRole("tab");
    expect(tabs.map((t) => t.textContent)).toEqual(["Overview", "Presence", "Sessions", "Events", "Network", "AdGuard", "Settings"]);
    expect(tabs[0].getAttribute("aria-selected")).toBe("true");
    fireEvent.click(tabs[2]);
    expect(screen.getAllByRole("tab")[2].getAttribute("aria-selected")).toBe("true");
  });
});

describe("DeviceDetail: presence tab", () => {
  it("shows the timeline and the numbers, in the browser's timezone", async () => {
    const api = mockApi(routes({ "/devices/1/presence*": presence }));
    page();
    fireEvent.click(await screen.findByRole("tab", { name: "Presence" }));
    expect(await screen.findByText("6h 0m")).toBeTruthy();
    expect(screen.getByText("25%")).toBeTruthy();
    expect(screen.getByText("2")).toBeTruthy();
    const tz = -new Date().getTimezoneOffset();
    expect(calls(api)).toContain(`GET /devices/1/presence?range=24h&tz_offset_minutes=${tz}`);
  });

  it("reloads for another range", async () => {
    const api = mockApi(routes({ "/devices/1/presence*": presence }));
    page();
    fireEvent.click(await screen.findByRole("tab", { name: "Presence" }));
    await screen.findByText("6h 0m");
    fireEvent.click(screen.getByRole("button", { name: "7 days" }));
    await waitFor(() => expect(calls(api).some((c) => c.includes("range=7d"))).toBe(true));
    expect(screen.getByRole("button", { name: "7 days" }).getAttribute("aria-pressed")).toBe("true");
  });

  it("says so when the device was not online, with no availability figure", async () => {
    await open("Presence", { "/devices/1/presence*": { ...presence, segments: [], online_percent: null, online_seconds: 0, session_count: 0 } });
    expect(await screen.findByText("Not seen online in this period.")).toBeTruthy();
    expect(screen.getByText("—")).toBeTruthy();
  });

  it("shows an error", async () => {
    await open("Presence", { "/devices/1/presence*": fail(500, "no history") });
    expect((await screen.findByRole("alert")).textContent).toBe("no history");
  });
});

describe("DeviceDetail: network tab", () => {
  it("lists addresses, hostnames and discovery sources", async () => {
    await open("Network", {
      "/devices/1/network": {
        addresses: [{ ip: "10.0.0.5", first_seen: "2026-01-01T00:00:00Z", last_seen: "2026-01-02T00:00:00Z", source: "arp", current: true }, { ip: "10.0.0.9", first_seen: "2026-01-01T00:00:00Z", last_seen: "2026-01-02T00:00:00Z", source: null, current: false }],
        names: [{ name: "nas.lan", source: "mdns", first_seen: "2026-01-01T00:00:00Z", last_seen: "2026-01-02T00:00:00Z" }],
        sources: [{ source: "arp-scan", first_observed: "2026-01-01T00:00:00Z", last_observed: "2026-01-02T00:00:00Z", observations: 42 }],
        observation_retention_days: 30,
      },
    });
    expect(await screen.findByText("10.0.0.5")).toBeTruthy();
    expect(screen.getAllByText("current")).toHaveLength(1);
    expect(screen.getByText("nas.lan")).toBeTruthy();
    expect(screen.getByText("via mdns")).toBeTruthy();
    expect(screen.getByText("· 42 sightings")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Discovery sources (last 30 days)" })).toBeTruthy();
  });

  it("shows empty states and errors", async () => {
    await open("Network", { "/devices/1/network": { addresses: [], names: [], sources: [], observation_retention_days: 7 } });
    expect(await screen.findAllByText("Nothing recorded yet.")).toHaveLength(3);
  });

  it("shows a load error", async () => {
    await open("Network", { "/devices/1/network": fail(500, "net unavailable") });
    expect((await screen.findByRole("alert")).textContent).toBe("net unavailable");
  });
});

describe("DeviceDetail: sessions and events tabs", () => {
  it("lists sessions, marking one that is still open", async () => {
    await open("Sessions", {
      "/devices/1/sessions": [
        { id: 1, device_id: 1, connected_at: "2026-01-01T00:00:00Z", disconnected_at: "2026-01-01T01:00:00Z", last_seen: "2026-01-01T01:00:00Z", source: "arp", duration_seconds: 3600 },
        { id: 2, device_id: 1, connected_at: "2026-01-02T00:00:00Z", disconnected_at: null, last_seen: "2026-01-02T00:00:00Z", source: "arp", duration_seconds: null },
      ],
    });
    expect(await screen.findByText("still connected")).toBeTruthy();
    expect(screen.getByText("1h 0m")).toBeTruthy();
  });

  it("handles no sessions and a session error", async () => {
    await open("Sessions", { "/devices/1/sessions": [] });
    expect(await screen.findByText("No sessions recorded yet.")).toBeTruthy();
  });

  it("shows a sessions error", async () => {
    await open("Sessions", { "/devices/1/sessions": fail(500, "sessions down") });
    expect((await screen.findByRole("alert")).textContent).toBe("sessions down");
  });

  it("lists events with old and new values", async () => {
    await open("Events", { "/devices/1/events*": { total: 1, items: [makeEvent({ event_type: "DEVICE_IP_CHANGED", old_value: "10.0.0.1", new_value: "10.0.0.2", source: "arp" })] } });
    expect(await screen.findByText("Device Ip Changed")).toBeTruthy();
    expect(screen.getByText(/10\.0\.0\.1 → 10\.0\.0\.2/)).toBeTruthy();
  });

  it("handles no events and an events error", async () => {
    await open("Events", { "/devices/1/events*": { total: 0, items: [] } });
    expect(await screen.findByText("No events recorded yet.")).toBeTruthy();
  });

  it("shows an events error", async () => {
    await open("Events", { "/devices/1/events*": fail(500, "events down") });
    expect((await screen.findByRole("alert")).textContent).toBe("events down");
  });
});

describe("DeviceDetail: AdGuard tab", () => {
  const base = { configured: true, available: true, error: null, recognized: true, client_name: "NAS", client_ids: ["10.0.0.5", "aa:bb"], stats_queries: 1234, sample_size: 10, sample_blocked: 2, last_query: "2026-01-01T00:00:00Z", top_domains: [{ domain: "example.com", count: 7 }], recent: [{ time: "2026-01-01T00:00:00Z", domain: "ads.example.net", type: "A", blocked: true, reason: "filter" }, { time: null, domain: "ok.example.org", type: null, blocked: false, reason: null }] };

  it("shows DNS activity for a recognised client", async () => {
    await open("AdGuard", { "/devices/1/adguard": base });
    expect(await screen.findByText("Yes — “NAS”")).toBeTruthy();
    expect(screen.getByText("10.0.0.5, aa:bb")).toBeTruthy();
    expect(screen.getByText("1234")).toBeTruthy();
    expect(screen.getByText("10 queries, 2 blocked")).toBeTruthy();
    expect(screen.getByText("example.com")).toBeTruthy();
    expect(screen.getAllByText("blocked")).toHaveLength(1);
  });

  it("copes with missing stats and an unrecognised client with no queries", async () => {
    await open("AdGuard", { "/devices/1/adguard": { ...base, recognized: false, client_ids: [], stats_queries: null, last_query: null, sample_size: 0, sample_blocked: 0, top_domains: [], recent: [] } });
    expect(await screen.findByText("No persistent client entry")).toBeTruthy();
    expect(screen.getByText("not reported")).toBeTruthy();
    expect(screen.getByText("none in the query log")).toBeTruthy();
    expect(screen.getByText(/No queries from this device/)).toBeTruthy();
  });

  it("points to setup when AdGuard is not configured", async () => {
    await open("AdGuard", { "/devices/1/adguard": { ...base, configured: false } });
    expect((await screen.findByRole("link", { name: "Set it up" })).getAttribute("href")).toBe("/adguard");
  });

  it("reports an unavailable server, with a fallback message", async () => {
    await open("AdGuard", { "/devices/1/adguard": { ...base, available: false, error: { kind: "timeout", message: "timed out" } } });
    expect(await screen.findByText("AdGuard Home: timed out")).toBeTruthy();
  });

  it("falls back to 'unavailable' without an error message", async () => {
    await open("AdGuard", { "/devices/1/adguard": { ...base, available: false } });
    expect(await screen.findByText("AdGuard Home: unavailable")).toBeTruthy();
  });

  it("shows a request error", async () => {
    await open("AdGuard", { "/devices/1/adguard": fail(500, "adguard route down") });
    expect((await screen.findByRole("alert")).textContent).toBe("adguard route down");
  });
});

describe("DeviceDetail: settings tab", () => {
  const saveForm = () => fireEvent.submit(screen.getByRole("button", { name: "Save" }).closest("form")!);

  it("pre-fills from the device and saves every field", async () => {
    const api = mockApi(routes({ "/devices/1": makeDevice({ notes: "old note", device_group: "IoT" }), "PATCH /devices/1": (b: unknown) => makeDevice({ ...(b as object), display_name: "Renamed" }) }));
    page();
    fireEvent.click(await screen.findByRole("tab", { name: "Settings" }));
    expect(screen.getByLabelText(/^Group/)).toHaveProperty("value", "IoT");
    expect(screen.getByLabelText("Notes")).toHaveProperty("value", "old note");
    fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: "Renamed" } });
    fireEvent.change(screen.getByLabelText(/^Vendor/), { target: { value: "ACME" } });
    fireEvent.change(screen.getByLabelText(/^Type/), { target: { value: "router" } });
    fireEvent.change(screen.getByLabelText("Notes"), { target: { value: "new note" } });
    fireEvent.click(screen.getByLabelText("Favorite"));
    fireEvent.click(screen.getByLabelText("Trusted"));
    fireEvent.click(screen.getByLabelText("Always connected (alert when down)"));
    fireEvent.click(screen.getByLabelText("Alerts enabled"));
    fireEvent.click(screen.getByLabelText("Ignore (hide from lists and counts)"));
    saveForm();
    expect((await screen.findByRole("status")).textContent).toBe("Saved");
    expect(bodyOf(api, "PATCH")).toEqual({
      friendly_name: "Renamed",
      vendor_override: "ACME",
      device_type: "router",
      device_group: "IoT",
      notes: "new note",
      is_known: true,
      is_trusted: true,
      is_favorite: true,
      always_connected: true,
      alert_enabled: true,
      is_ignored: true,
    });
    expect(screen.getByRole("heading", { name: "Renamed" })).toBeTruthy(); // the page picked up the saved device
  });

  it("forgets the 'Saved' note as soon as the form is edited again", async () => {
    mockApi(routes({ "PATCH /devices/1": makeDevice() }));
    page();
    fireEvent.click(await screen.findByRole("tab", { name: "Settings" }));
    saveForm();
    await screen.findByRole("status");
    fireEvent.click(screen.getByLabelText("Known device"));
    await waitFor(() => expect(screen.queryByRole("status")).toBeNull());
  });

  it("shows why saving failed", async () => {
    mockApi(routes({ "PATCH /devices/1": fail(422, "Name too long") }));
    page();
    fireEvent.click(await screen.findByRole("tab", { name: "Settings" }));
    saveForm();
    expect((await screen.findByRole("alert")).textContent).toBe("Name too long");
    expect(screen.queryByRole("status")).toBeNull();
  });
});
