import { act, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { calls, fail, makeDevice, makeEvent, mockApi, renderAt } from "../test-utils";
import Dashboard from "./Dashboard";

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

const status = (over = {}) => ({
  version: "1.0.0",
  anomalies_7d: 2,
  devices: { total: 10, online: 6, offline: 3, new: 1, unknown: 2, always_connected_down: 1 },
  ...over,
});

const routes = (over: Record<string, unknown> = {}) => ({
  "/status": status(),
  "/dashboard*": {
    range: "24h",
    start: "2026-01-01T00:00:00Z",
    end: "2026-01-02T00:00:00Z",
    series: [
      { time: "2026-01-01T00:00:00Z", online: 3, total: 9 },
      { time: "2026-01-02T00:00:00Z", online: 6, total: 10 },
    ],
    type_distribution: [{ type: "camera", count: 4 }],
    recently_disconnected: [makeDevice({ id: 9, display_name: "Printer", is_online: false, status: "OFFLINE", last_disconnection: "2026-01-01T00:00:00Z" })],
  },
  "/devices*": { total: 1, items: [makeDevice({ id: 5, display_name: "Fresh Device" })] },
  "/events*": { total: 1, items: [makeEvent({ event_type: "NEW_DEVICE", device_name: "Fresh Device" })] },
  "/scanner/runs": { running: false, runs: [] },
  "/integrations/adguard/status": { configured: false },
  ...over,
});

describe("Dashboard", () => {
  it("shows the headline numbers as links into the filtered device list", async () => {
    mockApi(routes());
    renderAt(<Dashboard />);
    const total = await screen.findByRole("link", { name: /Total devices/ });
    expect(total.textContent).toContain("10");
    expect(screen.getByRole("link", { name: /^Online/ }).getAttribute("href")).toBe("/devices?online=true");
    expect(screen.getByRole("link", { name: /Offline/ }).getAttribute("href")).toBe("/devices?online=false");
    expect(screen.getByRole("link", { name: /Anomalies/ }).getAttribute("href")).toBe("/events?event_type=DEVICE_ANOMALY");
    expect(screen.getByRole("link", { name: /Always-connected down/ }).getAttribute("href")).toBe("/devices?always_connected=true&online=false");
  });

  it("fills the lists, charts and cards from the API", async () => {
    mockApi(routes());
    renderAt(<Dashboard />);
    expect(await screen.findByText("Fresh Device", { selector: "a" })).toBeTruthy();
    expect(await screen.findByText("Printer")).toBeTruthy();
    expect(screen.getByText("New Device")).toBeTruthy(); // recent event
    expect(screen.getByText("camera")).toBeTruthy(); // device type bar
    expect(screen.getByRole("img", { name: /Devices online over the last 24 hours: 6 online now, 10 known/ })).toBeTruthy();
    expect(await screen.findByText("Not configured")).toBeTruthy(); // AdGuard card
    expect(await screen.findByText("No scan has run yet.")).toBeTruthy(); // scan card
  });

  it("derives the 'not seen yet' share of the donut", async () => {
    mockApi(routes());
    renderAt(<Dashboard />);
    expect((await screen.findByRole("img", { name: /6 online, 3 offline, 1 not seen yet/ })).tagName).toBe("svg");
  });

  it("guides a first-time user when there are no devices", async () => {
    mockApi(routes({ "/status": status({ devices: { total: 0, online: 0, offline: 0, new: 0, unknown: 0, always_connected_down: 0 }, anomalies_7d: 0 }) }));
    renderAt(<Dashboard />);
    expect(await screen.findByText("No devices yet.")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Settings" }).getAttribute("href")).toBe("/settings");
  });

  it("shows empty states for the three recent lists", async () => {
    mockApi(
      routes({
        "/dashboard*": { range: "24h", start: "", end: "", series: [], type_distribution: [], recently_disconnected: [] },
        "/devices*": { total: 0, items: [] },
        "/events*": { total: 0, items: [] },
      }),
    );
    renderAt(<Dashboard />);
    expect(await screen.findByText("Nothing yet.")).toBeTruthy();
    expect(screen.getByText("No device has gone offline.")).toBeTruthy();
    expect(screen.getByText("No events recorded.")).toBeTruthy();
    expect(screen.getByText("No devices yet.", { selector: "p" })).toBeTruthy(); // device-type bars
  });

  it("shows an error instead of the page when the status cannot load", async () => {
    mockApi(routes({ "/status": fail(500, "status unavailable") }));
    renderAt(<Dashboard />);
    expect((await screen.findByRole("alert")).textContent).toBe("status unavailable");
  });

  it("reloads the chart when another time range is chosen", async () => {
    const api = mockApi(routes());
    renderAt(<Dashboard />);
    await screen.findByText("Fresh Device", { selector: "a" });
    const week = screen.getByRole("button", { name: "7 days" });
    expect(week.getAttribute("aria-pressed")).toBe("false");
    fireEvent.click(week);
    await waitFor(() => expect(calls(api)).toContain("GET /dashboard?range=7d"));
    expect(screen.getByRole("button", { name: "7 days" }).getAttribute("aria-pressed")).toBe("true");
  });

  it("refreshes every 30 seconds while the tab is visible", async () => {
    const api = mockApi(routes());
    vi.useFakeTimers({ shouldAdvanceTime: true }); // before render, so the page's interval runs on the fake clock
    renderAt(<Dashboard />);
    await screen.findByText("Fresh Device", { selector: "a" });
    const before = calls(api).filter((c) => c === "GET /status").length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_100);
    });
    await waitFor(() => expect(calls(api).filter((c) => c === "GET /status").length).toBeGreaterThan(before));
  });
});
