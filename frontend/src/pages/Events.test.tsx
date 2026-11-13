import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { calls, fail, makeEvent, mockApi, renderAt } from "../test-utils";
import Events from "./Events";

afterEach(() => vi.unstubAllGlobals());

const lastQuery = (api: ReturnType<typeof mockApi>) => new URLSearchParams(calls(api).at(-1)!.split("?")[1]);

describe("Events", () => {
  it("lists events with a link to the device and old/new values", async () => {
    mockApi({
      "/events*": {
        total: 2,
        items: [
          makeEvent({ id: 1, event_type: "IP_CHANGED", old_value: "10.0.0.1", new_value: "10.0.0.2", source: "arp" }),
          makeEvent({ id: 2, device_id: null, device_name: null }),
        ],
      },
    });
    renderAt(<Events />);
    expect(await screen.findByText("Ip Changed")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Host One" }).getAttribute("href")).toBe("/devices/1");
    expect(screen.getByText(/10\.0\.0\.1 → 10\.0\.0\.2/)).toBeTruthy();
    expect(screen.getByText("(deleted device)")).toBeTruthy();
    expect(screen.getByText("2 events")).toBeTruthy();
  });

  it("says when nothing matches and uses the singular", async () => {
    mockApi({ "/events*": { total: 0, items: [] } });
    renderAt(<Events />);
    expect(await screen.findByText("No events match.")).toBeTruthy();
    expect(screen.getByText("0 events")).toBeTruthy();
  });

  it("shows an error", async () => {
    mockApi({ "/events*": fail(500, "boom") });
    renderAt(<Events />);
    expect((await screen.findByRole("alert")).textContent).toBe("boom");
  });

  it("starts from an event_type in the URL (dashboard deep link)", async () => {
    const api = mockApi({ "/events*": { total: 0, items: [] } });
    renderAt(<Events />, { route: "/events?event_type=DEVICE_ANOMALY" });
    await screen.findByText("No events match.");
    expect(lastQuery(api).get("event_type")).toBe("DEVICE_ANOMALY");
  });

  it("filters by type, date range and (debounced) search, restarting at page 1", async () => {
    const api = mockApi({ "/events*": { total: 0, items: [] } });
    renderAt(<Events />);
    await screen.findByText("No events match.");

    fireEvent.change(screen.getByLabelText("Event type"), { target: { value: "DEVICE_DISCOVERED" } });
    await waitFor(() => expect(lastQuery(api).get("event_type")).toBe("DEVICE_DISCOVERED"));

    fireEvent.change(screen.getByLabelText("From date"), { target: { value: "2026-01-02" } });
    fireEvent.change(screen.getByLabelText("To date"), { target: { value: "2026-01-03" } });
    await waitFor(() => expect(lastQuery(api).get("until")).toBeTruthy());
    expect(new Date(lastQuery(api).get("since")!).getTime()).toBe(new Date("2026-01-02T00:00:00").getTime());
    expect(new Date(lastQuery(api).get("until")!).getTime()).toBe(new Date("2026-01-03T23:59:59.999").getTime());

    fireEvent.change(screen.getByLabelText("Search events"), { target: { value: "nas" } });
    expect(lastQuery(api).get("q")).toBeNull(); // not yet: still debouncing
    await waitFor(() => expect(lastQuery(api).get("q")).toBe("nas"));
  });

  it("pages through results", async () => {
    const api = mockApi({ "/events*": { total: 120, items: [makeEvent()] } });
    renderAt(<Events />);
    await screen.findByText("120 events");
    const prev = screen.getByRole("button", { name: "Previous" }) as HTMLButtonElement;
    const next = screen.getByRole("button", { name: "Next" }) as HTMLButtonElement;
    expect(prev.disabled).toBe(true);
    fireEvent.click(next);
    await waitFor(() => expect(lastQuery(api).get("offset")).toBe("50"));
    fireEvent.click(next);
    await waitFor(() => expect(lastQuery(api).get("offset")).toBe("100"));
    expect(next.disabled).toBe(true); // 100 + 50 >= 120
    fireEvent.click(prev);
    await waitFor(() => expect(lastQuery(api).get("offset")).toBe("50"));
  });
});
