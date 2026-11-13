import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { calls, fail, mockApi } from "../test-utils";
import ScanCard from "./ScanCard";

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

const run = (over = {}) => ({
  id: 1,
  trigger: "manual",
  started_at: "2026-01-01T00:00:00Z",
  finished_at: "2026-01-01T00:00:05Z",
  providers: [],
  summary: { observed: 12, discovered: 2 },
  error: null,
  ...over,
});

describe("ScanCard", () => {
  it("shows when no scan has run", async () => {
    mockApi({ "/scanner/runs": { running: false, runs: [] } });
    render(<ScanCard onFinished={vi.fn()} />);
    expect(await screen.findByText("No scan has run yet.")).toBeTruthy();
  });

  it("summarises the last scan", async () => {
    mockApi({ "/scanner/runs": { running: false, runs: [run()] } });
    render(<ScanCard onFinished={vi.fn()} />);
    expect(await screen.findByText(/12 seen, 2 new/)).toBeTruthy();
  });

  it("reports a failed scan and provider problems", async () => {
    mockApi({
      "/scanner/runs": {
        running: false,
        runs: [run({ error: "scan crashed", providers: [{ name: "arp-scan", observations: 0, error: "permission denied" }, { name: "neighbor", observations: 3, error: null }] })],
      },
    });
    render(<ScanCard onFinished={vi.fn()} />);
    expect(await screen.findByText("scan crashed")).toBeTruthy();
    expect(screen.getByText("arp-scan:")).toBeTruthy();
    expect(screen.queryByText("neighbor:")).toBeNull();
  });

  it("surfaces an error loading the runs", async () => {
    mockApi({ "/scanner/runs": fail(500, "database locked") });
    render(<ScanCard onFinished={vi.fn()} />);
    expect(await screen.findByText("database locked")).toBeTruthy();
  });

  it("starts a scan, polls while it runs, then reports it finished", async () => {
    let running = false;
    let polls = 0;
    const api = mockApi({
      "POST /scanner/run": () => {
        running = true;
        return {};
      },
      "/scanner/runs": () => {
        if (running && ++polls >= 2) running = false; // the scan ends on the second poll
        return { running, runs: [run()] };
      },
    });
    const onFinished = vi.fn();
    render(<ScanCard onFinished={onFinished} />);
    await screen.findByText(/12 seen/);
    vi.useFakeTimers({ shouldAdvanceTime: true });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Scan now" }));
    });
    expect(await screen.findByText("Scanning…")).toBeTruthy();
    expect((screen.getByRole("button", { name: "Scan now" }) as HTMLButtonElement).disabled).toBe(true);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2100);
    });
    await waitFor(() => expect(onFinished).toHaveBeenCalledTimes(1));
    expect(calls(api)).toContain("POST /scanner/run");
  });

  it("shows why a scan could not start", async () => {
    mockApi({ "/scanner/runs": { running: false, runs: [] }, "POST /scanner/run": fail(409, "A scan is already running") });
    render(<ScanCard onFinished={vi.fn()} />);
    await screen.findByText("No scan has run yet.");
    fireEvent.click(screen.getByRole("button", { name: "Scan now" }));
    expect(await screen.findByText("A scan is already running")).toBeTruthy();
  });
});
