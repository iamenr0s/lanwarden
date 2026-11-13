import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { Presence } from "../types";
import PresenceTimeline from "./PresenceTimeline";

const base: Presence = {
  range: "24h",
  start: "2026-01-10T00:00:00Z",
  end: "2026-01-11T00:00:00Z",
  segments: [{ start: "2026-01-10T06:00:00Z", end: "2026-01-10T12:00:00Z" }],
  session_count: 1,
  online_seconds: 6 * 3600,
  tracked_seconds: 24 * 3600,
  online_percent: 25,
};

describe("PresenceTimeline", () => {
  it("summarises the data for screen readers", () => {
    render(<PresenceTimeline data={base} />);
    expect(screen.getByRole("img").getAttribute("aria-label")).toBe("Online 6h 0m (25% of tracked time) in 1 interval");
  });

  it("pluralises intervals and omits the percentage when unknown", () => {
    render(<PresenceTimeline data={{ ...base, segments: [], online_percent: null, online_seconds: 0 }} />);
    expect(screen.getByRole("img").getAttribute("aria-label")).toBe("Online 0s in 0 intervals");
  });

  it("positions a segment as a share of the range", () => {
    const { container } = render(<PresenceTimeline data={base} />);
    const bar = container.querySelector<HTMLElement>("div[title]")!;
    expect(bar.style.left).toBe("25%");
    expect(bar.style.width).toBe("25%");
  });

  it("keeps a very short session visible", () => {
    const data = { ...base, segments: [{ start: "2026-01-10T06:00:00Z", end: "2026-01-10T06:00:10Z" }] };
    const { container } = render(<PresenceTimeline data={data} />);
    expect(container.querySelector<HTMLElement>("div[title]")!.style.width).toBe("0.4%");
  });

  it("draws five axis ticks", () => {
    const { container } = render(<PresenceTimeline data={base} />);
    expect(container.querySelectorAll("[aria-hidden] span")).toHaveLength(5);
  });
});
