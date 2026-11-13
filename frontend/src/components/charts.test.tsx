import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { BarList, COLORS, Donut, LineChart } from "./charts";

describe("Donut", () => {
  const segments = [
    { label: "Online", value: 6, color: COLORS.online },
    { label: "Offline", value: 3, color: COLORS.offline },
    { label: "Not seen yet", value: 0, color: "#94a3b8" },
  ];

  it("summarises the parts for screen readers and lists a legend", () => {
    render(<Donut segments={segments} centerLabel="devices" />);
    expect(screen.getByRole("img").getAttribute("aria-label")).toBe("6 online, 3 offline, 0 not seen yet");
    expect(screen.getByText("Online").nextSibling?.textContent).toBe("6");
  });

  it("draws one arc per non-empty segment", () => {
    const { container } = render(<Donut segments={segments} centerLabel="devices" />);
    // the track plus two arcs; the zero-value segment is skipped
    expect(container.querySelectorAll("circle")).toHaveLength(3);
  });

  it("says so when there is nothing to show", () => {
    const { container } = render(<Donut segments={segments.map((s) => ({ ...s, value: 0 }))} centerLabel="devices" />);
    expect(screen.getByRole("img").getAttribute("aria-label")).toBe("No devices");
    expect(container.querySelectorAll("circle")).toHaveLength(1);
  });
});

describe("BarList", () => {
  it("scales bars against the largest value and prints the numbers", () => {
    const { container } = render(
      <BarList
        items={[
          { label: "camera", value: 4 },
          { label: "Unclassified", value: 1 },
        ]}
      />,
    );
    const bars = [...container.querySelectorAll<HTMLElement>("li > div:last-child > div")];
    expect(bars.map((b) => b.style.width)).toEqual(["100%", "25%"]);
    expect(screen.getByText("4")).toBeTruthy();
  });

  it("shows an empty state", () => {
    render(<BarList items={[]} />);
    expect(screen.getByText("No devices yet.")).toBeTruthy();
  });
});

describe("LineChart", () => {
  const points = [
    { time: "2026-01-10T00:00:00Z", online: 2, total: 5 },
    { time: "2026-01-10T12:00:00Z", online: 4, total: 5 },
    { time: "2026-01-11T00:00:00Z", online: 3, total: 6 },
  ];

  it("labels itself with the latest values and range", () => {
    render(<LineChart points={points} range="7d" />);
    expect(screen.getByRole("img").getAttribute("aria-label")).toBe("Devices online over the last 7 days: 3 online now, 6 known");
  });

  it.each([
    ["24h", "24 hours"],
    ["7d", "7 days"],
    ["30d", "30 days"],
  ])("names the %s range", (range, text) => {
    render(<LineChart points={points} range={range} />);
    expect(screen.getByRole("img").getAttribute("aria-label")).toContain(text);
  });

  it("has a hover title per point", () => {
    const { container } = render(<LineChart points={points} range="24h" />);
    expect(container.querySelectorAll("circle title")).toHaveLength(3);
  });

  it("copes with no data", () => {
    render(<LineChart points={[]} range="24h" />);
    expect(screen.getByRole("img").getAttribute("aria-label")).toContain("0 online now, 0 known");
  });

  it("uses a coarser y-axis step for larger fleets", () => {
    const big = points.map((p) => ({ ...p, online: p.online * 60, total: p.total * 60 }));
    const { container } = render(<LineChart points={big} range="7d" />);
    const ticks = [...container.querySelectorAll("text")].map((t) => t.textContent).filter((t) => /^\d+$/.test(t ?? ""));
    expect(ticks.length).toBeLessThanOrEqual(7);
  });
});
