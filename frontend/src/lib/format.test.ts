import { afterEach, describe, expect, it, vi } from "vitest";
import { duration, eventLabel, fullTime, timeAgo } from "./format";

afterEach(() => vi.useRealTimers());

describe("timeAgo", () => {
  it("handles missing values", () => {
    expect(timeAgo(null)).toBe("never");
    expect(timeAgo(undefined)).toBe("never");
  });

  it("picks the largest unit", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-10T12:00:00Z"));
    expect(timeAgo("2026-01-10T11:59:30Z")).toBe("just now");
    expect(timeAgo("2026-01-10T11:55:00Z")).toBe("5m ago");
    expect(timeAgo("2026-01-10T09:00:00Z")).toBe("3h ago");
    expect(timeAgo("2026-01-07T12:00:00Z")).toBe("3d ago");
  });

  it("never reports a negative age for a timestamp in the future", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-10T12:00:00Z"));
    expect(timeAgo("2026-01-10T12:05:00Z")).toBe("just now");
  });
});

describe("fullTime", () => {
  it("shows a dash for missing values and a locale string otherwise", () => {
    expect(fullTime(null)).toBe("—");
    expect(fullTime("2026-01-10T12:00:00Z")).toBe(new Date("2026-01-10T12:00:00Z").toLocaleString());
  });
});

describe("duration", () => {
  it.each([
    [null, "—"],
    [undefined, "—"],
    [45, "45s"],
    [125, "2m"],
    [3 * 3600 + 20 * 60, "3h 20m"],
    [2 * 86400 + 5 * 3600, "2d 5h"],
  ])("%s -> %s", (input, expected) => {
    expect(duration(input)).toBe(expected);
  });
});

describe("eventLabel", () => {
  it("title-cases SNAKE_CASE event types", () => {
    expect(eventLabel("DEVICE_CAME_ONLINE")).toBe("Device Came Online");
    expect(eventLabel("new_device")).toBe("New Device");
  });
});
