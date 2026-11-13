import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { Device } from "../types";
import { StatusBadge, StatusDot } from "./StatusBadge";

type Fields = Pick<Device, "is_online" | "always_connected" | "status">;
const dev = (o: Partial<Fields>): Fields => ({ is_online: false, always_connected: false, status: "KNOWN" as Device["status"], ...o });

const cases: [string, Fields, string][] = [
  ["online", dev({ is_online: true }), "Online"],
  ["offline", dev({}), "Offline"],
  ["down: always-connected and offline", dev({ always_connected: true }), "Down"],
  ["new device", dev({ status: "NEW" as Device["status"] }), "New"],
  ["unknown", dev({ status: "UNKNOWN" as Device["status"] }), "Unknown"],
];

describe("StatusBadge", () => {
  it.each(cases)("%s", (_name, device, text) => {
    render(<StatusBadge device={device} />);
    expect(screen.getByText(text)).toBeTruthy();
  });

  it("an unknown device is never reported as down", () => {
    render(<StatusBadge device={dev({ always_connected: true, status: "UNKNOWN" as Device["status"] })} />);
    expect(screen.queryByText("Down")).toBeNull();
  });
});

describe("StatusDot", () => {
  it.each([
    [dev({ is_online: true }), "Online"],
    [dev({}), "Offline"],
    [dev({ always_connected: true }), "Down"],
  ])("labels the dot for screen readers", (device, label) => {
    render(<StatusDot device={device} />);
    expect(screen.getByRole("img").getAttribute("aria-label")).toBe(label);
  });
});
