import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { calls, fail, mockApi, renderAt } from "../test-utils";
import Settings from "./Settings";

afterEach(() => vi.unstubAllGlobals());

const scanner = {
  interfaces: ["eth0"],
  networks: ["192.168.1.0/24"],
  scan_interval_seconds: 300,
  offline_threshold_seconds: 600,
  always_connected_offline_threshold_seconds: 600,
  new_device_window_hours: 24,
  observation_retention_days: 30,
  arp_scan_enabled: true,
  neighbor_discovery_enabled: true,
  adguard_discovery_enabled: false,
  service_discovery_enabled: true,
};
const response = (over = {}) => ({ settings: { scanner }, detected_networks: [], detection_ambiguous: false, ...over });
const type = (label: RegExp | string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });
const putBody = (api: ReturnType<typeof mockApi>) => JSON.parse(String(api.mock.calls.find(([, i]) => i?.method === "PUT")![1]?.body));
const saveForm = () => fireEvent.submit(screen.getByRole("button", { name: "Save" }).closest("form")!);

describe("Settings: scanner", () => {
  it("loads the current values into the form", async () => {
    mockApi({ "/settings": response() });
    renderAt(<Settings />);
    expect(await screen.findByLabelText(/Interfaces/)).toHaveProperty("value", "eth0");
    expect(screen.getByLabelText(/CIDR networks/)).toHaveProperty("value", "192.168.1.0/24");
    expect(screen.getByLabelText(/Scan interval/)).toHaveProperty("value", "300");
    expect((screen.getByLabelText("arp-scan") as HTMLInputElement).checked).toBe(true);
    expect((screen.getByLabelText("AdGuard Home") as HTMLInputElement).checked).toBe(false);
  });

  it("saves edited values, parsing the comma/space separated lists", async () => {
    const api = mockApi({ "/settings": response(), "PUT /settings": () => response() });
    renderAt(<Settings />);
    await screen.findByLabelText(/Interfaces/);
    type(/Interfaces/, "eth0, wlan0  eth1");
    type(/CIDR networks/, "10.0.0.0/24,192.168.1.0/24");
    type(/Scan interval/, "120");
    fireEvent.click(screen.getByLabelText("AdGuard Home"));
    fireEvent.click(screen.getByLabelText("arp-scan"));
    saveForm();
    expect(await screen.findByRole("status")).toHaveProperty("textContent", "Saved");
    expect(putBody(api)).toEqual({
      scanner: {
        ...scanner,
        interfaces: ["eth0", "wlan0", "eth1"],
        networks: ["10.0.0.0/24", "192.168.1.0/24"],
        scan_interval_seconds: 120,
        adguard_discovery_enabled: true,
        arp_scan_enabled: false,
      },
    });
  });

  it("adds detected networks without duplicating them", async () => {
    mockApi({ "/settings": response({ detected_networks: [{ interface: "eth1", cidr: "10.0.0.0/24" }], detection_ambiguous: true }) });
    renderAt(<Settings />);
    expect(await screen.findByText(/Several networks were detected/)).toBeTruthy();
    const add = screen.getByRole("button", { name: /eth1 · 10\.0\.0\.0\/24/ });
    fireEvent.click(add);
    fireEvent.click(add);
    expect(screen.getByLabelText(/Interfaces/)).toHaveProperty("value", "eth0, eth1");
    expect(screen.getByLabelText(/CIDR networks/)).toHaveProperty("value", "192.168.1.0/24, 10.0.0.0/24");
  });

  it("says 'Detected network' when only one was found", async () => {
    mockApi({ "/settings": response({ detected_networks: [{ interface: "eth0", cidr: "192.168.1.0/24" }] }) });
    renderAt(<Settings />);
    expect(await screen.findByText("Detected network:")).toBeTruthy();
  });

  it("shows why saving failed", async () => {
    mockApi({ "/settings": response(), "PUT /settings": fail(422, "Network too large") });
    renderAt(<Settings />);
    await screen.findByLabelText(/Interfaces/);
    saveForm();
    expect((await screen.findByRole("alert")).textContent).toBe("Network too large");
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("keeps the account cards usable while settings are loading or have failed", async () => {
    mockApi({ "/settings": fail(500, "settings unavailable") });
    renderAt(<Settings />);
    expect(screen.getByText("Loading…")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Change password" })).toBeTruthy();
    expect(await screen.findByText("settings unavailable")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Change password" })).toBeTruthy();
    expect(screen.getByText("Two-step verification")).toBeTruthy();
  });
});

describe("Settings: change password", () => {
  const form = () => screen.getByRole("button", { name: "Change password" }).closest("form")!;
  const fill = (cur: string, next: string, again: string) => {
    type(/^Current password/, cur);
    type(/^New password/, next);
    type(/^Repeat new password/, again);
  };

  it("rejects a mismatch without calling the API", async () => {
    const api = mockApi({ "/settings": response() });
    renderAt(<Settings />);
    fill("old", "new-password-1", "new-password-2");
    fireEvent.submit(form());
    expect((await screen.findByText("The new passwords do not match.")).getAttribute("role") ?? "alert").toBe("alert");
    expect(calls(api).some((c) => c.includes("/auth/password"))).toBe(false);
  });

  it("changes the password and clears the fields", async () => {
    const api = mockApi({ "/settings": response(), "POST /auth/password": {} });
    renderAt(<Settings />);
    fill("old", "new-password-1", "new-password-1");
    fireEvent.submit(form());
    expect((await screen.findByText(/Password changed/)).getAttribute("role")).toBe("status");
    const call = api.mock.calls.find(([u]) => String(u).endsWith("/auth/password"))!;
    expect(JSON.parse(String(call[1]?.body))).toEqual({ current_password: "old", new_password: "new-password-1" });
    expect(screen.getByLabelText(/^Current password/)).toHaveProperty("value", "");
  });

  it("shows the server's reason when the current password is wrong", async () => {
    mockApi({ "/settings": response(), "POST /auth/password": fail(401, "Current password is incorrect") });
    renderAt(<Settings />);
    fill("bad", "new-password-1", "new-password-1");
    fireEvent.submit(form());
    expect(await screen.findByText("Current password is incorrect")).toBeTruthy();
    await waitFor(() => expect((screen.getByRole("button", { name: "Change password" }) as HTMLButtonElement).disabled).toBe(false));
  });
});
