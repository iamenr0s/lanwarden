import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { calls, fail, mockApi, renderAt } from "../test-utils";
import AdGuard from "./AdGuard";

afterEach(() => vi.unstubAllGlobals());

const config = { configured: true, url: "http://192.168.1.2:3000", username: "admin", verify_tls: true, timeout_seconds: 10, password_set: true };
const server = { version: "v0.107.52", running: true, protection_enabled: true, dns_addresses: ["192.168.1.2"], dns_port: 53, http_port: 3000, language: "en" };
const reachable = { configured: true, reachable: true, server, error: null };

const routes = (over: Record<string, unknown> = {}) => ({
  "/integrations/adguard": config,
  "/integrations/adguard/status": reachable,
  ...over,
});
const type = (label: RegExp | string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });
const bodyOf = (api: ReturnType<typeof mockApi>, method: string) =>
  JSON.parse(String(api.mock.calls.find(([, i]) => i?.method === method)![1]?.body));
const saveForm = () => fireEvent.submit(screen.getByRole("button", { name: "Save" }).closest("form")!);
// The form is filled from the saved config in an effect, which can land just after "Reachable" appears.
const ready = async () => {
  await screen.findByText("Reachable");
  await waitFor(() => expect(screen.getByLabelText(/^URL/)).toHaveProperty("value", config.url));
};

describe("AdGuard: status", () => {
  it("shows the server facts when reachable", async () => {
    mockApi(routes());
    renderAt(<AdGuard />);
    expect(await screen.findByText("Reachable")).toBeTruthy();
    expect(screen.getByText("v0.107.52")).toBeTruthy();
    expect(screen.getByText("192.168.1.2:53")).toBeTruthy();
    expect(screen.getByText("enabled")).toBeTruthy();
    expect(screen.getByText("yes")).toBeTruthy();
  });

  it("shows dashes for facts the server did not report", async () => {
    mockApi(routes({ "/integrations/adguard/status": { ...reachable, server: { ...server, dns_addresses: [], dns_port: null, http_port: null, protection_enabled: null, running: null } } }));
    renderAt(<AdGuard />);
    await screen.findByText("Reachable");
    expect(screen.getAllByText("—")).toHaveLength(5 - 1); // every fact except the version
  });

  it("explains when it is not configured", async () => {
    mockApi(routes({ "/integrations/adguard/status": { configured: false, reachable: false, server: null, error: null } }));
    renderAt(<AdGuard />);
    expect(await screen.findByText(/Not configured yet/)).toBeTruthy();
  });

  it("reports an unreachable server, with a fallback message", async () => {
    mockApi(routes({ "/integrations/adguard/status": { configured: true, reachable: false, server: null, error: { kind: "timeout", message: "timed out" } } }));
    const { unmount } = renderAt(<AdGuard />);
    expect(await screen.findByText("Unreachable: timed out")).toBeTruthy();
    unmount();
    mockApi(routes({ "/integrations/adguard/status": { configured: true, reachable: false, server: null, error: null } }));
    renderAt(<AdGuard />);
    expect(await screen.findByText("Unreachable: unknown error")).toBeTruthy();
  });

  it("shows an error if the configuration cannot be loaded", async () => {
    mockApi(routes({ "/integrations/adguard": fail(500, "config unavailable") }));
    renderAt(<AdGuard />);
    expect((await screen.findByRole("alert")).textContent).toBe("config unavailable");
  });
});

describe("AdGuard: settings form", () => {
  it("pre-fills from the saved configuration and never shows the password", async () => {
    mockApi(routes());
    renderAt(<AdGuard />);
    await ready();
    expect(screen.getByLabelText(/^URL/)).toHaveProperty("value", "http://192.168.1.2:3000");
    expect(screen.getByLabelText(/^Username/)).toHaveProperty("value", "admin");
    expect(screen.getByLabelText(/^Password/)).toHaveProperty("value", "");
    expect(screen.getByText("A password is stored. Leave empty to keep it.")).toBeTruthy();
    expect((screen.getByLabelText("Verify TLS certificate") as HTMLInputElement).checked).toBe(true);
  });

  it("saves without a password when the field is empty, then reloads", async () => {
    const api = mockApi(routes({ "PUT /integrations/adguard": {} }));
    renderAt(<AdGuard />);
    await ready();
    type(/^URL/, "http://adguard.lan:3000");
    type(/Timeout/, "20");
    fireEvent.click(screen.getByLabelText("Verify TLS certificate"));
    saveForm();
    expect((await screen.findByRole("status")).textContent).toBe("Saved");
    expect(bodyOf(api, "PUT")).toEqual({ url: "http://adguard.lan:3000", username: "admin", verify_tls: false, timeout_seconds: 20 });
    await waitFor(() => expect(calls(api).filter((c) => c === "GET /integrations/adguard")).toHaveLength(2));
  });

  it("sends a new password once and clears the field", async () => {
    const api = mockApi(routes({ "PUT /integrations/adguard": {} }));
    renderAt(<AdGuard />);
    await ready();
    type(/^Password/, "s3cret");
    saveForm();
    await screen.findByRole("status");
    expect(bodyOf(api, "PUT")).toHaveProperty("password", "s3cret");
    expect(screen.getByLabelText(/^Password/)).toHaveProperty("value", "");
  });

  it("shows why saving failed", async () => {
    mockApi(routes({ "PUT /integrations/adguard": fail(422, "Invalid URL") }));
    renderAt(<AdGuard />);
    await ready();
    saveForm();
    expect((await screen.findByRole("alert")).textContent).toBe("Invalid URL");
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("will not save or test without a URL", async () => {
    mockApi(routes({ "/integrations/adguard": { ...config, url: null, configured: false, password_set: false } }));
    renderAt(<AdGuard />);
    await screen.findByText("Not configured yet", { exact: false }).catch(() => null);
    await waitFor(() => expect(screen.getByLabelText(/^URL/)).toBeTruthy());
    expect((screen.getByRole("button", { name: "Save" }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "Test connection" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.queryByText(/A password is stored/)).toBeNull();
  });
});

describe("AdGuard: test connection", () => {
  const test = async () => {
    await screen.findByText("Reachable");
    // the button stays disabled until the saved URL has been copied into the form
    await waitFor(() => expect(screen.getByLabelText(/^URL/)).toHaveProperty("value", config.url));
    fireEvent.click(screen.getByRole("button", { name: "Test connection" }));
  };

  it("reports success with DHCP details", async () => {
    const api = mockApi(routes({ "POST /integrations/adguard/test": { ok: true, error: null, server, dhcp_enabled: true, dhcp_leases: 5, configured_clients: 3 } }));
    renderAt(<AdGuard />);
    await test();
    expect(await screen.findByText("Connection successful")).toBeTruthy();
    expect(screen.getByText(/DHCP enabled, 5 leases · 3 configured clients/)).toBeTruthy();
    expect(bodyOf(api, "POST")).toMatchObject({ url: "http://192.168.1.2:3000", username: "admin" });
  });

  it("says when DHCP info is unavailable", async () => {
    mockApi(routes({ "POST /integrations/adguard/test": { ok: true, error: null, server, dhcp_enabled: null, dhcp_leases: null, configured_clients: null } }));
    renderAt(<AdGuard />);
    await test();
    expect(await screen.findByText("DHCP info unavailable")).toBeTruthy();
  });

  it("shows the failure with advice for its kind", async () => {
    mockApi(routes({ "POST /integrations/adguard/test": { ok: false, error: { kind: "auth", message: "401 Unauthorized" }, server: null, dhcp_enabled: null, dhcp_leases: null, configured_clients: null } }));
    renderAt(<AdGuard />);
    await test();
    const card = (await screen.findByText("401 Unauthorized")).closest("section")!;
    expect(within(card).getByText("Check the username and password.")).toBeTruthy();
  });

  it("falls back to a generic failure message, with no advice for unknown kinds", async () => {
    mockApi(routes({ "POST /integrations/adguard/test": { ok: false, error: null, server: null, dhcp_enabled: null, dhcp_leases: null, configured_clients: null } }));
    renderAt(<AdGuard />);
    await test();
    expect(await screen.findByText("Connection failed")).toBeTruthy();
  });

  it("shows a request error", async () => {
    mockApi(routes({ "POST /integrations/adguard/test": fail(500, "backend exploded") }));
    renderAt(<AdGuard />);
    await test();
    expect((await screen.findByRole("alert")).textContent).toBe("backend exploded");
  });
});
