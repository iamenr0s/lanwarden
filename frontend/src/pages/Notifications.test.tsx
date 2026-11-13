import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { calls, fail, mockApi, renderAt } from "../test-utils";
import Notifications from "./Notifications";

beforeEach(() => vi.stubGlobal("scrollTo", vi.fn()));
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const email = {
  id: 1,
  name: "Ops mail",
  provider: "email",
  event_types: ["DEVICE_DISCOVERED", "DEVICE_ANOMALY"],
  enabled: true,
  config: { host: "smtp.example.com", port: 465, security: "ssl", username: "bot", from_addr: "a@x.io", to_addrs: ["b@x.io", "c@x.io"], verify_tls: false, password_set: true },
};
const hook = {
  id: 2,
  name: "Chat",
  provider: "webhook",
  event_types: ["SOMETHING_NEW"],
  enabled: false,
  config: { verify_tls: true, url_set: true, url_hint: "https://hooks…/abc", secret_set: false },
};
const deliveries = [
  { id: 1, time: "2026-01-01T00:00:00Z", rule_id: 1, rule_name: "Ops mail", provider: "email", events: 3, ok: true, error: null },
  { id: 2, time: "2026-01-01T00:00:00Z", rule_id: 2, rule_name: "Chat", provider: "webhook", events: 1, ok: false, error: "HTTP 500" },
  { id: 3, time: "2026-01-01T00:00:00Z", rule_id: 2, rule_name: "Chat", provider: "webhook", events: 0, ok: true, error: null },
];

const routes = (over: Record<string, unknown> = {}) => ({
  "/notifications/rules": [email, hook],
  "/notifications/deliveries": deliveries,
  ...over,
});
const type = (label: RegExp | string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });
const saveForm = () => fireEvent.submit(screen.getByRole("button", { name: "Save" }).closest("form")!);
const bodyOf = (api: ReturnType<typeof mockApi>, method: string) =>
  JSON.parse(String(api.mock.calls.find(([, i]) => i?.method === method)![1]?.body));
// rule names also appear in "Recent deliveries", so look inside the Rules card only
const ruleRow = (name: string) =>
  within(screen.getByRole("heading", { name: "Rules" }).closest("section")!).getByText(name, { selector: "span.font-medium" }).closest("li")!;

describe("Notifications: lists", () => {
  it("shows rules with their events, state and provider", async () => {
    mockApi(routes());
    renderAt(<Notifications />);
    const row = (await screen.findByText("Ops mail", { selector: "span.font-medium" })).closest("li")!;
    expect(within(row).getByText("email")).toBeTruthy();
    expect(within(row).getByText("Unknown device discovered · Network anomaly (possible spoofing or IP conflict)")).toBeTruthy();
    const chat = ruleRow("Chat");
    expect(within(chat).getByText("disabled")).toBeTruthy();
    expect(within(chat).getByText("webhook")).toBeTruthy();
    expect(within(chat).getByText("SOMETHING_NEW")).toBeTruthy(); // unknown event types are shown as-is
  });

  it("shows recent deliveries with their outcome", async () => {
    mockApi(routes());
    renderAt(<Notifications />);
    await screen.findByText(/· 3 events/);
    expect(screen.getByText(/· 1 event$/)).toBeTruthy();
    expect(screen.getByText(/· test$/)).toBeTruthy();
    expect(screen.getByText("HTTP 500")).toBeTruthy();
    expect(screen.getAllByRole("img", { name: "Sent" })).toHaveLength(2);
    expect(screen.getAllByRole("img", { name: "Failed" })).toHaveLength(1);
  });

  it("shows empty states and a load error", async () => {
    mockApi(routes({ "/notifications/rules": [], "/notifications/deliveries": [] }));
    const { unmount } = renderAt(<Notifications />);
    expect(await screen.findByText(/No rules yet/)).toBeTruthy();
    expect(screen.getByText("Nothing sent since the server started.")).toBeTruthy();
    unmount();
    mockApi(routes({ "/notifications/rules": fail(500, "rules unavailable") }));
    renderAt(<Notifications />);
    expect(await screen.findByText("rules unavailable")).toBeTruthy();
  });
});

describe("Notifications: creating a rule", () => {
  it("creates an email rule with parsed recipients", async () => {
    const api = mockApi(routes({ "POST /notifications/rules": {} }));
    renderAt(<Notifications />);
    await screen.findByText("Ops mail", { selector: "span.font-medium" });
    fireEvent.click(screen.getByRole("button", { name: "New rule" }));
    expect(screen.queryByRole("button", { name: "New rule" })).toBeNull();
    type(/^Name/, "Alerts");
    type(/^Host/, "smtp.example.com");
    type(/^From address/, "alerts@example.com");
    type(/^To/, "a@x.io; b@x.io  c@x.io");
    type(/^Password/, "pw");
    saveForm();
    await waitFor(() => expect(screen.queryByText("New rule", { selector: "h2" })).toBeNull());
    expect(bodyOf(api, "POST")).toEqual({
      name: "Alerts",
      provider: "email",
      enabled: true,
      event_types: ["DEVICE_DISCOVERED", "ALWAYS_CONNECTED_DEVICE_DOWN", "ALWAYS_CONNECTED_DEVICE_RECOVERED", "DEVICE_ANOMALY"],
      config: { host: "smtp.example.com", port: 587, security: "starttls", username: "", from_addr: "alerts@example.com", to_addrs: ["a@x.io", "b@x.io", "c@x.io"], verify_tls: true, password: "pw" },
    });
    await waitFor(() => expect(calls(api).filter((c) => c === "GET /notifications/rules")).toHaveLength(2)); // list reloaded
  });

  it("creates a webhook rule with an optional signing secret", async () => {
    const api = mockApi(routes({ "POST /notifications/rules": {} }));
    renderAt(<Notifications />);
    await screen.findByText("Ops mail", { selector: "span.font-medium" });
    fireEvent.click(screen.getByRole("button", { name: "New rule" }));
    type(/^Name/, "Hook");
    type(/^Type/, "webhook");
    expect(screen.queryByLabelText(/^Host/)).toBeNull();
    type(/^URL/, "https://example.com/hook");
    type(/^Signing secret/, "sig");
    fireEvent.click(screen.getByLabelText("Verify TLS certificate"));
    saveForm();
    await waitFor(() => expect(api.mock.calls.some(([, i]) => i?.method === "POST")).toBe(true));
    expect(bodyOf(api, "POST")).toMatchObject({ provider: "webhook", config: { verify_tls: false, url: "https://example.com/hook", secret: "sig" } });
  });

  it("toggles events, and cannot be saved with none selected", async () => {
    mockApi(routes());
    renderAt(<Notifications />);
    await screen.findByText("Ops mail", { selector: "span.font-medium" });
    fireEvent.click(screen.getByRole("button", { name: "New rule" }));
    const save = screen.getByRole("button", { name: "Save" }) as HTMLButtonElement;
    for (const label of ["Unknown device discovered", "Always-connected device offline", "Always-connected device recovered", "Network anomaly (possible spoofing or IP conflict)"])
      fireEvent.click(screen.getByLabelText(label));
    expect(save.disabled).toBe(true);
    fireEvent.click(screen.getByLabelText("Device connected"));
    expect(save.disabled).toBe(false);
  });

  it("shows a save error and Cancel closes the form", async () => {
    mockApi(routes({ "POST /notifications/rules": fail(422, "Invalid SMTP host") }));
    renderAt(<Notifications />);
    await screen.findByText("Ops mail", { selector: "span.font-medium" });
    fireEvent.click(screen.getByRole("button", { name: "New rule" }));
    saveForm();
    expect((await screen.findByRole("alert")).textContent).toBe("Invalid SMTP host");
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.getByRole("button", { name: "New rule" })).toBeTruthy();
  });
});

describe("Notifications: editing a rule", () => {
  it("pre-fills an email rule, locks the type and keeps the stored password when left empty", async () => {
    const api = mockApi(routes({ "PUT /notifications/rules/1": {} }));
    renderAt(<Notifications />);
    await screen.findByText("Ops mail", { selector: "span.font-medium" });
    fireEvent.click(within(ruleRow("Ops mail")).getByRole("button", { name: "Edit" }));
    expect(screen.getByLabelText(/^Name/)).toHaveProperty("value", "Ops mail");
    expect(screen.getByLabelText(/^Host/)).toHaveProperty("value", "smtp.example.com");
    expect(screen.getByLabelText(/^To/)).toHaveProperty("value", "b@x.io, c@x.io");
    expect((screen.getByLabelText(/^Type/) as HTMLSelectElement).disabled).toBe(true);
    expect(screen.getByText("A password is stored. Leave empty to keep it.")).toBeTruthy();
    expect(window.scrollTo).toHaveBeenCalled();
    saveForm();
    await waitFor(() => expect(api.mock.calls.some(([, i]) => i?.method === "PUT")).toBe(true));
    const body = bodyOf(api, "PUT");
    expect(body.name).toBe("Ops mail");
    expect(body.config).not.toHaveProperty("password");
    expect(body.config).toMatchObject({ port: 465, security: "ssl", verify_tls: false, to_addrs: ["b@x.io", "c@x.io"] });
  });

  it("does not require a URL when one is already stored for a webhook", async () => {
    const api = mockApi(routes({ "PUT /notifications/rules/2": {} }));
    renderAt(<Notifications />);
    await screen.findByText("Chat", { selector: "span.font-medium" });
    fireEvent.click(within(ruleRow("Chat")).getByRole("button", { name: "Edit" }));
    expect(screen.getByText(/Stored encrypted \(https:\/\/hooks…\/abc\)/)).toBeTruthy();
    expect((screen.getByLabelText(/^URL/) as HTMLInputElement).required).toBe(false);
    saveForm();
    await waitFor(() => expect(api.mock.calls.some(([, i]) => i?.method === "PUT")).toBe(true));
    expect(bodyOf(api, "PUT").config).toEqual({ verify_tls: true }); // neither URL nor secret is resent
  });
});

describe("Notifications: delete and test", () => {
  it("deletes a rule after confirmation", async () => {
    const api = mockApi(routes({ "DELETE /notifications/rules/1": undefined }));
    vi.stubGlobal("confirm", vi.fn(() => true));
    renderAt(<Notifications />);
    await screen.findByText("Ops mail", { selector: "span.font-medium" });
    fireEvent.click(within(ruleRow("Ops mail")).getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(calls(api)).toContain("DELETE /notifications/rules/1"));
    expect(window.confirm).toHaveBeenCalledWith("Delete rule “Ops mail”?");
  });

  it("keeps the rule when the confirmation is declined", async () => {
    const api = mockApi(routes());
    vi.stubGlobal("confirm", vi.fn(() => false));
    renderAt(<Notifications />);
    await screen.findByText("Ops mail", { selector: "span.font-medium" });
    fireEvent.click(within(ruleRow("Ops mail")).getByRole("button", { name: "Delete" }));
    expect(calls(api).some((c) => c.startsWith("DELETE"))).toBe(false);
  });

  it("sends a test and reports success, reloading deliveries", async () => {
    const api = mockApi(routes({ "POST /notifications/rules/1/test": { ok: true, error: null } }));
    renderAt(<Notifications />);
    await screen.findByText("Ops mail", { selector: "span.font-medium" });
    fireEvent.click(within(ruleRow("Ops mail")).getByRole("button", { name: "Send test" }));
    expect(await screen.findByText("Test notification sent.")).toBeTruthy();
    await waitFor(() => expect(calls(api).filter((c) => c === "GET /notifications/deliveries")).toHaveLength(2));
  });

  it("reports a failed test", async () => {
    mockApi(routes({ "POST /notifications/rules/1/test": { ok: false, error: "smtp down" } }));
    renderAt(<Notifications />);
    await screen.findByText("Ops mail", { selector: "span.font-medium" });
    fireEvent.click(within(ruleRow("Ops mail")).getByRole("button", { name: "Send test" }));
    expect(await screen.findByText("Test failed: smtp down")).toBeTruthy();
  });
});
