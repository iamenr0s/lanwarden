import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { authState, calls, fail, mockApi, renderAt } from "../test-utils";
import MfaCard from "./MfaCard";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const off = authState({ mfa_enabled: false });
const on = authState({ mfa_enabled: true });
const type = (label: RegExp | string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });
const body = (api: ReturnType<typeof mockApi>, i = 0) => JSON.parse(String(api.mock.calls[i][1]?.body));

const routes = {
  "POST /auth/mfa/setup": { secret: "JBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/LanWarden:admin?secret=JBSWY3DPEHPK3PXP" },
  "POST /auth/mfa/enable": { recovery_codes: ["aaaa-1111", "bbbb-2222"] },
  "POST /auth/mfa/recovery-codes": { recovery_codes: ["cccc-3333"] },
  "POST /auth/mfa/disable": undefined,
};

describe("MfaCard: turning it on", () => {
  it("walks through password, QR code and code to the recovery codes", async () => {
    const api = mockApi(routes);
    const refresh = vi.fn().mockResolvedValue(undefined);
    renderAt(<MfaCard />, { auth: off, refresh });

    type(/Confirm your password/, "pw");
    fireEvent.click(screen.getByRole("button", { name: "Set up" }));
    expect(await screen.findByRole("img", { name: /QR code/ })).toBeTruthy();
    expect(screen.getByText("JBSW Y3DP EHPK 3PXP")).toBeTruthy(); // key shown in groups for manual entry
    expect(body(api)).toEqual({ password: "pw" });

    type(/Code from the app/, "123456");
    fireEvent.click(screen.getByRole("button", { name: "Turn on" }));
    expect(await screen.findByText("aaaa-1111")).toBeTruthy();
    expect(screen.getByText("bbbb-2222")).toBeTruthy();
    expect(body(api, 1)).toEqual({ code: "123456" });
    expect(screen.getByText(/shown only once/)).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "I have saved them" }));
    expect(refresh).toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Set up" })).toBeTruthy();
    expect(screen.queryByText("aaaa-1111")).toBeNull(); // the codes are gone for good
  });

  it("shows a wrong-password error and stays on the first step", async () => {
    mockApi({ "POST /auth/mfa/setup": fail(401, "Wrong password") });
    renderAt(<MfaCard />, { auth: off });
    type(/Confirm your password/, "bad");
    fireEvent.click(screen.getByRole("button", { name: "Set up" }));
    expect((await screen.findByRole("alert")).textContent).toBe("Wrong password");
    expect(screen.getByRole("button", { name: "Set up" })).toBeTruthy();
  });

  it("a wrong code keeps the user on the QR step, and Cancel backs out", async () => {
    mockApi({ ...routes, "POST /auth/mfa/enable": fail(400, "Invalid code") });
    renderAt(<MfaCard />, { auth: off });
    type(/Confirm your password/, "pw");
    fireEvent.click(screen.getByRole("button", { name: "Set up" }));
    await screen.findByRole("img", { name: /QR code/ });
    type(/Code from the app/, "000000");
    fireEvent.click(screen.getByRole("button", { name: "Turn on" }));
    expect((await screen.findByRole("alert")).textContent).toBe("Invalid code");
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.getByRole("button", { name: "Set up" })).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("explains why when the server forces enrolment", () => {
    renderAt(<MfaCard forced />, { auth: off });
    expect(screen.getByText(/requires two-step verification/)).toBeTruthy();
  });

  it("copies and downloads the recovery codes", async () => {
    mockApi(routes);
    const writeText = vi.fn();
    vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText } });
    const createObjectURL = vi.fn(() => "blob:codes");
    const revokeObjectURL = vi.fn();
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL, revokeObjectURL }));
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    renderAt(<MfaCard />, { auth: off });
    type(/Confirm your password/, "pw");
    fireEvent.click(screen.getByRole("button", { name: "Set up" }));
    await screen.findByRole("img", { name: /QR code/ });
    type(/Code from the app/, "123456");
    fireEvent.click(screen.getByRole("button", { name: "Turn on" }));
    await screen.findByText("aaaa-1111");

    fireEvent.click(screen.getByRole("button", { name: "Copy" }));
    expect(writeText).toHaveBeenCalledWith("aaaa-1111\nbbbb-2222");
    fireEvent.click(screen.getByRole("button", { name: "Download" }));
    expect(createObjectURL).toHaveBeenCalled();
    expect(click).toHaveBeenCalled();
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:codes");
  });
});

describe("MfaCard: already on", () => {
  beforeEach(() => mockApi(routes));

  it("says it is on and offers the two actions", () => {
    renderAt(<MfaCard />, { auth: on });
    expect(screen.getByText("Two-step verification is on.")).toBeTruthy();
    expect(screen.getByRole("button", { name: "New recovery codes" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Turn off" })).toBeTruthy();
  });

  it("replaces recovery codes after confirming with password and code", async () => {
    const api = mockApi(routes);
    const refresh = vi.fn().mockResolvedValue(undefined);
    renderAt(<MfaCard />, { auth: on, refresh });
    fireEvent.click(screen.getByRole("button", { name: "New recovery codes" }));
    type("Password", "pw");
    type("Code", "123456");
    fireEvent.click(screen.getByRole("button", { name: "Replace codes" }));
    expect(await screen.findByText("cccc-3333")).toBeTruthy();
    expect(calls(api)).toEqual(["POST /auth/mfa/recovery-codes"]);
    expect(body(api)).toEqual({ password: "pw", code: "123456" });
    expect(refresh).toHaveBeenCalled();
  });

  it("turns it off after confirming, and refreshes the session", async () => {
    const api = mockApi(routes);
    const refresh = vi.fn().mockResolvedValue(undefined);
    renderAt(<MfaCard />, { auth: on, refresh });
    fireEvent.click(screen.getByRole("button", { name: "Turn off" }));
    type("Password", "pw");
    type("Code", "123456");
    fireEvent.click(screen.getAllByRole("button", { name: "Turn off" }).at(-1)!);
    await waitFor(() => expect(refresh).toHaveBeenCalled());
    expect(calls(api)).toEqual(["POST /auth/mfa/disable"]);
    expect(body(api)).toEqual({ password: "pw", code: "123456" });
  });

  it("shows a failed confirmation and lets the user cancel", async () => {
    mockApi({ ...routes, "POST /auth/mfa/disable": fail(401, "Invalid code") });
    renderAt(<MfaCard />, { auth: on });
    fireEvent.click(screen.getByRole("button", { name: "Turn off" }));
    type("Password", "pw");
    type("Code", "1");
    fireEvent.click(screen.getAllByRole("button", { name: "Turn off" }).at(-1)!);
    expect((await screen.findByRole("alert")).textContent).toBe("Invalid code");
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.getByRole("button", { name: "New recovery codes" })).toBeTruthy();
  });
});
