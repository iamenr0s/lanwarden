import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { calls, fail, mockApi } from "../test-utils";
import Login from "./Login";

afterEach(() => vi.unstubAllGlobals());

const props = { setupRequired: false, tokenRequired: false, insecure: false };
const type = (label: RegExp, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });
const submit = (c: HTMLElement) => fireEvent.submit(c.querySelector("form")!);

describe("Login", () => {
  it("signs in with a username and password", async () => {
    const api = mockApi({ "POST /auth/login": { mfa_required: false } });
    const onDone = vi.fn().mockResolvedValue(undefined);
    const { container } = render(<Login {...props} onDone={onDone} />);
    type(/Username/, "admin");
    type(/^Password/, "hunter2");
    submit(container);
    await waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(JSON.parse(String(api.mock.calls[0][1]?.body))).toEqual({ username: "admin", password: "hunter2" });
  });

  it("shows the server's error and lets the user retry", async () => {
    mockApi({ "POST /auth/login": fail(401, "Invalid username or password") });
    const { container } = render(<Login {...props} onDone={vi.fn()} />);
    type(/Username/, "admin");
    type(/^Password/, "nope");
    submit(container);
    expect((await screen.findByRole("alert")).textContent).toBe("Invalid username or password");
    expect((screen.getByRole("button", { name: "Sign in" }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("first-run setup creates the account and sends the setup token when required", async () => {
    const api = mockApi({ "POST /auth/setup": { mfa_required: false } });
    const onDone = vi.fn().mockResolvedValue(undefined);
    const { container } = render(<Login setupRequired tokenRequired insecure={false} onDone={onDone} />);
    expect(screen.getByText("Create the administrator account to get started.")).toBeTruthy();
    type(/Setup token/, "tok");
    type(/Username/, "admin");
    type(/^Password/, "correct horse battery");
    submit(container);
    await waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(JSON.parse(String(api.mock.calls[0][1]?.body))).toEqual({ username: "admin", password: "correct horse battery", setup_token: "tok" });
  });

  it("setup without a token requirement omits the token", async () => {
    const api = mockApi({ "POST /auth/setup": { mfa_required: false } });
    const { container } = render(<Login setupRequired tokenRequired={false} insecure={false} onDone={vi.fn().mockResolvedValue(undefined)} />);
    expect(screen.queryByLabelText(/Setup token/)).toBeNull();
    type(/Username/, "admin");
    type(/^Password/, "correct horse battery");
    submit(container);
    await waitFor(() => expect(api).toHaveBeenCalled());
    expect(JSON.parse(String(api.mock.calls[0][1]?.body))).not.toHaveProperty("setup_token");
  });

  it("asks for an MFA code after the password, then completes sign-in", async () => {
    const api = mockApi({
      "POST /auth/login": { mfa_required: true, mfa_token: "step2" },
      "POST /auth/login/mfa": {},
    });
    const onDone = vi.fn().mockResolvedValue(undefined);
    const { container } = render(<Login {...props} onDone={onDone} />);
    type(/Username/, "admin");
    type(/^Password/, "hunter2");
    submit(container);
    await screen.findByLabelText("Code");
    expect(screen.queryByLabelText(/Username/)).toBeNull();
    type(/Code/, "123456");
    submit(container);
    await waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(calls(api)).toEqual(["POST /auth/login", "POST /auth/login/mfa"]);
    expect(JSON.parse(String(api.mock.calls[1][1]?.body))).toEqual({ mfa_token: "step2", code: "123456" });
  });

  it("an expired second-step token sends the user back to the password step", async () => {
    mockApi({
      "POST /auth/login": { mfa_required: true, mfa_token: "old" },
      "POST /auth/login/mfa": fail(401, "Sign-in expired, start again"),
    });
    const { container } = render(<Login {...props} onDone={vi.fn()} />);
    type(/Username/, "admin");
    type(/^Password/, "hunter2");
    submit(container);
    await screen.findByLabelText("Code");
    type(/Code/, "000000");
    submit(container);
    expect((await screen.findByRole("alert")).textContent).toMatch(/expired/);
    expect(screen.getByLabelText(/Username/)).toBeTruthy();
  });

  it("a wrong code keeps the user on the code step", async () => {
    mockApi({ "POST /auth/login": { mfa_required: true, mfa_token: "t" }, "POST /auth/login/mfa": fail(401, "Invalid code") });
    const { container } = render(<Login {...props} onDone={vi.fn()} />);
    type(/Username/, "a");
    type(/^Password/, "b");
    submit(container);
    await screen.findByLabelText("Code");
    type(/Code/, "1");
    submit(container);
    await screen.findByText("Invalid code");
    expect(screen.getByLabelText("Code")).toBeTruthy();
  });

  it("Back returns from the code step", async () => {
    mockApi({ "POST /auth/login": { mfa_required: true, mfa_token: "t" } });
    const { container } = render(<Login {...props} onDone={vi.fn()} />);
    type(/Username/, "a");
    type(/^Password/, "b");
    submit(container);
    await screen.findByLabelText("Code");
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    expect(screen.getByLabelText(/Username/)).toBeTruthy();
  });

  it("warns on an insecure connection", () => {
    render(<Login {...props} insecure onDone={vi.fn()} />);
    expect(screen.getByText(/not encrypted/)).toBeTruthy();
  });
});
