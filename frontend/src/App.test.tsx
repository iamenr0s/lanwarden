import { act, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import { authState, calls, mockApi } from "./test-utils";

afterEach(() => vi.unstubAllGlobals());

describe("App session gate", () => {
  it("shows the sign-in form when not authenticated", async () => {
    mockApi({ "/auth/state": authState({ authenticated: false, username: null }) });
    render(<App />);
    expect(screen.getByText("Loading…")).toBeTruthy();
    expect(await screen.findByRole("button", { name: "Sign in" })).toBeTruthy();
  });

  it("shows first-run setup when the server asks for it", async () => {
    mockApi({ "/auth/state": authState({ authenticated: false, setup_required: true }) });
    render(<App />);
    expect(await screen.findByRole("button", { name: "Create account" })).toBeTruthy();
  });

  it("falls back to the sign-in form if the session check fails", async () => {
    mockApi({});
    render(<App />);
    expect(await screen.findByRole("button", { name: "Sign in" })).toBeTruthy();
  });

  it("re-checks the session when the API reports it expired", async () => {
    const api = mockApi({ "/auth/state": authState({ authenticated: false }) });
    render(<App />);
    await screen.findByRole("button", { name: "Sign in" });
    act(() => {
      window.dispatchEvent(new Event("ga:unauthorized"));
    });
    await waitFor(() => expect(calls(api).filter((c) => c === "GET /auth/state")).toHaveLength(2));
  });
});
