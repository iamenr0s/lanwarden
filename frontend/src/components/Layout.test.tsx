import { fireEvent, screen, waitFor } from "@testing-library/react";
import { Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { authState, calls, mockApi, renderAt } from "../test-utils";
import Layout from "./Layout";

beforeEach(() => {
  sessionStorage.clear();
  localStorage.clear();
  vi.stubGlobal("matchMedia", vi.fn(() => ({ matches: false, addEventListener() {}, removeEventListener() {} })));
});
afterEach(() => vi.unstubAllGlobals());

const shell = (opts: Parameters<typeof renderAt>[1] = {}) =>
  renderAt(
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<p>home page</p>} />
        <Route path="devices" element={<p>devices page</p>} />
      </Route>
    </Routes>,
    opts,
  );

describe("Layout", () => {
  it("renders the navigation and the routed page", () => {
    shell();
    const nav = screen.getByRole("navigation", { name: "Main" });
    expect([...nav.querySelectorAll("a")].map((a) => a.textContent)).toEqual([
      "Dashboard",
      "Devices",
      "Events",
      "AdGuard",
      "Notifications",
      "Settings",
    ]);
    expect(screen.getByText("home page")).toBeTruthy();
    expect(screen.getByText("Signed in as admin")).toBeTruthy();
  });

  it("navigates between pages", () => {
    shell();
    fireEvent.click(screen.getByRole("link", { name: "Devices" }));
    expect(screen.getByText("devices page")).toBeTruthy();
  });

  it("toggles the mobile menu", () => {
    shell();
    const btn = screen.getByLabelText("Toggle navigation");
    expect(btn.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(btn);
    expect(btn.getAttribute("aria-expanded")).toBe("true");
    fireEvent.click(screen.getByRole("link", { name: "Devices" })); // choosing a page closes it again
    expect(btn.getAttribute("aria-expanded")).toBe("false");
  });

  it("changes the theme", () => {
    shell();
    fireEvent.change(screen.getByLabelText("Theme"), { target: { value: "light" } });
    expect(localStorage.getItem("ga-theme")).toBe("light");
    expect(document.documentElement.classList.contains("dark")).toBe(false);
  });

  it("signs out through the API and refreshes the session", async () => {
    const api = mockApi({ "POST /auth/logout": undefined });
    const refresh = vi.fn().mockResolvedValue(undefined);
    shell({ refresh });
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await waitFor(() => expect(refresh).toHaveBeenCalled());
    expect(calls(api)).toEqual(["POST /auth/logout"]);
  });

  it("shows the insecure-connection notice until dismissed, and remembers the dismissal", () => {
    const { unmount } = shell({ auth: authState({ insecure_transport: true }) });
    expect(screen.getByText(/not encrypted/)).toBeTruthy();
    fireEvent.click(screen.getByLabelText("Dismiss warning"));
    expect(screen.queryByText(/not encrypted/)).toBeNull();
    unmount();
    shell({ auth: authState({ insecure_transport: true }) });
    expect(screen.queryByText(/not encrypted/)).toBeNull();
  });

  it("shows no notice on a secure connection", () => {
    shell();
    expect(screen.queryByText(/not encrypted/)).toBeNull();
  });
});
