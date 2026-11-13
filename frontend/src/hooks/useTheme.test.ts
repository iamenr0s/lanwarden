import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { applyTheme, useTheme } from "./useTheme";

let prefersDark = true;
let listeners: (() => void)[] = [];

beforeEach(() => {
  localStorage.clear();
  document.documentElement.classList.remove("dark");
  prefersDark = true;
  listeners = [];
  vi.stubGlobal(
    "matchMedia",
    vi.fn(() => ({
      get matches() {
        return prefersDark;
      },
      addEventListener: (_: string, l: () => void) => listeners.push(l),
      removeEventListener: (_: string, l: () => void) => (listeners = listeners.filter((x) => x !== l)),
    })),
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const isDark = () => document.documentElement.classList.contains("dark");

describe("applyTheme", () => {
  it("dark and light are explicit; system follows the OS", () => {
    applyTheme("dark");
    expect(isDark()).toBe(true);
    applyTheme("light");
    expect(isDark()).toBe(false);
    prefersDark = true;
    applyTheme("system");
    expect(isDark()).toBe(true);
    prefersDark = false;
    applyTheme("system");
    expect(isDark()).toBe(false);
  });
});

describe("useTheme", () => {
  it("defaults to dark and persists a change", () => {
    const { result } = renderHook(() => useTheme());
    expect(result.current[0]).toBe("dark");
    expect(isDark()).toBe(true);
    act(() => result.current[1]("light"));
    expect(isDark()).toBe(false);
    expect(localStorage.getItem("ga-theme")).toBe("light");
  });

  it("restores a stored choice and ignores junk", () => {
    localStorage.setItem("ga-theme", "light");
    expect(renderHook(() => useTheme()).result.current[0]).toBe("light");
    localStorage.setItem("ga-theme", "purple");
    expect(renderHook(() => useTheme()).result.current[0]).toBe("dark");
  });

  it("in system mode it reacts to the OS changing, and stops listening afterwards", () => {
    localStorage.setItem("ga-theme", "system");
    const { result, unmount } = renderHook(() => useTheme());
    expect(result.current[0]).toBe("system");
    expect(listeners).toHaveLength(1);
    prefersDark = false;
    act(() => listeners[0]());
    expect(isDark()).toBe(false);
    unmount();
    expect(listeners).toHaveLength(0);
  });

  it("survives unavailable storage", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    const { result } = renderHook(() => useTheme());
    expect(result.current[0]).toBe("dark");
  });
});
