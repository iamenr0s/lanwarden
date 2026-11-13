import { renderHook, waitFor } from "@testing-library/react";
import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useApi } from "./useApi";

function respond(status: number, body: unknown) {
  vi.stubGlobal("fetch", vi.fn().mockImplementation(async () => new Response(JSON.stringify(body), { status })));
}

afterEach(() => vi.unstubAllGlobals());

describe("useApi", () => {
  it("loads data for a path", async () => {
    respond(200, { n: 1 });
    const { result } = renderHook(() => useApi<{ n: number }>("/thing"));
    expect(result.current.loading).toBe(true);
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.data).toEqual({ n: 1 });
    expect(result.current.error).toBeNull();
  });

  it("does nothing for a null path", () => {
    respond(200, {});
    const { result } = renderHook(() => useApi(null));
    expect(result.current.loading).toBe(false);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("exposes the error message", async () => {
    respond(500, { detail: "boom" });
    const { result } = renderHook(() => useApi("/thing"));
    await waitFor(() => expect(result.current.error).toBe("boom"));
    expect(result.current.data).toBeNull();
  });

  it("re-fetches on reload", async () => {
    respond(200, { n: 1 });
    const { result } = renderHook(() => useApi("/thing"));
    await waitFor(() => expect(result.current.loading).toBe(false));
    act(() => result.current.reload());
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
  });
});
