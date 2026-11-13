import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, api, qs } from "./client";

function respond(status: number, body?: unknown, statusText = "") {
  const res = new Response(body === undefined ? null : JSON.stringify(body), { status, statusText });
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(res));
}

afterEach(() => vi.unstubAllGlobals());

describe("qs", () => {
  it("drops empty values and encodes the rest", () => {
    expect(qs({ a: 1, b: "", c: null, d: undefined, e: false, f: "x y" })).toBe("?a=1&e=false&f=x+y");
  });

  it("returns an empty string when nothing is left", () => {
    expect(qs({ a: "", b: null })).toBe("");
  });
});

describe("api", () => {
  it("sends same-origin requests under /api and parses JSON", async () => {
    respond(200, { ok: true });
    await expect(api<{ ok: boolean }>("/health")).resolves.toEqual({ ok: true });
    const [url, init] = vi.mocked(fetch).mock.calls[0];
    expect(url).toBe("/api/health");
    expect(init).toMatchObject({ method: "GET", credentials: "same-origin", headers: undefined, body: undefined });
  });

  it("serialises a body as JSON", async () => {
    respond(200, {});
    await api("/devices/1", { method: "PATCH", body: { name: "nas" } });
    const init = vi.mocked(fetch).mock.calls[0][1]!;
    expect(init.body).toBe('{"name":"nas"}');
    expect(init.headers).toEqual({ "Content-Type": "application/json" });
  });

  it("returns undefined for 204", async () => {
    respond(204);
    await expect(api("/auth/logout", { method: "POST" })).resolves.toBeUndefined();
  });

  it("throws ApiError with the server's string detail", async () => {
    respond(400, { detail: "bad input" });
    const err = await api("/x").catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ status: 400, message: "bad input" });
  });

  it("joins validation messages from a detail array", async () => {
    respond(422, { detail: [{ msg: "too short" }, { msg: "required" }] });
    await expect(api("/x")).rejects.toMatchObject({ status: 422, message: "too short; required" });
  });

  it("falls back to the status text for a non-JSON error body", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("<html>", { status: 502, statusText: "Bad Gateway" })));
    await expect(api("/x")).rejects.toMatchObject({ status: 502, message: "Bad Gateway" });
  });

  it("signals an expired session on a 401, but not for /auth/ endpoints", async () => {
    const onUnauthorized = vi.fn();
    window.addEventListener("ga:unauthorized", onUnauthorized);
    try {
      respond(401, { detail: "no" });
      await expect(api("/devices")).rejects.toBeInstanceOf(ApiError);
      expect(onUnauthorized).toHaveBeenCalledTimes(1);

      respond(401, { detail: "wrong password" });
      await expect(api("/auth/login", { method: "POST", body: {} })).rejects.toBeInstanceOf(ApiError);
      expect(onUnauthorized).toHaveBeenCalledTimes(1);
    } finally {
      window.removeEventListener("ga:unauthorized", onUnauthorized);
    }
  });
});
