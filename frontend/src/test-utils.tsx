import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import { AuthContext } from "./hooks/auth";
import type { AuthState, Device, DeviceEvent } from "./types";

const FAIL = Symbol("fail");
/** A route result that makes the mocked API answer with an error status and a `detail` message. */
export const fail = (status: number, detail: string) => ({ [FAIL]: true, status, detail });

type Route = unknown | ((body: unknown) => unknown);

/**
 * Stub `fetch` with a table of routes. Keys are `"METHOD /path"` or just `"/path"` (any method), without the
 * `/api` prefix; a trailing `*` matches a prefix. Exact keys win over prefixes. Unmatched requests answer 404.
 */
export function mockApi(routes: Record<string, Route>) {
  const fn = vi.fn(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? "GET";
    const path = String(url).replace(/^\/api/, "");
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    const candidates = [`${method} ${path}`, path];
    const entries = Object.entries(routes);
    const hit =
      candidates.map((c) => entries.find(([k]) => k === c)).find(Boolean) ?? // "METHOD /path" beats "/path"
      entries.find(([k]) => k.endsWith("*") && candidates.some((c) => c.startsWith(k.slice(0, -1))));
    if (!hit) return new Response(JSON.stringify({ detail: `no mock for ${method} ${path}` }), { status: 404 });
    const value = typeof hit[1] === "function" ? (hit[1] as (b: unknown) => unknown)(body) : hit[1];
    if (value && typeof value === "object" && FAIL in value) {
      const f = value as ReturnType<typeof fail>;
      return new Response(JSON.stringify({ detail: f.detail }), { status: f.status });
    }
    return value === undefined ? new Response(null, { status: 204 }) : new Response(JSON.stringify(value), { status: 200 });
  });
  vi.stubGlobal("fetch", fn);
  return fn;
}

/** Requests the mocked API received, as `"METHOD /path"` strings. */
export const calls = (fn: ReturnType<typeof mockApi>) =>
  fn.mock.calls.map(([url, init]) => `${init?.method ?? "GET"} ${String(url).replace(/^\/api/, "")}`);

export const authState = (over: Partial<AuthState> = {}): AuthState => ({
  setup_required: false,
  setup_token_required: false,
  insecure_transport: false,
  authenticated: true,
  username: "admin",
  mfa_enabled: false,
  mfa_enrolment_required: false,
  mfa_required: false,
  mfa_token: null,
  ...over,
});

export const makeDevice = (over: Partial<Device> = {}): Device => ({
  id: 1,
  mac_address: "aa:bb:cc:dd:ee:01",
  current_ip: "192.168.1.10",
  hostname: "host1",
  friendly_name: null,
  vendor: "Acme",
  vendor_override: null,
  device_type: null,
  device_group: null,
  status: "ONLINE",
  is_online: true,
  first_seen: "2026-01-01T00:00:00Z",
  last_seen: "2026-01-01T00:00:00Z",
  last_connection: null,
  last_disconnection: null,
  is_known: true,
  is_favorite: false,
  always_connected: false,
  alert_enabled: false,
  is_ignored: false,
  is_trusted: false,
  notes: null,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
  display_name: "Host One",
  effective_vendor: "Acme",
  model: null,
  type_guess: null,
  effective_type: null,
  is_randomized_mac: false,
  ...over,
});

export const makeEvent = (over: Partial<DeviceEvent> = {}): DeviceEvent => ({
  id: 1,
  device_id: 1,
  device_name: "Host One",
  timestamp: "2026-01-01T00:00:00Z",
  event_type: "DEVICE_CAME_ONLINE",
  old_value: null,
  new_value: null,
  source: null,
  metadata: null,
  ...over,
});

/** Render inside a router and an authenticated session. */
export function renderAt(ui: ReactElement, { route = "/", auth = authState(), refresh = async () => {} } = {}) {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <AuthContext.Provider value={{ auth, refresh }}>{ui}</AuthContext.Provider>
    </MemoryRouter>,
  );
}
