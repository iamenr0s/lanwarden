import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { qs } from "../api/client";
import { StatusBadge, StatusDot } from "../components/StatusBadge";
import { ErrorBox, inputCls, Loading } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { timeAgo } from "../lib/format";
import type { Device, Page } from "../types";

const PAGE_SIZE = 50;

// Each chip toggles one query param; the URL is the single source of filter state,
// so dashboard cards can deep-link here.
const CHIPS: { label: string; key: string; value: string }[] = [
  { label: "Online", key: "online", value: "true" },
  { label: "Offline", key: "online", value: "false" },
  { label: "New", key: "status", value: "NEW" },
  { label: "Unknown", key: "known", value: "false" },
  { label: "Known", key: "known", value: "true" },
  { label: "Favorites", key: "favorite", value: "true" },
  { label: "Always connected", key: "always_connected", value: "true" },
];

const COLUMNS: { label: string; sort?: string; cls?: string }[] = [
  { label: "" },
  { label: "Device", sort: "name" },
  { label: "Hostname", cls: "hidden lg:table-cell" },
  { label: "IP", sort: "ip" },
  { label: "MAC", sort: "mac", cls: "hidden md:table-cell" },
  { label: "Vendor", sort: "vendor", cls: "hidden xl:table-cell" },
  { label: "Type", sort: "type", cls: "hidden lg:table-cell" },
  { label: "Last seen", sort: "last_seen" },
  { label: "First seen", sort: "first_seen", cls: "hidden xl:table-cell" },
];

export default function Devices() {
  const [params, setParams] = useSearchParams();
  const [search, setSearch] = useState(params.get("q") ?? "");
  const sort = params.get("sort") ?? "last_seen";
  const order = params.get("order") ?? "desc";
  const page = Number(params.get("page") ?? "0");

  const update = (changes: Record<string, string | null>) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(changes)) v === null ? next.delete(k) : next.set(k, v);
    if (!("page" in changes)) next.delete("page");
    setParams(next, { replace: true });
  };

  // debounce typing into the URL-backed search
  useEffect(() => {
    const t = setTimeout(() => {
      if ((params.get("q") ?? "") !== search) update({ q: search || null });
    }, 300);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search]);

  const query = qs({
    q: params.get("q"),
    status: params.get("status"),
    online: params.get("online"),
    known: params.get("known"),
    favorite: params.get("favorite"),
    always_connected: params.get("always_connected"),
    group: params.get("group"),
    type: params.get("type"),
    sort,
    order,
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  });
  const { data, error, loading } = useApi<Page<Device>>(`/devices${query}`);

  const toggleSort = (col: string) =>
    update({ sort: col, order: sort === col && order === "asc" ? "desc" : "asc" });

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Devices</h1>

      <input
        className={`${inputCls} max-w-md`}
        type="search"
        placeholder="Search name, hostname, IP, MAC, vendor…"
        aria-label="Search devices"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
      />

      <div className="flex flex-wrap gap-2" role="group" aria-label="Filters">
        {CHIPS.map((c) => {
          const active = params.get(c.key) === c.value;
          return (
            <button
              key={c.label}
              aria-pressed={active}
              onClick={() => update({ [c.key]: active ? null : c.value })}
              className={`rounded-full border px-3 py-1 text-sm ${
                active
                  ? "border-emerald-500 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                  : "border-slate-300 text-slate-600 hover:bg-slate-100 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
              }`}
            >
              {c.label}
            </button>
          );
        })}
        {params.get("group") && (
          <button onClick={() => update({ group: null })} className="rounded-full border border-slate-300 px-3 py-1 text-sm dark:border-slate-700">
            Group: {params.get("group")} ✕
          </button>
        )}
        {params.get("type") && (
          <button onClick={() => update({ type: null })} className="rounded-full border border-slate-300 px-3 py-1 text-sm dark:border-slate-700">
            Type: {params.get("type")} ✕
          </button>
        )}
      </div>

      {error && <ErrorBox message={error} />}
      {loading && !data && <Loading />}

      {data && (
        <>
          <div className="overflow-x-auto rounded-lg border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-slate-200 text-xs uppercase text-slate-500 dark:border-slate-800">
                <tr>
                  {COLUMNS.map((c, i) => (
                    <th
                      key={i}
                      scope="col"
                      aria-sort={c.sort === sort ? (order === "asc" ? "ascending" : "descending") : undefined}
                      className={`px-3 py-2 font-medium ${c.cls ?? ""}`}
                    >
                      {c.sort ? (
                        <button onClick={() => toggleSort(c.sort!)} className="uppercase hover:text-slate-900 dark:hover:text-slate-100">
                          {c.label} {c.sort === sort ? (order === "asc" ? "↑" : "↓") : ""}
                        </button>
                      ) : (
                        c.label
                      )}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                {data.items.map((d) => (
                  <tr key={d.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                    <td className="px-3 py-2"><StatusDot device={d} /></td>
                    <td className="px-3 py-2">
                      <Link to={`/devices/${d.id}`} className="font-medium hover:underline">
                        {d.is_favorite && <span aria-label="Favorite" className="mr-1 text-warn">★</span>}
                        {d.display_name}
                      </Link>
                      {d.is_randomized_mac && <span title="Locally administered (private/randomised) MAC address: says little about the hardware" className="ml-2 rounded-full bg-slate-500/15 px-2 py-0.5 text-xs text-slate-500">private MAC</span>}
                      {!d.is_known && <span className="ml-2 align-middle"><StatusBadge device={d.status === "NEW" ? d : { ...d, status: "UNKNOWN" }} /></span>}
                    </td>
                    <td className="hidden px-3 py-2 text-slate-500 lg:table-cell">{d.hostname ?? "—"}</td>
                    <td className="px-3 py-2 font-mono text-xs">{d.current_ip ?? "—"}</td>
                    <td className="hidden px-3 py-2 font-mono text-xs md:table-cell">{d.mac_address ?? "—"}</td>
                    <td className="hidden px-3 py-2 xl:table-cell">{d.effective_vendor ?? "—"}</td>
                    <td className="hidden px-3 py-2 lg:table-cell">{d.effective_type ?? "—"}{!d.device_type && d.type_guess && <span title="Guessed from vendor and hostname; set a type on the device to override" className="ml-1 text-xs text-slate-500">(auto)</span>}</td>
                    <td className="px-3 py-2 text-slate-500">{timeAgo(d.last_seen)}</td>
                    <td className="hidden px-3 py-2 text-slate-500 xl:table-cell">{timeAgo(d.first_seen)}</td>
                  </tr>
                ))}
                {data.items.length === 0 && (
                  <tr>
                    <td colSpan={COLUMNS.length} className="px-3 py-8 text-center text-slate-500">
                      {[...params.keys()].some((k) => !["sort", "order", "page"].includes(k)) ? (
                        "No devices match these filters."
                      ) : (
                        <>No devices yet. Run a scan from the <Link to="/" className="text-emerald-600 hover:underline dark:text-emerald-400">Dashboard</Link>.</>
                      )}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-between text-sm text-slate-500">
            <span>{data.total} device{data.total === 1 ? "" : "s"}</span>
            <span className="flex gap-2">
              <button disabled={page === 0} onClick={() => update({ page: String(page - 1) })} className="rounded-sm border border-slate-300 px-3 py-1 disabled:opacity-40 dark:border-slate-700">Previous</button>
              <button disabled={(page + 1) * PAGE_SIZE >= data.total} onClick={() => update({ page: String(page + 1) })} className="rounded-sm border border-slate-300 px-3 py-1 disabled:opacity-40 dark:border-slate-700">Next</button>
            </span>
          </div>
        </>
      )}
    </div>
  );
}
