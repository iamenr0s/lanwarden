import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { qs } from "../api/client";
import { Card, ErrorBox, inputCls, Loading } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { eventLabel, fullTime } from "../lib/format";
import { DeviceEvent, EVENT_TYPES, Page } from "../types";

const PAGE_SIZE = 50;

export default function Events() {
  const [search, setSearch] = useState("");
  const [q, setQ] = useState("");
  const [params] = useSearchParams();
  const [type, setType] = useState(params.get("event_type") ?? "");
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [page, setPage] = useState(0);

  useEffect(() => {
    const t = setTimeout(() => {
      setQ(search);
      setPage(0);
    }, 300);
    return () => clearTimeout(t);
  }, [search]);

  // date inputs are local calendar days: [since 00:00, until 23:59:59.999]
  const query = qs({
    q,
    event_type: type,
    since: since ? new Date(`${since}T00:00:00`).toISOString() : "",
    until: until ? new Date(`${until}T23:59:59.999`).toISOString() : "",
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  });
  const { data, error, loading } = useApi<Page<DeviceEvent>>(`/events${query}`);

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Events</h1>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <input className={inputCls} type="search" placeholder="Search device, IP, MAC, values…" aria-label="Search events" value={search} onChange={(e) => setSearch(e.target.value)} />
        <select className={inputCls} aria-label="Event type" value={type} onChange={(e) => { setType(e.target.value); setPage(0); }}>
          <option value="">All event types</option>
          {EVENT_TYPES.map((t) => <option key={t} value={t}>{eventLabel(t)}</option>)}
        </select>
        <input className={inputCls} type="date" aria-label="From date" value={since} onChange={(e) => { setSince(e.target.value); setPage(0); }} />
        <input className={inputCls} type="date" aria-label="To date" value={until} onChange={(e) => { setUntil(e.target.value); setPage(0); }} />
      </div>

      {error && <ErrorBox message={error} />}
      {loading && !data && <Loading />}
      {data && (
        <Card>
          {data.items.length === 0 ? (
            <p className="text-sm text-slate-500">No events match.</p>
          ) : (
            <ul className="divide-y divide-slate-200 dark:divide-slate-800">
              {data.items.map((e) => (
                <li key={e.id} className="flex flex-wrap items-center justify-between gap-2 py-2 text-sm">
                  <span>
                    <span className="font-medium">{eventLabel(e.event_type)}</span>{" "}
                    {e.device_id ? (
                      <Link to={`/devices/${e.device_id}`} className="text-emerald-600 hover:underline dark:text-emerald-400">{e.device_name}</Link>
                    ) : (
                      <span className="text-slate-500">(deleted device)</span>
                    )}
                    {(e.old_value || e.new_value) && <span className="text-slate-500"> · {e.old_value ?? "—"} → {e.new_value ?? "—"}</span>}
                  </span>
                  <span className="text-slate-500">{fullTime(e.timestamp)}{e.source ? ` · ${e.source}` : ""}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      )}
      {data && (
        <div className="flex items-center justify-between text-sm text-slate-500">
          <span>{data.total} event{data.total === 1 ? "" : "s"}</span>
          <span className="flex gap-2">
            <button disabled={page === 0} onClick={() => setPage(page - 1)} className="rounded-sm border border-slate-300 px-3 py-1 disabled:opacity-40 dark:border-slate-700">Previous</button>
            <button disabled={(page + 1) * PAGE_SIZE >= data.total} onClick={() => setPage(page + 1)} className="rounded-sm border border-slate-300 px-3 py-1 disabled:opacity-40 dark:border-slate-700">Next</button>
          </span>
        </div>
      )}
    </div>
  );
}
