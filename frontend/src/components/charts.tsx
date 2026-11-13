import type { SeriesPoint } from "../types";

// Status colours used across the whole UI: green online, gray offline, amber new, red problem.
export const COLORS = { online: "#22c55e", offline: "#6b7280", warn: "#f59e0b", down: "#ef4444", accent: "#10b981" };

export interface Segment {
  label: string;
  value: number;
  color: string;
}

/** Ring chart of parts of a whole, with a legend. The text legend is the accessible version of the ring. */
export function Donut({ segments, centerLabel }: { segments: Segment[]; centerLabel: string }) {
  const total = segments.reduce((s, x) => s + x.value, 0);
  const R = 15.9155; // circumference 100, so a value's percentage is its dash length
  let offset = 25; // start at 12 o'clock
  const summary = total === 0 ? "No devices" : segments.map((s) => `${s.value} ${s.label.toLowerCase()}`).join(", ");

  return (
    <div className="flex items-center gap-5">
      <svg viewBox="0 0 42 42" className="h-32 w-32 shrink-0" role="img" aria-label={summary}>
        <circle cx="21" cy="21" r={R} fill="none" stroke="currentColor" strokeOpacity="0.12" strokeWidth="5" />
        {total > 0 &&
          segments.map((s) => {
            if (s.value === 0) return null;
            const pct = (s.value / total) * 100;
            const el = (
              <circle
                key={s.label}
                cx="21" cy="21" r={R} fill="none" stroke={s.color} strokeWidth="5"
                strokeDasharray={`${pct} ${100 - pct}`} strokeDashoffset={offset}
              />
            );
            offset -= pct;
            return el;
          })}
        <text x="21" y="21.5" textAnchor="middle" fontSize="8" fontWeight="600" fill="currentColor">{total}</text>
        <text x="21" y="27" textAnchor="middle" fontSize="3.2" fill="currentColor" opacity="0.6">{centerLabel}</text>
      </svg>
      <ul className="min-w-0 flex-1 space-y-1.5 text-sm">
        {segments.map((s) => (
          <li key={s.label} className="flex items-center gap-2">
            <span className="inline-block h-2.5 w-2.5 shrink-0 rounded-xs" style={{ background: s.color }} aria-hidden />
            <span className="text-slate-500">{s.label}</span>
            <span className="ml-auto pl-3 font-medium">{s.value}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Horizontal proportional bars; the numbers are printed so colour is never the only signal. */
export function BarList({ items }: { items: { label: string; value: number }[] }) {
  const max = Math.max(1, ...items.map((i) => i.value));
  if (items.length === 0) return <p className="text-sm text-slate-500">No devices yet.</p>;
  return (
    <ul className="space-y-2 text-sm">
      {items.map((i) => (
        <li key={i.label}>
          <div className="mb-0.5 flex justify-between gap-3">
            <span className={i.label === "Unclassified" ? "text-slate-500" : "capitalize"}>{i.label}</span>
            <span className="font-medium">{i.value}</span>
          </div>
          <div className="h-2 overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800">
            <div className="h-full rounded-full" style={{ width: `${(i.value / max) * 100}%`, background: COLORS.accent }} />
          </div>
        </li>
      ))}
    </ul>
  );
}

const W = 640, H = 210, L = 34, R = 10, T = 12, B = 26;

function niceStep(max: number): number {
  for (const s of [1, 2, 5, 10, 20, 50, 100, 200, 500]) if (max / s <= 5) return s;
  return 1000;
}

/** Online devices (filled) against devices known so far (dashed), sampled over the chosen range. */
export function LineChart({ points, range }: { points: SeriesPoint[]; range: string }) {
  const n = points.length;
  const peak = Math.max(1, ...points.map((p) => Math.max(p.online, p.total)));
  const step = niceStep(peak);
  const yMax = Math.ceil(peak / step) * step;
  const x = (i: number) => L + (i / Math.max(1, n - 1)) * (W - L - R);
  const y = (v: number) => T + (1 - v / yMax) * (H - T - B);
  const path = (key: "online" | "total") => points.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(p[key]).toFixed(1)}`).join(" ");
  const yTicks = Array.from({ length: yMax / step + 1 }, (_, i) => i * step);
  const xTicks = [0, 0.25, 0.5, 0.75, 1].map((f) => Math.round(f * (n - 1)));
  const fmt = (iso: string) =>
    range === "24h"
      ? new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
      : new Date(iso).toLocaleDateString([], { month: "short", day: "numeric" });
  const last = points[n - 1];
  const span = range === "24h" ? "24 hours" : range === "7d" ? "7 days" : "30 days";
  const label = `Devices online over the last ${span}: ${last?.online ?? 0} online now, ${last?.total ?? 0} known`;

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label={label}>
      {yTicks.map((v) => (
        <g key={v}>
          <line x1={L} x2={W - R} y1={y(v)} y2={y(v)} stroke="currentColor" strokeOpacity="0.12" />
          <text x={L - 6} y={y(v) + 3} textAnchor="end" fontSize="10" fill="currentColor" opacity="0.6">{v}</text>
        </g>
      ))}
      {n > 1 && <path d={`${path("online")} L${x(n - 1)},${y(0)} L${x(0)},${y(0)} Z`} fill={COLORS.online} fillOpacity="0.18" />}
      <path d={path("total")} fill="none" stroke={COLORS.offline} strokeWidth="1.5" strokeDasharray="4 3" />
      <path d={path("online")} fill="none" stroke={COLORS.online} strokeWidth="2" strokeLinejoin="round" />
      {points.map((p, i) => (
        <circle key={i} cx={x(i)} cy={y(p.online)} r="6" fill="transparent">
          <title>{`${new Date(p.time).toLocaleString()}: ${p.online} online of ${p.total} known`}</title>
        </circle>
      ))}
      {xTicks.map((i) => (
        <text key={i} x={x(i)} y={H - 8} textAnchor={i === 0 ? "start" : i === n - 1 ? "end" : "middle"} fontSize="10" fill="currentColor" opacity="0.6">
          {points[i] ? fmt(points[i].time) : ""}
        </text>
      ))}
    </svg>
  );
}
