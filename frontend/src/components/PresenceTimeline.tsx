import { duration } from "../lib/format";
import type { Presence } from "../types";

const TICKS = 5;

/** One horizontal bar: green where the device was online, empty elsewhere. */
export default function PresenceTimeline({ data }: { data: Presence }) {
  const start = new Date(data.start).getTime();
  const total = Math.max(1, new Date(data.end).getTime() - start);
  const pct = (iso: string) => ((new Date(iso).getTime() - start) / total) * 100;
  const short = total <= 36 * 3600 * 1000; // hours for a day view, dates for longer ones
  const label = (ms: number) =>
    short
      ? new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
      : new Date(ms).toLocaleDateString([], { month: "short", day: "numeric" });

  const summary = `Online ${duration(data.online_seconds)}${data.online_percent !== null ? ` (${data.online_percent}% of tracked time)` : ""} in ${data.segments.length} interval${data.segments.length === 1 ? "" : "s"}`;

  return (
    <div>
      <div
        role="img"
        aria-label={summary}
        className="relative h-9 w-full overflow-hidden rounded-md bg-slate-200 dark:bg-slate-800"
      >
        {data.segments.map((s, i) => (
          <div
            key={i}
            title={`${new Date(s.start).toLocaleString()} → ${new Date(s.end).toLocaleString()}`}
            className="absolute inset-y-0 bg-online"
            // keep very short sessions visible
            style={{ left: `${pct(s.start)}%`, width: `${Math.max(0.4, pct(s.end) - pct(s.start))}%` }}
          />
        ))}
      </div>
      <div className="mt-1 flex justify-between text-xs text-slate-500" aria-hidden>
        {Array.from({ length: TICKS }, (_, i) => (
          <span key={i}>{label(start + (total * i) / (TICKS - 1))}</span>
        ))}
      </div>
    </div>
  );
}
