import { useEffect, useRef, useState } from "react";
import { api } from "../api/client";
import { btnCls, Card, ErrorBox } from "./ui";
import { timeAgo } from "../lib/format";
import type { ScanRuns } from "../types";

/** Shows the last scan and starts a new one. Polls while a scan is running. */
export default function ScanCard({ onFinished }: { onFinished: () => void }) {
  const [state, setState] = useState<ScanRuns | null>(null);
  const [error, setError] = useState<string | null>(null);
  const wasRunning = useRef(false);

  const load = async () => {
    try {
      const s = await api<ScanRuns>("/scanner/runs");
      setState(s);
      setError(null);
      if (wasRunning.current && !s.running) onFinished();
      wasRunning.current = s.running;
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed");
    }
  };

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!state?.running) return;
    const t = setInterval(() => void load(), 2000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state?.running]);

  const start = async () => {
    try {
      await api("/scanner/run", { method: "POST" });
      wasRunning.current = true;
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not start scan");
    }
  };

  const last = state?.runs[0];
  const problems = last?.providers.filter((p) => p.error) ?? [];

  return (
    <Card title="Network scan">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="text-sm">
          {state?.running ? (
            <span>Scanning…</span>
          ) : last ? (
            <span className="text-slate-500">
              Last scan {timeAgo(last.finished_at ?? last.started_at)}
              {last.summary && ` · ${last.summary.observed} seen, ${last.summary.discovered} new`}
            </span>
          ) : (
            <span className="text-slate-500">No scan has run yet.</span>
          )}
        </div>
        <button className={btnCls} onClick={start} disabled={state?.running}>
          Scan now
        </button>
      </div>
      {error && <div className="mt-3"><ErrorBox message={error} /></div>}
      {last?.error && <div className="mt-3"><ErrorBox message={last.error} /></div>}
      {problems.length > 0 && (
        <ul className="mt-3 space-y-1 text-sm text-amber-700 dark:text-amber-400">
          {problems.map((p) => (
            <li key={p.name}>
              <span className="font-medium">{p.name}:</span> {p.error}
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
