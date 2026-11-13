import { Link } from "react-router-dom";
import { Card } from "./ui";
import { useApi } from "../hooks/useApi";
import type { AdGuardHealth } from "../types";

/** Dashboard health card. Deliberately small: this app monitors devices, not DNS. */
export default function AdGuardCard() {
  const { data, loading } = useApi<AdGuardHealth>("/integrations/adguard/status");

  let dot = "bg-offline";
  let text = "Checking…";
  let sub: string | null = null;
  if (!loading && data) {
    if (!data.configured) {
      text = "Not configured";
    } else if (data.reachable && data.server) {
      dot = "bg-online";
      text = "Reachable";
      sub = `v${data.server.version.replace(/^v/, "")} · protection ${data.server.protection_enabled ? "on" : "off"}`;
    } else {
      dot = "bg-down";
      text = "Unreachable";
      sub = data.error?.message ?? null;
    }
  }

  return (
    <Card title="AdGuard Home">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 text-sm">
          <p className="font-medium">
            <span className={`mr-2 inline-block h-2.5 w-2.5 rounded-full ${dot}`} aria-hidden />
            {text}
          </p>
          {sub && <p className="mt-1 text-slate-500">{sub}</p>}
        </div>
        <Link to="/adguard" className="shrink-0 text-sm text-emerald-600 hover:underline dark:text-emerald-400">
          {data?.configured ? "Manage" : "Set up"}
        </Link>
      </div>
    </Card>
  );
}
