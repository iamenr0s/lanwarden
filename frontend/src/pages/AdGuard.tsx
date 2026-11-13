import { FormEvent, useEffect, useState } from "react";
import { api } from "../api/client";
import { btnCls, btnGhostCls, Card, ErrorBox, Field, inputCls, Loading, Toggle } from "../components/ui";
import { useApi } from "../hooks/useApi";
import type { AdGuardConfig, AdGuardHealth, AdGuardServer, AdGuardTestResult } from "../types";

const KIND_HELP: Record<string, string> = {
  auth: "Check the username and password.",
  timeout: "The server did not answer in time. Check the URL, firewall and timeout.",
  tls: "Use a trusted certificate, or turn off “Verify TLS” for a self-signed one.",
  unavailable: "Check the URL and that AdGuard Home is running.",
  bad_response: "The URL answered, but not like AdGuard Home.",
};

function ServerFacts({ s }: { s: AdGuardServer }) {
  const rows: [string, string][] = [
    ["Version", s.version],
    ["DNS", `${s.dns_addresses.join(", ") || "—"}${s.dns_port ? `:${s.dns_port}` : ""}`],
    ["Web port", s.http_port ? String(s.http_port) : "—"],
    ["Protection", s.protection_enabled === null ? "—" : s.protection_enabled ? "enabled" : "disabled"],
    ["Running", s.running === null ? "—" : s.running ? "yes" : "no"],
  ];
  return (
    <dl className="grid grid-cols-2 gap-x-6 gap-y-1 text-sm sm:grid-cols-3">
      {rows.map(([k, v]) => (
        <div key={k}>
          <dt className="text-slate-500">{k}</dt>
          <dd className="font-medium">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export default function AdGuard() {
  const config = useApi<AdGuardConfig>("/integrations/adguard");
  const health = useApi<AdGuardHealth>("/integrations/adguard/status");
  const [url, setUrl] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [verifyTls, setVerifyTls] = useState(true);
  const [timeoutS, setTimeoutS] = useState(10);
  const [busy, setBusy] = useState<"test" | "save" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [result, setResult] = useState<AdGuardTestResult | null>(null);

  useEffect(() => {
    if (config.data) {
      setUrl(config.data.url ?? "");
      setUsername(config.data.username);
      setVerifyTls(config.data.verify_tls);
      setTimeoutS(config.data.timeout_seconds);
    }
  }, [config.data]);

  if (config.error) return <ErrorBox message={config.error} />;
  if (!config.data) return <Loading />;

  // An empty password field means "keep the stored one"; it is never pre-filled.
  const body = { url, username, verify_tls: verifyTls, timeout_seconds: timeoutS, ...(password ? { password } : {}) };

  const test = async () => {
    setBusy("test");
    setError(null);
    setResult(null);
    try {
      setResult(await api<AdGuardTestResult>("/integrations/adguard/test", { method: "POST", body }));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed");
    } finally {
      setBusy(null);
    }
  };

  const save = async (e: FormEvent) => {
    e.preventDefault();
    setBusy("save");
    setError(null);
    setSaved(false);
    try {
      await api("/integrations/adguard", { method: "PUT", body });
      setPassword("");
      setSaved(true);
      config.reload();
      health.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Save failed");
    } finally {
      setBusy(null);
    }
  };

  const h = health.data;
  return (
    <div className="max-w-3xl space-y-6">
      <h1 className="text-2xl font-semibold">AdGuard Home</h1>

      <Card title="Connection status">
        {!h ? (
          <Loading />
        ) : !h.configured ? (
          <p className="text-sm text-slate-500">
            Not configured yet. LanWarden works without it; AdGuard adds DHCP names, DNS activity and per-device DNS history.
          </p>
        ) : h.reachable && h.server ? (
          <div className="space-y-3">
            <p className="text-sm"><span className="mr-2 inline-block h-2.5 w-2.5 rounded-full bg-online" aria-hidden />Reachable</p>
            <ServerFacts s={h.server} />
          </div>
        ) : (
          <ErrorBox message={`Unreachable: ${h.error?.message ?? "unknown error"}`} />
        )}
      </Card>

      <form onSubmit={save} className="space-y-5">
        <Card title="Integration settings">
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="URL" hint="e.g. http://192.168.1.2:3000">
              <input className={inputCls} value={url} onChange={(e) => setUrl(e.target.value)} required placeholder="http://adguard.lan:3000" />
            </Field>
            <Field label="Username">
              <input className={inputCls} value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" />
            </Field>
            <Field label="Password" hint={config.data.password_set ? "A password is stored. Leave empty to keep it." : undefined}>
              <input
                className={inputCls}
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="new-password"
                placeholder={config.data.password_set ? "••••••••" : ""}
              />
            </Field>
            <Field label="Timeout (seconds)">
              <input className={inputCls} type="number" min={1} max={60} value={timeoutS} onChange={(e) => setTimeoutS(Number(e.target.value))} />
            </Field>
          </div>
          <div className="mt-4">
            <Toggle label="Verify TLS certificate" checked={verifyTls} onChange={setVerifyTls} />
          </div>
          <p className="mt-3 text-xs text-slate-500">
            The password is encrypted on the server and never sent back to the browser. Turn on AdGuard discovery under Settings →
            Discovery sources.
          </p>
        </Card>

        {error && <ErrorBox message={error} />}

        <div className="flex flex-wrap items-center gap-3">
          <button type="button" className={btnGhostCls} onClick={test} disabled={busy !== null || !url}>
            {busy === "test" ? "Testing…" : "Test connection"}
          </button>
          <button className={btnCls} disabled={busy !== null || !url}>Save</button>
          {saved && <span role="status" className="text-sm text-online">Saved</span>}
        </div>
      </form>

      {result && (
        <Card title="Test result">
          {result.ok && result.server ? (
            <div className="space-y-3">
              <p role="status" className="text-sm font-medium text-online">Connection successful</p>
              <ServerFacts s={result.server} />
              <p className="text-sm text-slate-500">
                {result.dhcp_enabled === null ? "DHCP info unavailable" : `DHCP ${result.dhcp_enabled ? "enabled" : "disabled"}, ${result.dhcp_leases ?? 0} leases`}
                {result.configured_clients !== null && ` · ${result.configured_clients} configured clients`}
              </p>
            </div>
          ) : (
            <div className="space-y-1">
              <ErrorBox message={result.error?.message ?? "Connection failed"} />
              {result.error && KIND_HELP[result.error.kind] && <p className="text-sm text-slate-500">{KIND_HELP[result.error.kind]}</p>}
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
