import { FormEvent, useState } from "react";
import { api } from "../api/client";
import { useAuth } from "../hooks/auth";
import QrCode from "./QrCode";
import { btnCls, btnGhostCls, Card, ErrorBox, Field, inputCls } from "./ui";

type Step = { kind: "idle" } | { kind: "setup"; secret: string; uri: string } | { kind: "codes"; codes: string[] };
type Action = "regenerate" | "disable" | null;

const group = (s: string) => s.replace(/(.{4})/g, "$1 ").trim();

/** Two-step verification (TOTP) enrolment and management. Secrets and recovery codes are shown once. */
export default function MfaCard({ forced = false }: { forced?: boolean }) {
  const { auth, refresh } = useAuth();
  const [step, setStep] = useState<Step>({ kind: "idle" });
  const [action, setAction] = useState<Action>(null);
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const reset = () => {
    setPassword("");
    setCode("");
    setError(null);
  };

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed");
    } finally {
      setBusy(false);
    }
  };

  const start = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const r = await api<{ secret: string; otpauth_uri: string }>("/auth/mfa/setup", { method: "POST", body: { password } });
      setStep({ kind: "setup", secret: r.secret, uri: r.otpauth_uri });
      reset();
    });
  };

  const enable = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const r = await api<{ recovery_codes: string[] }>("/auth/mfa/enable", { method: "POST", body: { code } });
      setStep({ kind: "codes", codes: r.recovery_codes });
      reset();
    });
  };

  const confirm = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      if (action === "disable") {
        await api("/auth/mfa/disable", { method: "POST", body: { password, code } });
      } else {
        const r = await api<{ recovery_codes: string[] }>("/auth/mfa/recovery-codes", { method: "POST", body: { password, code } });
        setStep({ kind: "codes", codes: r.recovery_codes });
      }
      setAction(null);
      reset();
      await refresh();
    });
  };

  const download = (codes: string[]) => {
    const url = URL.createObjectURL(new Blob([`LanWarden recovery codes (each works once)\n\n${codes.join("\n")}\n`], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "lanwarden-recovery-codes.txt";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Card title="Two-step verification">
      {error && <div className="mb-3"><ErrorBox message={error} /></div>}

      {step.kind === "codes" && (
        <div className="space-y-3">
          <p className="text-sm font-medium">Save these recovery codes now. They are shown only once.</p>
          <p className="text-sm text-slate-500">Each code works one time if you lose your authenticator. Store them somewhere safe, separate from your password.</p>
          <ul className="grid grid-cols-2 gap-x-6 gap-y-1 rounded-md border border-slate-300 bg-slate-50 p-3 font-mono text-sm dark:border-slate-700 dark:bg-slate-950 sm:grid-cols-5">
            {step.codes.map((c) => <li key={c}>{c}</li>)}
          </ul>
          <div className="flex flex-wrap gap-2">
            <button className={btnGhostCls} onClick={() => void navigator.clipboard?.writeText(step.codes.join("\n"))}>Copy</button>
            <button className={btnGhostCls} onClick={() => download(step.codes)}>Download</button>
            <button className={btnCls} onClick={() => { setStep({ kind: "idle" }); void refresh(); }}>I have saved them</button>
          </div>
        </div>
      )}

      {step.kind === "setup" && (
        <form onSubmit={enable} className="space-y-4">
          <p className="text-sm text-slate-500">Scan this code with an authenticator app (any TOTP app works), then enter the 6-digit code it shows.</p>
          <div className="flex flex-wrap items-start gap-6">
            <QrCode value={step.uri} label="QR code for your authenticator app" />
            <div className="min-w-0 space-y-3 text-sm">
              <div>
                <p className="text-slate-500">Can’t scan? Enter this key manually:</p>
                <p className="mt-1 select-all break-all font-mono">{group(step.secret)}</p>
              </div>
              <Field label="Code from the app">
                <input className={inputCls} inputMode="numeric" autoComplete="one-time-code" maxLength={7} value={code} onChange={(e) => setCode(e.target.value)} required />
              </Field>
              <div className="flex gap-2">
                <button className={btnCls} disabled={busy}>Turn on</button>
                <button type="button" className={btnGhostCls} onClick={() => { setStep({ kind: "idle" }); reset(); }}>Cancel</button>
              </div>
            </div>
          </div>
        </form>
      )}

      {step.kind === "idle" && !auth.mfa_enabled && (
        <form onSubmit={start} className="space-y-3">
          {forced && <p className="text-sm text-amber-700 dark:text-amber-400">This server requires two-step verification. Set it up to continue.</p>}
          <p className="text-sm text-slate-500">Add a second step at sign-in: a 6-digit code from an authenticator app, on top of your password.</p>
          <div className="max-w-xs">
            <Field label="Confirm your password">
              <input className={inputCls} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
            </Field>
          </div>
          <button className={btnCls} disabled={busy}>Set up</button>
        </form>
      )}

      {step.kind === "idle" && auth.mfa_enabled && (
        <div className="space-y-3">
          <p className="text-sm"><span className="mr-2 inline-block h-2.5 w-2.5 rounded-full bg-online" aria-hidden />Two-step verification is on.</p>
          {action === null ? (
            <div className="flex flex-wrap gap-2">
              <button className={btnGhostCls} onClick={() => { setAction("regenerate"); reset(); }}>New recovery codes</button>
              <button className={btnGhostCls} onClick={() => { setAction("disable"); reset(); }}>Turn off</button>
            </div>
          ) : (
            <form onSubmit={confirm} className="space-y-3">
              <p className="text-sm text-slate-500">
                {action === "disable" ? "Turning it off" : "Replacing your recovery codes"} needs your password and a current code (or a recovery code).
              </p>
              <div className="grid max-w-md gap-3 sm:grid-cols-2">
                <Field label="Password"><input className={inputCls} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required /></Field>
                <Field label="Code"><input className={inputCls} value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" required /></Field>
              </div>
              <div className="flex gap-2">
                <button className={btnCls} disabled={busy}>{action === "disable" ? "Turn off" : "Replace codes"}</button>
                <button type="button" className={btnGhostCls} onClick={() => { setAction(null); reset(); }}>Cancel</button>
              </div>
            </form>
          )}
        </div>
      )}
    </Card>
  );
}
