import { FormEvent, useState } from "react";
import { api, ApiError } from "../api/client";
import type { AuthState } from "../types";
import Logo from "../components/Logo";
import InsecureNotice from "../components/InsecureNotice";
import { btnCls, ErrorBox, Field, inputCls } from "../components/ui";

export default function Login({
  setupRequired,
  tokenRequired,
  insecure,
  onDone,
}: {
  setupRequired: boolean;
  tokenRequired: boolean;
  insecure: boolean;
  onDone: () => Promise<void>;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [token, setToken] = useState("");
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (mfaToken) {
        // second step: the code (or a recovery code) completes sign-in
        await api("/auth/login/mfa", { method: "POST", body: { mfa_token: mfaToken, code } });
        await onDone();
        return;
      }
      const res = await api<AuthState>(setupRequired ? "/auth/setup" : "/auth/login", {
        method: "POST",
        body: { username, password, ...(setupRequired && tokenRequired ? { setup_token: token } : {}) },
      });
      if (res.mfa_required && res.mfa_token) {
        setMfaToken(res.mfa_token);
        setPassword("");
        return;
      }
      await onDone();
    } catch (err) {
      // a stale or tampered second-step token cannot be retried: go back to the password step
      if (mfaToken && err instanceof ApiError && err.status === 401 && /expired/i.test(err.message)) {
        setMfaToken(null);
        setCode("");
      }
      setError(err instanceof Error ? err.message : "Request failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <form
        onSubmit={submit}
        className="w-full max-w-sm space-y-4 rounded-lg border border-slate-200 bg-white p-6 dark:border-slate-800 dark:bg-slate-900"
      >
        <div className="flex items-center gap-2">
          <Logo size={48} />
          <h1 className="text-xl font-semibold">LanWarden</h1>
        </div>
        <p className="text-sm text-slate-500">
          {mfaToken
            ? "Enter the 6-digit code from your authenticator app, or one of your recovery codes."
            : setupRequired
              ? "Create the administrator account to get started."
              : "Sign in to continue."}
        </p>
        {insecure && <InsecureNotice />}
        {error && <ErrorBox message={error} />}
        {mfaToken && (
          <Field label="Code">
            <input className={inputCls} value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" autoFocus required />
          </Field>
        )}
        {!mfaToken && setupRequired && tokenRequired && (
          <Field label="Setup token" hint="The value of LANWARDEN_SETUP_TOKEN from the server's configuration.">
            <input className={inputCls} type="password" value={token} onChange={(e) => setToken(e.target.value)} autoComplete="off" required />
          </Field>
        )}
        {!mfaToken && (
          <>
            <Field label="Username">
              <input className={inputCls} value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required minLength={3} />
            </Field>
            <Field label="Password" hint={setupRequired ? "At least 10 characters." : undefined}>
              <input
                className={inputCls}
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete={setupRequired ? "new-password" : "current-password"}
                required
                minLength={setupRequired ? 10 : 1}
              />
            </Field>
          </>
        )}
        <button className={`${btnCls} w-full`} disabled={busy}>
          {mfaToken ? "Verify" : setupRequired ? "Create account" : "Sign in"}
        </button>
        {mfaToken && (
          <button type="button" className="w-full text-sm text-slate-500 hover:underline" onClick={() => { setMfaToken(null); setCode(""); setError(null); }}>
            Back
          </button>
        )}
      </form>
    </div>
  );
}
