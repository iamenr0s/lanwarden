import { api } from "../api/client";
import Logo from "../components/Logo";
import MfaCard from "../components/MfaCard";
import { useAuth } from "../hooks/auth";

/** Shown instead of the app while the server requires MFA and this account has none. */
export default function EnrolMfa() {
  const { refresh } = useAuth();
  return (
    <div className="mx-auto max-w-2xl space-y-6 p-4 md:p-8">
      <h1 className="flex items-center gap-3 text-2xl font-semibold"><Logo size={40} />LanWarden</h1>
      <MfaCard forced />
      <button
        className="text-sm text-emerald-600 hover:underline dark:text-emerald-400"
        onClick={async () => {
          await api("/auth/logout", { method: "POST" });
          await refresh();
        }}
      >
        Sign out
      </button>
    </div>
  );
}
