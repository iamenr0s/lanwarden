/** Shown when the page was loaded over plain HTTP from a non-loopback address: anything typed here, including
 *  the password, and the session cookie cross the network unencrypted. */
export default function InsecureNotice({ onDismiss }: { onDismiss?: () => void }) {
  return (
    <div role="alert" className="flex items-start justify-between gap-3 rounded-md border border-warn/50 bg-warn/10 px-3 py-2 text-sm text-amber-800 dark:text-amber-300">
      <p>
        <span className="font-medium">This connection is not encrypted.</span> Your password and session can be read by anyone on the network.
        Turn on HTTPS (<code>LANWARDEN_TLS_MODE=selfsigned</code>) or put LanWarden behind an HTTPS reverse proxy.
      </p>
      {onDismiss && (
        <button onClick={onDismiss} aria-label="Dismiss warning" className="shrink-0 rounded-sm px-2 hover:bg-warn/20">
          ✕
        </button>
      )}
    </div>
  );
}
