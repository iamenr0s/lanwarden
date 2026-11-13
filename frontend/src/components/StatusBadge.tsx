import type { Device } from "../types";

type StatusFields = Pick<Device, "is_online" | "always_connected" | "status">;

const isDown = (d: StatusFields) => d.always_connected && !d.is_online && d.status !== "UNKNOWN";

/** green = online, gray = offline, amber = new/warning, red = problem/down. */
export function StatusDot({ device }: { device: StatusFields }) {
  const down = isDown(device);
  const color = down ? "bg-down" : device.is_online ? "bg-online" : "bg-offline";
  const label = down ? "Down" : device.is_online ? "Online" : "Offline";
  return <span role="img" aria-label={label} title={label} className={`inline-block h-2.5 w-2.5 rounded-full ${color}`} />;
}

export function StatusBadge({ device }: { device: StatusFields }) {
  const base = "inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium";
  if (isDown(device)) return <span className={`${base} bg-down/15 text-red-600 dark:text-red-400`}>Down</span>;
  if (device.status === "NEW") return <span className={`${base} bg-warn/15 text-amber-700 dark:text-amber-400`}>New</span>;
  if (device.status === "UNKNOWN")
    return <span className={`${base} bg-slate-500/15 text-slate-600 dark:text-slate-400`}>Unknown</span>;
  return device.is_online ? (
    <span className={`${base} bg-online/15 text-green-700 dark:text-green-400`}>Online</span>
  ) : (
    <span className={`${base} bg-offline/15 text-slate-600 dark:text-slate-400`}>Offline</span>
  );
}
