export type DeviceStatus = "ONLINE" | "OFFLINE" | "NEW" | "UNKNOWN";

export interface Device {
  id: number;
  mac_address: string | null;
  current_ip: string | null;
  hostname: string | null;
  friendly_name: string | null;
  vendor: string | null;
  vendor_override: string | null;
  device_type: string | null;
  device_group: string | null;
  status: DeviceStatus;
  is_online: boolean;
  first_seen: string | null;
  last_seen: string | null;
  last_connection: string | null;
  last_disconnection: string | null;
  is_known: boolean;
  is_favorite: boolean;
  always_connected: boolean;
  alert_enabled: boolean;
  is_ignored: boolean;
  is_trusted: boolean;
  notes: string | null;
  created_at: string;
  updated_at: string;
  display_name: string;
  effective_vendor: string | null;
  model: string | null;
  type_guess: string | null;
  effective_type: string | null;
  is_randomized_mac: boolean;
}

export type DeviceUpdate = Partial<
  Pick<
    Device,
    | "friendly_name"
    | "vendor_override"
    | "device_type"
    | "device_group"
    | "notes"
    | "is_known"
    | "is_favorite"
    | "always_connected"
    | "alert_enabled"
    | "is_ignored"
    | "is_trusted"
  >
>;

export interface Page<T> {
  items: T[];
  total: number;
}

export interface DeviceEvent {
  id: number;
  device_id: number | null;
  device_name: string | null;
  timestamp: string;
  event_type: string;
  old_value: string | null;
  new_value: string | null;
  source: string | null;
  metadata: Record<string, unknown> | null;
}

export interface DeviceSession {
  id: number;
  device_id: number;
  connected_at: string;
  disconnected_at: string | null;
  last_seen: string;
  source: string | null;
  duration_seconds: number | null;
}

export interface Status {
  version: string;
  anomalies_7d: number;
  devices: {
    total: number;
    online: number;
    offline: number;
    new: number;
    unknown: number;
    always_connected_down: number;
  };
}

export interface ScannerSettings {
  interfaces: string[];
  networks: string[];
  scan_interval_seconds: number;
  offline_threshold_seconds: number;
  always_connected_offline_threshold_seconds: number;
  new_device_window_hours: number;
  observation_retention_days: number;
  arp_scan_enabled: boolean;
  neighbor_discovery_enabled: boolean;
  adguard_discovery_enabled: boolean;
  service_discovery_enabled: boolean;
}

export interface SettingsResponse {
  settings: { scanner: ScannerSettings };
  detected_networks: { interface: string; cidr: string }[];
  detection_ambiguous: boolean;
}

export interface ScanRun {
  id: number;
  trigger: string;
  started_at: string;
  finished_at: string | null;
  providers: { name: string; observations: number; error: string | null }[];
  summary: Record<string, number> | null;
  error: string | null;
}

export interface ScanRuns {
  running: boolean;
  runs: ScanRun[];
}

export interface Presence {
  range: string;
  start: string;
  end: string;
  segments: { start: string; end: string }[];
  session_count: number;
  online_seconds: number;
  tracked_seconds: number;
  online_percent: number | null;
}

export interface NetworkHistory {
  addresses: { ip: string; first_seen: string; last_seen: string; source: string | null; current: boolean }[];
  names: { name: string; source: string; first_seen: string; last_seen: string }[];
  sources: { source: string; first_observed: string; last_observed: string; observations: number }[];
  observation_retention_days: number;
}

export interface SeriesPoint {
  time: string;
  online: number;
  total: number;
}

export interface DashboardData {
  range: string;
  start: string;
  end: string;
  series: SeriesPoint[];
  type_distribution: { type: string; count: number }[];
  recently_disconnected: Device[];
}

export interface NotificationRule {
  id: number;
  name: string;
  provider: "email" | "webhook";
  event_types: string[];
  enabled: boolean;
  config: Record<string, unknown>; // secrets appear only as `<field>_set` booleans
}

export interface Delivery {
  id: number;
  time: string;
  rule_id: number;
  rule_name: string;
  provider: string;
  events: number;
  ok: boolean;
  error: string | null;
}

export interface AdGuardError {
  kind: string;
  message: string;
}

export interface AdGuardServer {
  version: string;
  running: boolean | null;
  protection_enabled: boolean | null;
  dns_addresses: string[];
  dns_port: number | null;
  http_port: number | null;
  language: string | null;
}

export interface AdGuardConfig {
  configured: boolean;
  url: string | null;
  username: string;
  verify_tls: boolean;
  timeout_seconds: number;
  password_set: boolean;
}

export interface AdGuardHealth {
  configured: boolean;
  reachable: boolean;
  server: AdGuardServer | null;
  error: AdGuardError | null;
}

export interface AdGuardTestResult {
  ok: boolean;
  error: AdGuardError | null;
  server: AdGuardServer | null;
  dhcp_enabled: boolean | null;
  dhcp_leases: number | null;
  configured_clients: number | null;
}

export interface DeviceAdGuard {
  configured: boolean;
  available: boolean;
  error: AdGuardError | null;
  recognized: boolean;
  client_name: string | null;
  client_ids: string[];
  stats_queries: number | null;
  sample_size: number;
  sample_blocked: number;
  last_query: string | null;
  top_domains: { domain: string; count: number }[];
  recent: { time: string | null; domain: string; type: string | null; blocked: boolean; reason: string | null }[];
}

export interface AuthState {
  setup_required: boolean;
  setup_token_required: boolean;
  insecure_transport: boolean;
  mfa_enabled: boolean;
  mfa_enrolment_required: boolean;
  mfa_required: boolean;
  mfa_token: string | null;
  authenticated: boolean;
  username: string | null;
}

export const EVENT_TYPES = [
  "DEVICE_DISCOVERED",
  "DEVICE_CONNECTED",
  "DEVICE_DISCONNECTED",
  "DEVICE_IP_CHANGED",
  "DEVICE_NAME_CHANGED",
  "ALWAYS_CONNECTED_DEVICE_DOWN",
  "ALWAYS_CONNECTED_DEVICE_RECOVERED",
  "DEVICE_ANOMALY",
] as const;
