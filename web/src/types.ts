export type Severity = 'critical' | 'fatal' | 'high' | 'medium' | 'low' | 'informational' | 'unknown';
export type AlertStatus = 'open' | 'acknowledged' | 'suppressed' | 'closed';

export interface SyncState {
 coverage_start?: string;
	status?: 'healthy' | 'failed' | 'pending' | 'never_synced' | 'stale' | 'partial';
	failed_records?: number;
  cursor_end?: string;
  pending?: boolean;
  pending_count?: number;
  last_success_at?: string;
  last_attempt_at?: string;
  last_error?: string;
  last_error_at?: string;
  last_duration_ms?: number;
  items_last_run?: number;
  consecutive_failures?: number;
  healthy?: boolean;
}

export interface IngestFailure {
  id: string;
  account_id: string;
  raw: unknown;
  error: string;
  attempts: number;
  mapper_version: string;
  last_attempt_at: string;
}

export interface Account {
  id: string;
  name: string;
  provider: string;
  provider_name?: string;
  account_uid?: string;
  region?: string;
  enabled: boolean;
  options?: Record<string, string>;
  access_key_hint?: string;
  credential_configured?: boolean;
  created_at?: string;
  updated_at?: string;
  sync_state?: SyncState;
}

export interface CredentialField {
  name: string;
  label: string;
  secret?: boolean;
  required?: boolean;
  multiline?: boolean;
  help?: string;
}

export interface OptionField {
  name: string;
  label: string;
  required?: boolean;
  placeholder?: string;
  help?: string;
}

export interface Product {
  code: string;
  name: string;
}

export interface Provider {
  id: string;
  name: string;
  vendor: string;
  product: string;
  product_uid?: string;
  api_version?: string;
  mapper_version?: string;
  credential_fields?: CredentialField[];
  option_fields?: OptionField[];
  products?: Product[];
}

export interface Meta {
  name: string;
  version?: string;
  commit?: string;
  build_date?: string;
  ocsf_version?: string;
  api_prefix?: string;
  mcp_endpoint?: string;
  auth_enabled?: boolean;
  dev_mode?: boolean;
  mock?: boolean;
  sync_enabled?: boolean;
  session_ttl_seconds?: number;
  providers?: Provider[];
}

export interface User {
  id: string;
  username: string;
  role: 'admin' | 'viewer';
  disabled?: boolean;
}

export interface Me {
  auth_type: 'session' | 'apikey' | 'dev';
  dev_mode?: boolean;
  expires_at?: string;
  user: User;
}

export interface Resource {
  id?: string;
  name?: string;
  type?: string;
}

export interface Observable {
  name?: string;
  type?: string;
  type_id?: number;
  value?: string;
}

export interface Evidence {
  type?: string;
  data?: unknown;
}

export type AlertGroupBy = 'type_asset' | 'signature' | 'asset' | 'source';

export interface QueryWindow {
 time_field?: string;
 snapshot_sequence?: number;
  start?: string;
  end?: string;
}

export interface AlertGroup {
  id: string;
  group_by: AlertGroupBy;
  key: Record<string, string>;
  title: string;
  finding_count: number;
  revision_count: number;
  max_severity: Severity;
  first_seen_at: string | null;
  last_seen_at: string | null;
  providers?: string[];
  resource_id?: string;
  resource_name?: string;
  source_ip?: string;
  alert_type?: string;
}

export interface AlertGroupList {
 snapshot_sequence?: number;
 coverage?: Coverage;
  groups: AlertGroup[];
  total: number;
  group_by: AlertGroupBy;
  limit: number;
  offset: number;
  window?: QueryWindow;
}

export interface AlertRevision {
  projection_updated?: boolean;
 record?: Alert;
 sequence?: number;
 raw_hash?: string;
 raw_url?: string;
  id: string;
  alert_id: string;
  revision: number;
  captured_at: string;
  title?: string;
  severity: Severity;
  vendor_status?: string;
  raw?: unknown;
  ocsf?: unknown;
}

export interface Alert {
  projection_updated?: boolean;
 rule_id?: string;
 finding_kind?: string;
 source_created_at?: string;
 source_updated_at?: string;
 ingested_at?: string;
 last_ingested_at?: string;
 raw_hash?: string;
 raw_url?: string;
 revision?: number;
 sequence?: number;
 provenance?: Record<string, { source: string; paths: string[]; transform: string }>;
 occurrence_count?: number;
 occurrence_scope?: string;
 ocsf_omission_reason?: string;

  id: string;
  provider: string;
  account_id: string;
  account_name?: string;
  account_uid?: string;
  external_id?: string;
  product?: string;
  title: string;
  description?: string;
  severity: Severity;
  severity_id?: number;
  original_severity?: string;
  status: AlertStatus;
  vendor_status?: string;
  alert_type?: string;
  event_time: string;
  first_seen_at?: string;
  last_seen_at?: string;
  region?: string;
  resource?: Resource;
  resources?: Resource[];
  source_ip?: string;
  destination_ip?: string;
  tactic?: string;
  technique?: string;
  observables?: Observable[];
  evidences?: Evidence[];
  mapper_version?: string;
  ocsf?: unknown;
  raw?: unknown;
  created_at?: string;
  updated_at?: string;
}

export interface AlertList {
 snapshot_sequence?: number;
 coverage?: Coverage;
  alerts: Alert[];
  total: number;
  limit: number;
  offset: number;
  window?: QueryWindow;
}

export interface DayCount {
  day: string;
  count: number;
}

export interface Count {
  key: string;
  name?: string;
  count: number;
}

export interface Statistics {
  total: number;
  by_severity?: Record<string, number>;
  by_provider?: Record<string, number>;
  by_status?: Record<string, number>;
  by_day?: DayCount[];
  top_resources?: Count[];
}

export interface StatsResponse {
  statistics: Statistics;
  window?: { start?: string; end?: string };
}

export interface HealthResponse {
  status: string;
  version?: string;
  uptime_seconds?: number;
  database?: string;
  accounts?: Account[];
  summary?: {
    healthy?: number;
    unhealthy?: number;
    pending?: number;
    disabled?: number;
  };
}

export interface SyncRun {
  id: string;
  account_id: string;
  provider?: string;
  trigger: string;
  status: string;
  started_at: string;
  finished_at?: string;
  pages?: number;
  fetched?: number;
  created?: number;
  updated?: number;
  failed?: number;
  duration_ms?: number;
  error?: string;
}

export interface APIKey {
  id: string;
  name: string;
  prefix: string;
  created_at: string;
  last_used_at?: string;
  expires_at?: string;
  revoked_at?: string;
}

export interface AccountPayload {
  name?: string;
  provider?: string;
  account_uid?: string;
  region?: string;
  enabled?: boolean;
  options?: Record<string, string>;
  access_key_id?: string;
  access_key_secret?: string;
  session_token?: string;
  service_account_json?: string;
  [key: string]: unknown;
}

export type Page = 'overview' | 'alerts' | 'accounts' | 'health' | 'mcp' | 'audit';

export interface Coverage {
 complete: boolean;
 boundary: string;
 accounts: Array<{account_id: string;provider: string;name: string;status: string;complete: boolean;api: string;api_version: string;scope: Record<string,string>;time_basis: string;coverage_start: string | null;watermark: string | null;failed_records: number;limitations: string[]}>;
}
