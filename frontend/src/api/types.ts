// Mirrors config_assessment/core/models.py and config_assessment/api/schemas.py.
// Hand-written and additive-only, matching the API's own additive-only
// contract. A candidate for OpenAPI codegen if hand-maintaining it ever costs
// more than the generated indirection would.

export type Severity = "Critical" | "High" | "Medium" | "Low" | "None";

export interface Directive {
  name: string;
  value: string;
  context: string;
  source_file: string;
  line_number: number | null;
}

export interface Misconfiguration {
  target_name: string;
  directive: string;
  bad_value: string;
  ac: string;
  c: string;
  i: string;
  a: string;
  good_value: string;
  id: string;
  av: string;
  au: string;
  base_score: number;
  temporal_score: number;
  gel: string;
  grl: string;
  cves: string[];
  cce_id: string;
  cis_section: string;
  justification: string;
  recommendation: string;
  rule_type: string;
  required_when: string;
  expected_value_prefix: string;
  detected_in_scan: boolean;
  source_directive: Directive | null;
  version_amplification: number;
  version_risk_note: string;
  narrative: string;
  confidence: number;
}

export interface AttackChain {
  chain_id: string;
  target_name: string;
  misconfig_directives: string[];
  amplification: number;
  justification: string;
  cross_target: boolean;
  active: boolean;
  triggered_by: string[];
  amplified_score: number;
}

export interface SystemProfile {
  av: string;
  au: string;
  rationale_av: string;
  rationale_au: string;
}

export interface ScanResult {
  target_name: string;
  input_path: string;
  input_hash: string;
  profile: SystemProfile;
  scan_id: string;
  timestamp: string;
  issues: Misconfiguration[];
  chains: AttackChain[];
  global_base_score: number;
  global_temporal_score: number;
  severity: Severity;
  total_directives_scanned: number;
  total_issues_found: number;
  total_chains_detected: number;
  detected_version: string | null;
  version_exploits: unknown[];
  exploit_lookup_failed: boolean;
  version_cves_checked: number;
  unknown_directives: string[];
  manifest: Record<string, unknown>;
}

// POST /scans and /scans/upload return this — ScanResult plus the CI-flag
// outcome fields (--threshold, --suppress-file), surfaced as data.
export interface ScanResponse extends ScanResult {
  passed_threshold: boolean;
  suppressed_count: number;
}

export interface ScanListItem {
  id: string;
  target_name: string;
  input_path: string;
  global_base_score: number;
  global_temporal_score: number;
  severity: Severity;
  total_directives: number;
  total_issues: number;
  total_chains: number;
  host_id: number | null;
  timestamp: string;
}

export interface TrendSeries {
  input_path: string;
  scores: number[];
  timestamps: string[];
  first: number;
  last: number;
  delta: number;
  verdict: string;
  sparkline: string;
}

export interface HostRollup {
  scans: number;
  total_issues: number;
  total_chains: number;
  worst_score: number;
  worst_target: string | null;
  average_score: number;
}

export interface TargetInfo {
  name: string;
  display_name: string;
  version: string;
  benchmark_source: string;
  priority: number;
}

/** A service `live` mode can resolve, from GET /targets/live.
 *  `detected` means its config directory exists where the *server* runs —
 *  false for everything under Docker unless the host's /etc is mounted. */
export interface LiveService {
  service: string;
  plugin: string;
  config_dir: string;
  aliases: string[];
  detected: boolean;
  plugin_installed: boolean;
}

export interface Benchmark {
  name: string;
  version: string;
  benchmark_source: string;
}

export interface HealthResponse {
  status: "ok";
  db_reachable: boolean;
  plugins_registered: number;
}

export interface HostRegistryEntry {
  id: number;
  label: string;
}

export interface DiffResult {
  old_score: number;
  new_score: number;
  score_delta: number;
  resolved: unknown[];
  new_issues: unknown[];
  unchanged: unknown[];
}

// ── Background jobs ───────────────────────────────────────────────────
// Long-running CLI operations (build, plugin install) run as threads
// server-side; the browser polls /jobs/{id} + /jobs/{id}/logs?after=seq.
export type JobStatus = "queued" | "running" | "succeeded" | "failed" | "cancelled";

export interface Job {
  id: string;
  kind: string;
  status: JobStatus;
  params_json: string;
  result_json: string | null;
  error: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface JobLogLine {
  seq: number;
  ts: string;
  line: string;
}

export interface InstalledPlugin {
  name: string;
  display_name: string;
  version: string;
  benchmark_source: string;
}

export interface AvailablePlugin {
  service: string;
  service_name: string;
  sources: { type: string; title: string; format: string }[];
}

export interface PluginsResponse {
  installed: InstalledPlugin[];
  available: AvailablePlugin[];
}

// ── Watch sessions ─────────────────────────────────────────────────────
// `live` is heartbeat-derived (true for any running session, CLI or server).
// `runner_state` is only set for sessions this server process owns — a CLI
// session reports null, and cannot be paused or stopped from the console.
// "failed": a sessão rebentou (ex.: caminho que nenhum plugin reconhece).
export type RunnerState = "running" | "paused" | "stopped" | "failed";

export interface WatchSession {
  watch_session: string;
  target_name: string | null;
  input_path: string | null;
  host_id: number | null;
  global_temporal_score: number;
  severity: string | null;
  total_issues: number;
  total_chains: number;
  watch_interval: number | null;
  timestamp: string | null;
  last_seen: string | null;
  live: boolean;
  runner_state: RunnerState | null;
  /** Preenchido só quando runner_state === "failed". */
  error?: string | null;
}

export interface WatchEvent {
  timestamp: string | null;
  target_name: string | null;
  input_path: string | null;
  global_temporal_score: number;
  severity: string | null;
  total_issues: number;
  total_chains: number;
  watch_interval: number | null;
}

export interface WatchDetail {
  watch_session: string;
  latest: WatchSession;
  events: WatchEvent[];
  sparkline: string;
  first_score: number;
  last_score: number;
}

// ── management surface ────────────────────────────────────────────────

/**
 * The server's *effective* configuration, read-only by design. Note
 * `api_key_required` is a boolean, never the key itself.
 */
export interface ServerSettings {
  caspar_version: string;
  db_path: string;
  plugins_dir: string | null;
  data_dir: string | null;
  api_key_required: boolean;
  registered_plugins: string[];
}

export interface DoctorFinding {
  severity: string;
  category: string;
  message: string;
}

export interface DoctorReport {
  healthy: boolean;
  errors: number;
  warnings: number;
  findings: DoctorFinding[];
}

export interface SuppressionItem {
  directive: string;
  reason: string;
  bad_value: string;
  date: string;
}

/** One line the remediation plan can rewrite automatically. */
export interface FixEdit {
  file: string;
  line_number: number;
  directive: string;
  old_line: string;
  new_line: string;
}

/** A finding the plan cannot rewrite — it needs a human decision. */
export interface FixManualStep {
  directive: string;
  good_value: string;
  reason: string;
  recommendation: string;
  score: number;
}

/**
 * A remediation plan. `applied` is always false over REST: this endpoint
 * never writes to disk, unlike the CLI's `caspar fix --in-place`.
 */
export interface FixPreview {
  /** Null when the scanned file matched no known target plugin. */
  target_name: string | null;
  edits: FixEdit[];
  manual: FixManualStep[];
  diff: string;
  applied: boolean;
}

export interface PromoteStatsRow {
  target: string;
  rules: number;
  promoted: number;
  needs_review: number;
}
