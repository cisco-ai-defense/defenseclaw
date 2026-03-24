export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

export function compareSeverity(a: Severity, b: Severity): number {
  return (SEVERITY_RANK[a] ?? 0) - (SEVERITY_RANK[b] ?? 0);
}

export function maxSeverity(items: readonly Severity[]): Severity {
  let max: Severity = "INFO";
  for (const s of items) {
    if (compareSeverity(s, max) > 0) max = s;
  }
  return max;
}

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  location?: string;
  remediation?: string;
  scanner: string;
  tags?: string[];
}

export interface ScanMetadata {
  manifest_name?: string;
  manifest_version?: string;
  file_count: number;
  total_size_bytes: number;
  has_lockfile: boolean;
  has_install_scripts: boolean;
  detected_capabilities: string[];
}

export interface ScanResult {
  scanner: string;
  target: string;
  timestamp: string;
  findings: Finding[];
  duration_ns?: number;
  metadata?: ScanMetadata;
}

export interface ScanReport {
  results: ScanResult[];
  max_severity: Severity;
  total_findings: number;
  clean: boolean;
  errors?: string[];
}

export type InstallType = "skill" | "mcp" | "plugin";

export type Verdict =
  | "blocked"
  | "allowed"
  | "clean"
  | "rejected"
  | "warning"
  | "scan-error";

export interface AdmissionResult {
  type: InstallType;
  name: string;
  path: string;
  verdict: Verdict;
  reason: string;
  timestamp: string;
}

export interface BlockEntry {
  id: string;
  target_type: string;
  target_name: string;
  reason: string;
  created_at: string;
}

export interface AllowEntry {
  id: string;
  target_type: string;
  target_name: string;
  reason: string;
  created_at: string;
}

export interface DaemonStatus {
  running: boolean;
  uptime_seconds?: number;
  connectors?: Record<string, ConnectorHealth>;
}

export interface ConnectorHealth {
  name: string;
  status: "healthy" | "degraded" | "unhealthy" | "stopped";
  message?: string;
  last_check?: string;
}

export interface PluginManifest {
  name: string;
  version?: string;
  description?: string;
  permissions?: string[];
  tools?: ToolManifest[];
  commands?: CommandManifest[];
  dependencies?: Record<string, string>;
  scripts?: Record<string, string>;
  source?: string;
}

export interface ToolManifest {
  name: string;
  description?: string;
  parameters?: Record<string, unknown>;
  permissions?: string[];
}

export interface CommandManifest {
  name: string;
  description?: string;
  args?: Array<{ name: string; required?: boolean }>;
}

export interface MCPServerConfig {
  name: string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  transport?: "stdio" | "http" | "sse";
  tools?: ToolManifest[];
  enabled?: boolean;
}
