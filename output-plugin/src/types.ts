/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

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

export interface TaxonomyRef {
  objective: string;      // e.g. "OB-009"
  technique: string;      // e.g. "AITech-9.3"
  sub_technique?: string; // e.g. "AISubtech-9.3.1"
}

export interface Finding {
  id: string;
  rule_id?: string;
  severity: Severity;
  confidence?: number;
  title: string;
  description: string;
  evidence?: string;
  location?: string;
  remediation?: string;
  scanner: string;
  tags?: string[];
  taxonomy?: TaxonomyRef;
  occurrence_count?: number;
  suppressed?: boolean;
  suppression_reason?: string;
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

export type CategoryStatus = "pass" | "info" | "warn" | "fail";

export interface AssessmentCategory {
  name: string;
  status: CategoryStatus;
  summary: string;
}

export type ScanVerdict = "benign" | "suspicious" | "malicious" | "unknown";

export interface Assessment {
  verdict: ScanVerdict;
  confidence: number;
  summary: string;
  categories: AssessmentCategory[];
}

export interface ScanResult {
  scanner: string;
  target: string;
  timestamp: string;
  findings: Finding[];
  duration_ns?: number;
  metadata?: ScanMetadata;
  assessment?: Assessment;
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
  updated_at: string;
}

export interface AllowEntry {
  id: string;
  target_type: string;
  target_name: string;
  reason: string;
  updated_at: string;
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

export type ScanProfile = "default" | "strict";

export interface PluginScanOptions {
  profile?: ScanProfile;
  /** Policy preset name ("default", "strict", "permissive") or path to YAML policy file. */
  policy?: string;
}

/**
 * Correlates plugin↔sidecar traffic for observability and agent registry mapping.
 * Field names use camelCase; HTTP headers use the X-DefenseClaw-* spellings.
 */
export interface CorrelationContext {
  runId?: string;
  sessionId?: string;
  /** Logical agent id for `X-DefenseClaw-Agent-Id` (config, env, or persisted stable id). */
  agentId: string;
  /** Per–extension-session instance id minted by the plugin; may converge with the sidecar echo. */
  agentInstanceId?: string;
  /** Echoed from the sidecar (`X-DefenseClaw-Sidecar-Instance-Id` response header). */
  sidecarInstanceId?: string;
  traceId?: string;
  agentName?: string;
  policyId?: string;
}

/** Structured log line for outbound sidecar HTTP requests (retain_plugin_logs). */
export interface OutboundSidecarRequestLog {
  runId?: string;
  sessionId?: string;
  agentId: string;
  status_code: number;
  duration_ms: number;
}
