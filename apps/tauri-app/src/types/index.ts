// Core severity levels for findings and alerts
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

// Subsystem health status
export interface SubsystemHealth {
  state: 'starting' | 'running' | 'reconnecting' | 'stopped' | 'error' | 'disabled';
  since: string; // ISO timestamp
  details?: Record<string, unknown>;
}

// Overall health snapshot from sidecar
export interface HealthSnapshot {
  started_at: string; // ISO timestamp
  uptime_ms: number;
  gateway: SubsystemHealth;
  watcher: SubsystemHealth;
  api: SubsystemHealth;
  guardrail: SubsystemHealth;
  telemetry: SubsystemHealth;
  splunk: SubsystemHealth;
}

// Alert from audit log
export interface Alert {
  id: string;
  timestamp: string; // ISO timestamp
  severity: Severity;
  source: string; // e.g., "skill-scanner", "mcp-scanner", "enforce"
  category: string; // e.g., "scan", "block", "quarantine"
  message: string;
  details?: Record<string, unknown>;
}

// Skill definition
export interface Skill {
  id: string;
  name: string;
  path: string;
  source: 'workspace' | 'user' | 'global';
  status: 'active' | 'blocked' | 'quarantined';
  scanStatus?: 'clean' | 'suspicious' | 'malicious';
  lastScanned?: string; // ISO timestamp
}

// MCP Server definition
export interface MCPServer {
  id: string;
  name: string;
  command: string;
  args: string[];
  env?: Record<string, string>;
  status: 'active' | 'blocked' | 'quarantined';
  scanStatus?: 'clean' | 'suspicious' | 'malicious';
  lastScanned?: string; // ISO timestamp
}

// Tool entry from inventory
export interface ToolEntry {
  name: string;
  source: 'skill' | 'mcp' | 'builtin';
  description?: string;
  parameters?: Record<string, unknown>;
}

// Scan result finding
export interface Finding {
  severity: Severity;
  category: string; // e.g., "code-injection", "network-call", "file-access"
  message: string;
  location?: string; // File path or line number
  evidence?: string; // Code snippet or pattern match
  recommendation?: string;
}

// Scan result
export interface ScanResult {
  target: string; // Path or identifier
  targetType: 'skill' | 'mcp-server' | 'tool';
  timestamp: string; // ISO timestamp
  scanner: string; // e.g., "skill-scanner", "mcp-scanner", "codeguard"
  status: 'clean' | 'suspicious' | 'malicious';
  findings: Finding[];
  metadata?: Record<string, unknown>;
}

// Guardrail configuration
export interface GuardrailConfig {
  enabled: boolean;
  scanOnInstall: boolean;
  blockHighSeverity: boolean;
  quarantineSuspicious: boolean;
  allowList: string[]; // Paths or identifiers
  blockList: string[]; // Paths or identifiers
}
