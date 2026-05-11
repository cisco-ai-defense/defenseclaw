// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Strongly-typed schema for the docs-site policy creator. Every field
// here maps 1:1 to a knob the live engine reads; field names match
// what `defenseclaw policy activate` writes to ~/.defenseclaw/policies.
// Keeping a single source of truth in TS lets every section, validator,
// emitter, and Live-Test caller share the same shape.

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SEVERITIES_UPPER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;
export type SeverityUpper = (typeof SEVERITIES_UPPER)[number];

export const SCANNER_TYPES = ['skill', 'mcp', 'plugin'] as const;
export type ScannerType = (typeof SCANNER_TYPES)[number];

export type RuntimeAction = 'enable' | 'disable';
export type FileAction = 'none' | 'quarantine';
export type InstallAction = 'none' | 'allow' | 'block';

export interface SeverityActionTriple {
  runtime: RuntimeAction;
  file: FileAction;
  install: InstallAction;
}

export type SeverityActionMatrix = Record<Severity, SeverityActionTriple>;

export interface AdmissionConfig {
  scan_on_install: boolean;
  allow_list_bypass_scan: boolean;
}

export interface FirstPartyEntry {
  target_type: ScannerType;
  target_name: string;
  reason: string;
  source_path_contains: string[];
}

export type GuardrailCategory = string; // free-form; default catalog ships with injection / secrets / exfiltration

export interface GuardrailHilt {
  enabled: boolean;
  min_severity: SeverityUpper;
}

export interface GuardrailConfig {
  block_threshold: 1 | 2 | 3 | 4;
  alert_threshold: 1 | 2 | 3 | 4;
  cisco_trust_level: 'full' | 'advisory' | 'none';
  hilt: GuardrailHilt;
  patterns: Record<GuardrailCategory, string[]>;
  severity_mappings: Record<GuardrailCategory, SeverityUpper>;
}

// A single regex rule inside a guardrail rule pack file.
export interface RuleDef {
  id: string;
  enabled?: boolean;
  pattern: string;
  title: string;
  severity: SeverityUpper;
  confidence: number; // 0..1
  tags: string[];
}

// One guardrail/<pack>/rules/<filename>.yaml file. Stored under the
// pack name + the file's category (which is also the YAML's `category`
// key today).
export interface RulesFile {
  filename: string; // e.g. "secrets" → emitted as secrets.yaml
  category: string;
  rules: RuleDef[];
}

// Suppression layers from internal/guardrail/rulepack.go.
export interface PreJudgeStrip {
  id: string;
  pattern: string;
  context: string;
  applies_to: Array<'pii' | 'injection' | 'tool-injection' | 'exfil'>;
}

export interface FindingSuppressionDef {
  id: string;
  finding_pattern: string;
  entity_pattern: string;
  condition?: '' | 'is_epoch' | 'is_platform_id';
  reason: string;
}

export interface ToolSuppressionDef {
  tool_pattern: string;
  suppress_findings: string[];
  reason: string;
}

export interface SuppressionsBundle {
  pre_judge_strips: PreJudgeStrip[];
  finding_suppressions: FindingSuppressionDef[];
  tool_suppressions: ToolSuppressionDef[];
}

export interface SensitiveTool {
  name: string;
  result_inspection: boolean;
  judge_result: boolean;
  min_entities_for_alert?: number;
}

export interface JudgeCategoryDef {
  finding_id: string;
  severity?: SeverityUpper;
  severity_default?: SeverityUpper;
  severity_prompt?: SeverityUpper;
  severity_completion?: SeverityUpper;
  enabled: boolean;
}

export interface JudgeConfig {
  name: 'pii' | 'injection' | 'tool-injection' | 'exfil';
  enabled: boolean;
  system_prompt: string;
  adjudication_prompt?: string;
  min_categories_for_high?: number;
  single_category_max_severity?: SeverityUpper;
  categories: Record<string, JudgeCategoryDef>;
}

export interface FirewallConfig {
  default_action: 'allow' | 'deny';
  blocked_destinations: string[];
  allowed_domains: string[];
  allowed_ports: number[];
}

export interface WebhookEntry {
  url: string;
  type: 'slack' | 'webex' | 'pagerduty' | 'generic';
  secret_env?: string;
  room_id?: string;
  min_severity: SeverityUpper;
  events: Array<'block' | 'drift' | 'guardrail'>;
  enabled: boolean;
}

export interface WatchConfig {
  rescan_enabled: boolean;
  rescan_interval_min: number;
}

export interface EnforcementConfig {
  max_enforcement_delay_seconds: number;
}

export interface AuditConfig {
  log_all_actions: boolean;
  log_scan_results: boolean;
  retention_days: number;
}

// Per-scanner overrides. Today each scanner ships its own pack format
// (codeguard, plugin-scanner, skill-scanner). The wizard lets the
// operator pick a profile by name; full inline overrides ship in a
// later phase.
export interface ScannerProfileSelection {
  codeguard?: string; // profile name
  'plugin-scanner'?: string;
  'skill-scanner'?: string;
}

// A custom Rego snippet (Phase 5). Snippets append to the bundled Rego
// at install time. They MUST declare `package defenseclaw.custom.<name>`
// so the bundled modules can reference them via data.defenseclaw.custom.
export interface CustomRegoSnippet {
  name: string; // becomes the filename (custom-<name>.rego)
  package: string; // e.g. "defenseclaw.custom.my_rule"
  source: string;
  description: string;
}

export interface Policy {
  name: string;
  description: string;
  basedOn: 'default' | 'strict' | 'permissive';
  admission: AdmissionConfig;
  skill_actions: SeverityActionMatrix;
  scanner_overrides: Partial<Record<ScannerType, Partial<Record<Severity, SeverityActionTriple>>>>;
  first_party_allow_list: FirstPartyEntry[];
  guardrail: GuardrailConfig;
  rule_pack: {
    name: string; // referenced from the policy.yaml (default: <policy.name>)
    files: RulesFile[];
  };
  suppressions: SuppressionsBundle;
  sensitive_tools: SensitiveTool[];
  judges: JudgeConfig[];
  firewall: FirewallConfig;
  webhooks: WebhookEntry[];
  watch: WatchConfig;
  enforcement: EnforcementConfig;
  audit: AuditConfig;
  scanners: ScannerProfileSelection;
  custom_rego: CustomRegoSnippet[];
}

// --- Validation findings ----------------------------------------------------

export type ValidationLevel = 'error' | 'warning' | 'info';

export interface ValidationFinding {
  level: ValidationLevel;
  code: ValidationCode;
  message: string;
  // Dotted JSON path or section name where the issue lives. The
  // wizard uses this to scroll the user to the right control.
  location: string;
  // Optional fix suggestion the wizard renders inline.
  fix?: string;
}

export type ValidationCode =
  | 'REGEX_INVALID'
  | 'REGEX_RE2_INCOMPAT'
  | 'REGEX_REDOS'
  | 'REGEX_ANCHOR_MISSING'
  | 'ID_DUPLICATE'
  | 'ID_FORMAT'
  | 'SEVERITY_OUT_OF_RANGE'
  | 'SUPP_OVER_BROAD'
  | 'RULE_OVERLAP'
  | 'WEBHOOK_SECRET_MISSING'
  | 'FIREWALL_DEFAULT_DENY_NO_ALLOW'
  | 'SCANNER_OVERRIDE_LOOSER'
  | 'OPA_VERDICT_UNEXPECTED'
  | 'NAME_INVALID'
  | 'CUSTOM_REGO_MISSING_PACKAGE';

// --- Generated build-time types ---------------------------------------------

export interface PresetBundle {
  name: 'default' | 'strict' | 'permissive';
  description: string;
  bundle: {
    name: string;
    description: string;
    policy: Record<string, unknown>;
    guardrail: {
      rules: Record<string, unknown>;
      judge: Record<string, unknown>;
      suppressions: Record<string, unknown> | null;
      sensitiveTools: Record<string, unknown> | null;
    };
    scanners: Record<string, Record<string, Record<string, unknown>>>;
  };
}

export interface PresetsFile {
  generated_at: string;
  presets: PresetBundle[];
}

export interface RecipeKindMap {
  'rule:secrets': RuleDef;
  'rule:injection': RuleDef;
  'rule:exfiltration': RuleDef;
  'rule:command': RuleDef;
  'rule:path': RuleDef;
  'rule:enterprise-data': RuleDef;
  'rule:trust-exploit': RuleDef;
  'rule:cognitive': RuleDef;
  'rule:c2': RuleDef;
  pre_judge_strip: PreJudgeStrip;
  finding_suppression: FindingSuppressionDef;
  tool_suppression: ToolSuppressionDef;
}

export type RecipeKind = keyof RecipeKindMap;

export interface Recipe {
  id: string;
  title: string;
  kind: RecipeKind;
  body: Record<string, unknown>;
  why: string;
  examples: string[];
  counterexamples: string[];
  source: string;
  tags: string[];
}

export interface RecipesFile {
  generated_at: string;
  recipes: Recipe[];
}

export interface Scenario {
  id: string;
  title: string;
  domain: 'admission' | 'guardrail' | 'firewall' | 'audit' | 'skill_actions';
  input: Record<string, unknown>;
  description: string;
  expectedVerdict: string;
}

export interface ScenariosFile {
  generated_at: string;
  scenarios: Scenario[];
}

export interface OpaManifest {
  generated_at: string;
  domains: Array<{
    name: string;
    wasm: string;
    entrypoints: string[];
  }>;
  skipped: string[];
}

export interface OpaResult {
  verdict: string;
  reason?: string;
  raw: unknown;
}
