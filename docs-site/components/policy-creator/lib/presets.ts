// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Convert the build-time JSON dump of a bundled preset (default,
// strict, permissive) into a fully-typed Policy ready for the wizard
// to mutate. Values that don't appear in the bundled YAML fall back
// to engine defaults; this keeps the wizard usable even when an
// operator-supplied policy omits an entire section.

import presetsData from '@/data/policy-presets.json';
import type {
  AdmissionConfig,
  AuditConfig,
  CiscoAIDefenseConfig,
  CorrelationClause,
  CorrelationPattern,
  CorrelationSequenceStep,
  DataAxis,
  EnforcementConfig,
  FirewallConfig,
  FirstPartyEntry,
  GuardrailConfig,
  JudgeConfig,
  Policy,
  PresetBundle,
  PresetsFile,
  RulesFile,
  ScannerType,
  SensitiveTool,
  Severity,
  SeverityActionMatrix,
  SeverityActionTriple,
  SeverityUpper,
  SuppressionsBundle,
  ToolCapabilityClass,
  WatchConfig,
} from '../types';
import {
  DATA_AXES,
  SCANNER_TYPES,
  SEVERITIES,
  SEVERITIES_UPPER,
  TOOL_CAPABILITY_CLASSES,
} from '../types';

const TYPED_PRESETS: PresetsFile = presetsData as unknown as PresetsFile;

export function listPresets(): PresetBundle[] {
  return TYPED_PRESETS.presets;
}

export function presetByName(name: 'default' | 'strict' | 'permissive'): PresetBundle | undefined {
  return TYPED_PRESETS.presets.find((p) => p.name === name);
}

const DEFAULT_TRIPLE: SeverityActionTriple = {
  runtime: 'enable',
  file: 'none',
  install: 'none',
};

const STRICT_TRIPLE: SeverityActionTriple = {
  runtime: 'disable',
  file: 'quarantine',
  install: 'block',
};

function readTriple(value: unknown): SeverityActionTriple {
  const o = (value ?? {}) as Partial<SeverityActionTriple>;
  return {
    runtime: o.runtime === 'disable' ? 'disable' : 'enable',
    file: o.file === 'quarantine' ? 'quarantine' : 'none',
    install: o.install === 'block' || o.install === 'allow' ? o.install : 'none',
  };
}

function readSkillActions(raw: unknown): SeverityActionMatrix {
  const r = (raw ?? {}) as Record<Severity, unknown>;
  const out = {} as SeverityActionMatrix;
  for (const sev of SEVERITIES) {
    out[sev] = readTriple(r[sev]);
  }
  return out;
}

function readScannerOverrides(raw: unknown): Policy['scanner_overrides'] {
  const out: Policy['scanner_overrides'] = {};
  const o = (raw ?? {}) as Record<ScannerType, Record<Severity, unknown>>;
  for (const scanner of SCANNER_TYPES) {
    const inner = o[scanner];
    if (!inner) continue;
    const accum: Partial<Record<Severity, SeverityActionTriple>> = {};
    for (const sev of SEVERITIES) {
      if (inner[sev] != null) accum[sev] = readTriple(inner[sev]);
    }
    if (Object.keys(accum).length > 0) out[scanner] = accum;
  }
  return out;
}

function readAdmission(raw: unknown): AdmissionConfig {
  const o = (raw ?? {}) as Partial<AdmissionConfig>;
  return {
    scan_on_install: o.scan_on_install !== false,
    allow_list_bypass_scan: o.allow_list_bypass_scan !== false,
  };
}

function readGuardrail(raw: unknown): GuardrailConfig {
  const o = (raw ?? {}) as Partial<GuardrailConfig> & { hilt?: Partial<GuardrailConfig['hilt']> };
  return {
    block_threshold: clampSeverityRank(o.block_threshold ?? 4),
    alert_threshold: clampSeverityRank(o.alert_threshold ?? 2),
    cisco_trust_level: (['full', 'advisory', 'none'] as const).includes(
      (o.cisco_trust_level ?? 'full') as 'full' | 'advisory' | 'none',
    )
      ? (o.cisco_trust_level as 'full' | 'advisory' | 'none')
      : 'full',
    hilt: {
      enabled: !!o.hilt?.enabled,
      min_severity: (
        (['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as readonly SeverityUpper[]).includes(
          (o.hilt?.min_severity ?? 'HIGH') as SeverityUpper,
        )
          ? o.hilt?.min_severity
          : 'HIGH'
      ) as SeverityUpper,
    },
    patterns: { ...((o.patterns as Record<string, string[]> | undefined) ?? {}) },
    severity_mappings: {
      ...((o.severity_mappings as Record<string, SeverityUpper> | undefined) ?? {}),
    },
  };
}

function clampSeverityRank(n: unknown): 1 | 2 | 3 | 4 {
  const v = Number(n);
  if (v <= 1) return 1;
  if (v <= 2) return 2;
  if (v <= 3) return 3;
  return 4;
}

function readFirewall(raw: unknown): FirewallConfig {
  const o = (raw ?? {}) as Partial<FirewallConfig>;
  return {
    default_action: o.default_action === 'allow' ? 'allow' : 'deny',
    blocked_destinations: Array.isArray(o.blocked_destinations) ? [...o.blocked_destinations] : [],
    allowed_domains: Array.isArray(o.allowed_domains) ? [...o.allowed_domains] : [],
    allowed_ports: Array.isArray(o.allowed_ports) ? [...o.allowed_ports] : [443, 80],
  };
}

function readAudit(raw: unknown): AuditConfig {
  const o = (raw ?? {}) as Partial<AuditConfig>;
  return {
    log_all_actions: o.log_all_actions !== false,
    log_scan_results: o.log_scan_results !== false,
    retention_days: typeof o.retention_days === 'number' ? o.retention_days : 90,
  };
}

function readWatch(raw: unknown): WatchConfig {
  const o = (raw ?? {}) as Partial<WatchConfig>;
  return {
    rescan_enabled: !!o.rescan_enabled,
    rescan_interval_min: typeof o.rescan_interval_min === 'number' ? o.rescan_interval_min : 30,
  };
}

function readEnforcement(raw: unknown): EnforcementConfig {
  const o = (raw ?? {}) as Partial<EnforcementConfig>;
  return {
    max_enforcement_delay_seconds:
      typeof o.max_enforcement_delay_seconds === 'number' ? o.max_enforcement_delay_seconds : 2,
  };
}

function readFirstParty(raw: unknown): FirstPartyEntry[] {
  if (!Array.isArray(raw)) return [];
  return (raw as Array<Partial<FirstPartyEntry>>).map((e) => ({
    target_type: (e.target_type ?? 'plugin') as ScannerType,
    target_name: e.target_name ?? '',
    reason: e.reason ?? '',
    source_path_contains: Array.isArray(e.source_path_contains) ? [...e.source_path_contains] : [],
  }));
}

function readSuppressions(raw: unknown): SuppressionsBundle {
  const o = (raw ?? {}) as Partial<SuppressionsBundle>;
  return {
    pre_judge_strips: Array.isArray(o.pre_judge_strips) ? [...o.pre_judge_strips] : [],
    finding_suppressions: Array.isArray(o.finding_suppressions) ? [...o.finding_suppressions] : [],
    tool_suppressions: Array.isArray(o.tool_suppressions) ? [...o.tool_suppressions] : [],
  };
}

function readSensitiveTools(raw: unknown): SensitiveTool[] {
  const o = (raw ?? {}) as { tools?: unknown };
  if (!Array.isArray(o.tools)) return [];
  return (o.tools as Array<Partial<SensitiveTool>>).map((t) => ({
    name: t.name ?? '',
    result_inspection: !!t.result_inspection,
    judge_result: !!t.judge_result,
    min_entities_for_alert: t.min_entities_for_alert,
  }));
}

function readJudges(raw: unknown): JudgeConfig[] {
  if (!raw || typeof raw !== 'object') return [];
  const out: JudgeConfig[] = [];
  for (const [name, body] of Object.entries(raw as Record<string, unknown>)) {
    const b = body as Partial<JudgeConfig>;
    if (!['pii', 'injection', 'tool-injection', 'exfil'].includes(name)) continue;
    out.push({
      name: name as JudgeConfig['name'],
      enabled: b.enabled !== false,
      system_prompt: b.system_prompt ?? '',
      adjudication_prompt: b.adjudication_prompt,
      min_categories_for_high: b.min_categories_for_high,
      min_categories_for_critical: b.min_categories_for_critical,
      single_category_max_severity: b.single_category_max_severity,
      categories: { ...((b.categories as JudgeConfig['categories']) ?? {}) },
    });
  }
  return out;
}

function readSeverityUpper(value: unknown, fallback: SeverityUpper): SeverityUpper {
  if (typeof value !== 'string') return fallback;
  const upper = value.toUpperCase() as SeverityUpper;
  return (SEVERITIES_UPPER as readonly string[]).includes(upper) ? upper : fallback;
}

function readDataAxis(value: unknown): DataAxis | undefined {
  if (typeof value !== 'string') return undefined;
  return (DATA_AXES as readonly string[]).includes(value) ? (value as DataAxis) : undefined;
}

function readCapabilityClass(value: unknown): ToolCapabilityClass | undefined {
  if (typeof value !== 'string') return undefined;
  return (TOOL_CAPABILITY_CLASSES as readonly string[]).includes(value)
    ? (value as ToolCapabilityClass)
    : undefined;
}

function readCorrelationClause(raw: unknown): CorrelationClause {
  const o = (raw ?? {}) as Record<string, unknown>;
  const clause: CorrelationClause = {};
  const axis = readDataAxis(o.axis);
  if (axis) clause.axis = axis;
  const cap = readCapabilityClass(o.tool_capability_class);
  if (cap) clause.tool_capability_class = cap;
  if (Array.isArray(o.with_rule_match)) {
    const ids = o.with_rule_match.filter((v): v is string => typeof v === 'string' && v.length > 0);
    if (ids.length > 0) clause.with_rule_match = ids;
  }
  // Only honor min_severity when it parses to a real severity level.
  // Garbage strings ("medium-ish", null, 7) fall through to the
  // gateway's default ("any severity") instead of being silently
  // clamped to LOW, which would over-tighten the clause.
  if (typeof o.min_severity === 'string') {
    const upper = o.min_severity.toUpperCase();
    if ((SEVERITIES_UPPER as readonly string[]).includes(upper)) {
      clause.min_severity = upper as SeverityUpper;
    }
  }
  return clause;
}

function readCorrelationPatterns(raw: unknown): CorrelationPattern[] {
  if (!raw || typeof raw !== 'object') return [];
  const o = raw as { patterns?: unknown };
  if (!Array.isArray(o.patterns)) return [];

  const out: CorrelationPattern[] = [];
  for (const entry of o.patterns) {
    if (!entry || typeof entry !== 'object') continue;
    const p = entry as Record<string, unknown>;
    if (typeof p.id !== 'string' || p.id.length === 0) continue;
    const allOf = Array.isArray(p.all_of) ? p.all_of.map(readCorrelationClause) : undefined;
    const fingerprintChain = Array.isArray(p.fingerprint_chain)
      ? p.fingerprint_chain.map(readCorrelationClause)
      : undefined;
    const sequence = Array.isArray(p.sequence)
      ? p.sequence
          .filter((s): s is Record<string, unknown> => !!s && typeof s === 'object')
          .map<CorrelationSequenceStep>((s) => ({
            severity: readSeverityUpper(s.severity, 'MEDIUM'),
          }))
      : undefined;

    out.push({
      id: p.id,
      description: typeof p.description === 'string' ? p.description : '',
      window_events: typeof p.window_events === 'number' && p.window_events > 0
        ? Math.floor(p.window_events)
        : 30,
      severity_on_match: readSeverityUpper(p.severity_on_match, 'CRITICAL'),
      ...(allOf && allOf.length > 0 ? { all_of: allOf } : {}),
      ...(sequence && sequence.length > 0 ? { sequence } : {}),
      ...(fingerprintChain && fingerprintChain.length > 0
        ? { fingerprint_chain: fingerprintChain }
        : {}),
      enabled: p.enabled !== false, // default-on; the bundled YAML doesn't carry this flag today
    });
  }
  return out;
}

function readCiscoAIDefense(raw: unknown): CiscoAIDefenseConfig {
  const o = (raw ?? {}) as Partial<{
    enabled: boolean;
    endpoint: string;
    api_key_env: string;
    scan_hook_surface: boolean;
  }>;
  return {
    // Wizard exposes an explicit on/off knob even though gateway-side
    // the lane no-ops silently when api_key_env is empty. Cleaner UX
    // than "set api_key_env='' to disable".
    enabled: !!o.enabled,
    endpoint: typeof o.endpoint === 'string' ? o.endpoint : '',
    api_key_env: typeof o.api_key_env === 'string' ? o.api_key_env : '',
    // Mirrors CiscoAIDefenseConfig.HookSurfaceEnabled() — default true.
    scan_hook_surface: o.scan_hook_surface !== false,
  };
}

function defaultCiscoAIDefense(): CiscoAIDefenseConfig {
  return { enabled: false, endpoint: '', api_key_env: '', scan_hook_surface: true };
}

function readRulesFiles(raw: unknown): RulesFile[] {
  if (!raw || typeof raw !== 'object') return [];
  const out: RulesFile[] = [];
  for (const [filename, body] of Object.entries(raw as Record<string, unknown>)) {
    const b = body as Partial<RulesFile>;
    out.push({
      filename,
      category: b.category ?? filename,
      rules: Array.isArray(b.rules) ? [...b.rules] : [],
    });
  }
  return out.sort((a, b) => a.filename.localeCompare(b.filename));
}

/** Build a fully-populated Policy from a preset bundle. */
export function policyFromPreset(name: 'default' | 'strict' | 'permissive'): Policy {
  const preset = presetByName(name);
  if (!preset) {
    return blankPolicy(name);
  }
  const policyRaw = (preset.bundle.policy ?? {}) as Record<string, unknown>;
  const guardrailPack = preset.bundle.guardrail;

  return {
    name: 'my-policy',
    description: `Customized from ${name}`,
    basedOn: name,
    admission: readAdmission(policyRaw.admission),
    skill_actions: readSkillActions(policyRaw.skill_actions),
    scanner_overrides: readScannerOverrides(policyRaw.scanner_overrides),
    first_party_allow_list: readFirstParty(policyRaw.first_party_allow_list),
    guardrail: readGuardrail(policyRaw.guardrail),
    rule_pack: { name: 'my-policy', files: readRulesFiles(guardrailPack.rules) },
    suppressions: readSuppressions(guardrailPack.suppressions),
    sensitive_tools: readSensitiveTools(guardrailPack.sensitiveTools),
    judges: readJudges(guardrailPack.judge),
    firewall: readFirewall(policyRaw.firewall),
    webhooks: Array.isArray(policyRaw.webhooks) ? (policyRaw.webhooks as Policy['webhooks']) : [],
    watch: readWatch(policyRaw.watch),
    enforcement: readEnforcement(policyRaw.enforcement),
    audit: readAudit(policyRaw.audit),
    scanners: {},
    custom_rego: [],
    correlator: readCorrelationPatterns(guardrailPack.correlator),
    cisco_ai_defense: readCiscoAIDefense(
      (policyRaw.cisco_ai_defense as unknown) ?? undefined,
    ),
  };
}

function blankPolicy(name: 'default' | 'strict' | 'permissive'): Policy {
  return {
    name: 'my-policy',
    description: 'Custom policy',
    basedOn: name,
    admission: { scan_on_install: true, allow_list_bypass_scan: true },
    skill_actions: {
      critical: STRICT_TRIPLE,
      high: STRICT_TRIPLE,
      medium: DEFAULT_TRIPLE,
      low: DEFAULT_TRIPLE,
      info: DEFAULT_TRIPLE,
    },
    scanner_overrides: {},
    first_party_allow_list: [],
    guardrail: {
      block_threshold: 4,
      alert_threshold: 2,
      cisco_trust_level: 'full',
      hilt: { enabled: false, min_severity: 'HIGH' },
      patterns: {},
      severity_mappings: {},
    },
    rule_pack: { name: 'my-policy', files: [] },
    suppressions: { pre_judge_strips: [], finding_suppressions: [], tool_suppressions: [] },
    sensitive_tools: [],
    judges: [],
    firewall: {
      default_action: 'deny',
      blocked_destinations: ['169.254.169.254', 'fd00:ec2::254'],
      allowed_domains: [],
      allowed_ports: [443, 80],
    },
    webhooks: [],
    watch: { rescan_enabled: true, rescan_interval_min: 30 },
    enforcement: { max_enforcement_delay_seconds: 2 },
    audit: { log_all_actions: true, log_scan_results: true, retention_days: 90 },
    scanners: {},
    custom_rego: [],
    correlator: [],
    cisco_ai_defense: defaultCiscoAIDefense(),
  };
}
