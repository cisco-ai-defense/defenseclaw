// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Project a wizard-state Policy into the OPA `data.json` shape that
// the bundled Rego modules read at evaluation time. This is the
// browser-side port of cli/defenseclaw/commands/cmd_policy.py
// :_sync_opa_data — same logic, same field names, same uppercase
// severity keys, same "enable → allow / disable → block" mapping.

import type {
  CorrelationClause,
  CorrelationPattern,
  Policy,
  ScannerType,
  SeverityActionTriple,
} from '../types';
import { SEVERITIES_UPPER, SCANNER_TYPES } from '../types';

interface OpaActionTriple {
  runtime: 'allow' | 'block';
  file: 'none' | 'quarantine';
  install: 'none' | 'allow' | 'block';
}

function projectAction(t: SeverityActionTriple): OpaActionTriple {
  return {
    runtime: t.runtime === 'disable' ? 'block' : 'allow',
    file: t.file,
    install: t.install,
  };
}

export interface OpaData {
  config: {
    policy_name: string;
    allow_list_bypass_scan: boolean;
    scan_on_install: boolean;
    max_enforcement_delay_seconds: number;
  };
  actions: Record<string, OpaActionTriple>;
  scanner_overrides: Record<string, Record<string, OpaActionTriple>>;
  first_party_allow_list: Array<{
    target_type: string;
    target_name: string;
    reason: string;
    source_path_contains: string[];
  }>;
  severity_ranking: Record<string, number>;
  audit: {
    retention_days: number;
    log_all_actions: boolean;
    log_scan_results: boolean;
  };
  guardrail: {
    severity_rank: Record<string, number>;
    block_threshold: number;
    alert_threshold: number;
    cisco_trust_level: string;
    hilt: { enabled: boolean; min_severity: string };
    patterns: Record<string, string[]>;
    severity_mappings: Record<string, string>;
  };
  firewall: {
    default_action: string;
    blocked_destinations: string[];
    allowed_domains: string[];
    allowed_ports: number[];
  };
  /** Session correlator (Layer 5). Mirrors the YAML schema in
   *  internal/guardrail/defaults/correlation-patterns.yaml so custom
   *  Rego snippets can reason against the same data the live engine
   *  evaluates. */
  correlator: {
    patterns: Array<{
      id: string;
      window_events: number;
      severity_on_match: string;
      all_of?: OpaCorrelationClause[];
      sequence?: Array<{ severity: string }>;
      fingerprint_chain?: OpaCorrelationClause[];
    }>;
  };
  /** Cisco AI Defense lane visibility for Rego policies that want to
   *  branch on whether the hook surface is being scanned. */
  cisco_ai_defense: {
    enabled: boolean;
    api_key_env: string;
    scan_hook_surface: boolean;
  };
}

interface OpaCorrelationClause {
  axis?: string;
  tool_capability_class?: string;
  with_rule_match?: string[];
  min_severity?: string;
}

function projectClause(c: CorrelationClause): OpaCorrelationClause {
  const out: OpaCorrelationClause = {};
  if (c.axis) out.axis = c.axis;
  if (c.tool_capability_class) out.tool_capability_class = c.tool_capability_class;
  if (c.with_rule_match && c.with_rule_match.length > 0) {
    out.with_rule_match = [...c.with_rule_match];
  }
  if (c.min_severity) out.min_severity = c.min_severity;
  return out;
}

function projectCorrelator(patterns: CorrelationPattern[]) {
  return {
    patterns: patterns
      .filter((p) => p.enabled)
      .map((p) => ({
        id: p.id,
        window_events: p.window_events,
        severity_on_match: p.severity_on_match,
        ...(p.all_of && p.all_of.length > 0
          ? { all_of: p.all_of.map(projectClause) }
          : {}),
        ...(p.sequence && p.sequence.length > 0
          ? { sequence: p.sequence.map((s) => ({ severity: s.severity })) }
          : {}),
        ...(p.fingerprint_chain && p.fingerprint_chain.length > 0
          ? { fingerprint_chain: p.fingerprint_chain.map(projectClause) }
          : {}),
      })),
  };
}

export function projectPolicyToData(policy: Policy): OpaData {
  const actions: Record<string, OpaActionTriple> = {};
  for (const sev of SEVERITIES_UPPER) {
    const lower = sev.toLowerCase() as keyof typeof policy.skill_actions;
    actions[sev] = projectAction(policy.skill_actions[lower]);
  }

  const scannerOverrides: Record<string, Record<string, OpaActionTriple>> = {};
  for (const scanner of SCANNER_TYPES as readonly ScannerType[]) {
    const ovr = policy.scanner_overrides[scanner];
    if (!ovr) continue;
    const projected: Record<string, OpaActionTriple> = {};
    for (const sev of SEVERITIES_UPPER) {
      const lower = sev.toLowerCase() as keyof typeof ovr;
      const triple = ovr[lower];
      if (triple) projected[sev] = projectAction(triple);
    }
    if (Object.keys(projected).length > 0) {
      scannerOverrides[scanner] = projected;
    }
  }

  return {
    config: {
      policy_name: policy.name || 'custom',
      allow_list_bypass_scan: policy.admission.allow_list_bypass_scan,
      scan_on_install: policy.admission.scan_on_install,
      max_enforcement_delay_seconds: policy.enforcement.max_enforcement_delay_seconds,
    },
    actions,
    scanner_overrides: scannerOverrides,
    first_party_allow_list: policy.first_party_allow_list,
    severity_ranking: { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 },
    audit: {
      retention_days: policy.audit.retention_days,
      log_all_actions: policy.audit.log_all_actions,
      log_scan_results: policy.audit.log_scan_results,
    },
    guardrail: {
      severity_rank: { NONE: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 },
      block_threshold: policy.guardrail.block_threshold,
      alert_threshold: policy.guardrail.alert_threshold,
      cisco_trust_level: policy.guardrail.cisco_trust_level,
      hilt: { ...policy.guardrail.hilt },
      patterns: { ...policy.guardrail.patterns },
      severity_mappings: { ...policy.guardrail.severity_mappings },
    },
    firewall: {
      default_action: policy.firewall.default_action,
      blocked_destinations: [...policy.firewall.blocked_destinations],
      allowed_domains: [...policy.firewall.allowed_domains],
      allowed_ports: [...policy.firewall.allowed_ports],
    },
    correlator: projectCorrelator(policy.correlator ?? []),
    cisco_ai_defense: {
      // Defensive defaults match CiscoAIDefenseConfig defaults in
      // presets.ts. Hydration boundaries (PolicyCreator, share decode)
      // run normalizeImportedPolicy and SHOULD have backfilled these;
      // belt-and-suspenders so stale state can't crash data projection.
      enabled: policy.cisco_ai_defense?.enabled ?? false,
      api_key_env: policy.cisco_ai_defense?.api_key_env ?? '',
      scan_hook_surface: policy.cisco_ai_defense?.scan_hook_surface ?? true,
    },
  };
}
