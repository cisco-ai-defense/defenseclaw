// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Compute a small, human-readable diff between the wizard's current
// Policy and the bundled preset it derived from. We could ship a
// generic deep-diff library, but the wizard only cares about a fixed
// set of high-signal differences — surfacing them as a list of
// "added/removed/changed" strings reads better than a tree.

import type { Policy } from '../types';
import { policyFromPreset } from './presets';

export interface DiffEntry {
  kind: 'added' | 'removed' | 'changed';
  path: string;
  description: string;
}

export function diffAgainstBase(policy: Policy): DiffEntry[] {
  const base = policyFromPreset(policy.basedOn);
  const out: DiffEntry[] = [];

  if (policy.admission.scan_on_install !== base.admission.scan_on_install) {
    out.push({
      kind: 'changed',
      path: 'admission.scan_on_install',
      description: `${base.admission.scan_on_install} → ${policy.admission.scan_on_install}`,
    });
  }
  if (policy.admission.allow_list_bypass_scan !== base.admission.allow_list_bypass_scan) {
    out.push({
      kind: 'changed',
      path: 'admission.allow_list_bypass_scan',
      description: `${base.admission.allow_list_bypass_scan} → ${policy.admission.allow_list_bypass_scan}`,
    });
  }

  for (const sev of ['critical', 'high', 'medium', 'low', 'info'] as const) {
    const bs = base.skill_actions[sev];
    const ps = policy.skill_actions[sev];
    for (const k of ['runtime', 'file', 'install'] as const) {
      if (bs[k] !== ps[k]) {
        out.push({
          kind: 'changed',
          path: `skill_actions.${sev}.${k}`,
          description: `${bs[k]} → ${ps[k]}`,
        });
      }
    }
  }

  for (const scanner of Object.keys(policy.scanner_overrides)) {
    if (!base.scanner_overrides[scanner as keyof typeof base.scanner_overrides]) {
      out.push({
        kind: 'added',
        path: `scanner_overrides.${scanner}`,
        description: 'new override section',
      });
    }
  }

  if (policy.first_party_allow_list.length !== base.first_party_allow_list.length) {
    out.push({
      kind: 'changed',
      path: 'first_party_allow_list',
      description: `${base.first_party_allow_list.length} → ${policy.first_party_allow_list.length} entries`,
    });
  }

  if (policy.guardrail.block_threshold !== base.guardrail.block_threshold) {
    out.push({
      kind: 'changed',
      path: 'guardrail.block_threshold',
      description: `${base.guardrail.block_threshold} → ${policy.guardrail.block_threshold}`,
    });
  }
  if (policy.guardrail.alert_threshold !== base.guardrail.alert_threshold) {
    out.push({
      kind: 'changed',
      path: 'guardrail.alert_threshold',
      description: `${base.guardrail.alert_threshold} → ${policy.guardrail.alert_threshold}`,
    });
  }
  if (policy.guardrail.hilt.enabled !== base.guardrail.hilt.enabled) {
    out.push({
      kind: 'changed',
      path: 'guardrail.hilt.enabled',
      description: `${base.guardrail.hilt.enabled} → ${policy.guardrail.hilt.enabled}`,
    });
  }

  const baseRuleCount = base.rule_pack.files.reduce((acc, f) => acc + f.rules.length, 0);
  const ruleCount = policy.rule_pack.files.reduce((acc, f) => acc + f.rules.length, 0);
  if (baseRuleCount !== ruleCount) {
    out.push({
      kind: 'changed',
      path: 'rule_pack',
      description: `${baseRuleCount} → ${ruleCount} rules`,
    });
  }

  for (const layer of [
    'pre_judge_strips',
    'finding_suppressions',
    'tool_suppressions',
  ] as const) {
    if (policy.suppressions[layer].length !== base.suppressions[layer].length) {
      out.push({
        kind: 'changed',
        path: `suppressions.${layer}`,
        description: `${base.suppressions[layer].length} → ${policy.suppressions[layer].length}`,
      });
    }
  }

  if (policy.firewall.default_action !== base.firewall.default_action) {
    out.push({
      kind: 'changed',
      path: 'firewall.default_action',
      description: `${base.firewall.default_action} → ${policy.firewall.default_action}`,
    });
  }
  if (policy.firewall.allowed_domains.length !== base.firewall.allowed_domains.length) {
    out.push({
      kind: 'changed',
      path: 'firewall.allowed_domains',
      description: `${base.firewall.allowed_domains.length} → ${policy.firewall.allowed_domains.length} entries`,
    });
  }

  if (policy.webhooks.length !== base.webhooks.length) {
    out.push({
      kind: 'changed',
      path: 'webhooks',
      description: `${base.webhooks.length} → ${policy.webhooks.length} entries`,
    });
  }

  if (policy.audit.retention_days !== base.audit.retention_days) {
    out.push({
      kind: 'changed',
      path: 'audit.retention_days',
      description: `${base.audit.retention_days} → ${policy.audit.retention_days}`,
    });
  }

  if (policy.custom_rego.length > 0) {
    out.push({
      kind: 'added',
      path: 'custom_rego',
      description: `${policy.custom_rego.length} custom Rego snippet${policy.custom_rego.length === 1 ? '' : 's'}`,
    });
  }

  return out;
}
