// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Pure function that turns Quick Start interview answers into a fully-
// realized Policy object. Re-runs on every answer change so the
// playground/right-rail summary stays in sync.
//
// Idempotent: same answers in → same Policy out. We always start from
// a clean preset (per the user's posture choice) and apply mutations
// on top, so a previously-applied answer that gets unchecked is
// undone naturally.

import type {
  Policy,
  RuleDef,
  ToolSuppressionDef,
  WebhookEntry,
} from '../types';
import { policyFromPreset } from '../lib/presets';
import {
  ALLOW_CARDS,
  BLOCK_CARDS,
  RESPONSES,
  SINK_CARDS,
  type Answers,
  type SinkAnswer,
} from './questions';

/**
 * Apply Quick Start answers on top of the chosen base preset.
 *
 * The mapping is intentionally additive on the rule-pack side: we
 * enable rules that match the operator's `block` cards but never
 * disable a rule that already shipped enabled in the preset. The
 * "block more / allow more" framing fits the user's mental model
 * better than "I'm overriding a curated default" each time.
 */
export function applyAnswers(answers: Answers): Policy {
  const policy = policyFromPreset(answers.posture);

  // --- Q2: BLOCK ----------------------------------------------------------

  const enabledRuleIds = new Set<string>();
  const newDestinations = new Set<string>();
  const forcedCorrelatorIds = new Set<string>();
  for (const cardId of answers.block) {
    const card = BLOCK_CARDS.find((c) => c.id === cardId);
    if (!card) continue;
    for (const rid of card.ruleIds) enabledRuleIds.add(rid);
    for (const dest of card.destinations ?? []) newDestinations.add(dest);
    if (card.guardrailPatterns) {
      for (const gp of card.guardrailPatterns) {
        const existing = policy.guardrail.patterns[gp.category] ?? [];
        policy.guardrail.patterns[gp.category] = Array.from(
          new Set([...existing, ...gp.patterns]),
        );
        policy.guardrail.severity_mappings[gp.category] = gp.severity;
      }
    }
    for (const cid of card.correlatorPatternIds ?? []) forcedCorrelatorIds.add(cid);
  }
  // Layer-5 cards force the named correlator patterns to enabled even if
  // they were disabled in the playground. Patterns not referenced by any
  // card retain whatever state the preset shipped (almost always enabled).
  if (forcedCorrelatorIds.size > 0) {
    policy.correlator = policy.correlator.map((p) =>
      forcedCorrelatorIds.has(p.id) ? { ...p, enabled: true } : p,
    );
  }
  // Walk every rule in every loaded pack file and force `enabled=true`
  // for those whose id appears in the user's selected cards. Rules
  // not referenced by any card are left in whatever state the preset
  // shipped (typically enabled).
  for (const file of policy.rule_pack.files) {
    file.rules = file.rules.map((r): RuleDef => {
      if (enabledRuleIds.has(r.id)) return { ...r, enabled: true };
      return r;
    });
  }
  // Add card-supplied destinations that aren't already blocked.
  policy.firewall.blocked_destinations = Array.from(
    new Set([...policy.firewall.blocked_destinations, ...newDestinations]),
  );

  // --- Q3: ALLOW ----------------------------------------------------------

  const newToolSupps: ToolSuppressionDef[] = [];
  const newDomains = new Set<string>(answers.domainsExtra.map((d) => d.trim()).filter(Boolean));
  const newFirstParty = new Set<string>(
    answers.firstPartyExtra.map((d) => d.trim()).filter(Boolean),
  );

  for (const cardId of answers.allow) {
    const card = ALLOW_CARDS.find((c) => c.id === cardId);
    if (!card) continue;
    if (card.toolPattern && card.suppressFindings && card.suppressFindings.length > 0) {
      newToolSupps.push({
        tool_pattern: card.toolPattern,
        suppress_findings: [...card.suppressFindings],
        reason: card.title,
      });
    }
    for (const d of card.domains ?? []) newDomains.add(d);
    for (const fp of card.firstParty ?? []) newFirstParty.add(fp);
  }
  // Dedupe by tool_pattern so re-running with the same answers doesn't
  // add duplicates (the operator might toggle, untoggle, retoggle).
  policy.suppressions.tool_suppressions = dedupBy(
    [...policy.suppressions.tool_suppressions, ...newToolSupps],
    (s) => s.tool_pattern,
  );
  policy.firewall.allowed_domains = Array.from(
    new Set([...policy.firewall.allowed_domains, ...newDomains]),
  );
  // First-party allow list expects {target_type, target_name, reason}
  // entries; the Quick Start only collects target_name globs so we
  // default target_type to 'plugin' (the broadest), matching how the
  // bundled allow list ships.
  for (const glob of newFirstParty) {
    if (policy.first_party_allow_list.some((e) => e.target_name === glob)) continue;
    policy.first_party_allow_list.push({
      target_type: 'plugin',
      target_name: glob,
      reason: 'Added via Quick Start',
      source_path_contains: [],
    });
  }

  // --- Q4: response posture ----------------------------------------------

  const resp = RESPONSES.find((r) => r.id === answers.response) ?? RESPONSES[1];
  policy.guardrail.block_threshold = resp.block_threshold;
  policy.guardrail.alert_threshold = resp.alert_threshold;
  policy.guardrail.hilt = {
    enabled: resp.hilt_enabled,
    min_severity: resp.hilt_min,
  };
  // Skill actions: response posture also tightens / loosens the
  // install column. "block" → block at MEDIUM, "ask" → ask at MEDIUM,
  // log_only / alert → leave the preset's defaults alone.
  if (resp.id === 'block') {
    policy.skill_actions.medium = { ...policy.skill_actions.medium, install: 'block' };
    policy.skill_actions.high = { ...policy.skill_actions.high, install: 'block' };
    policy.skill_actions.critical = { ...policy.skill_actions.critical, install: 'block' };
  }

  // --- Q5: sinks ----------------------------------------------------------

  const newWebhooks: WebhookEntry[] = [];
  for (const cardId of Object.keys(answers.sinks)) {
    const ans = answers.sinks[cardId];
    if (!ans?.enabled) continue;
    const card = SINK_CARDS.find((c) => c.id === cardId);
    if (!card) continue;
    if (cardId === 'local_file') {
      // The audit log is always-on at the audit config layer; nothing
      // to write into webhooks. Just make sure the audit config
      // reflects the operator's intent.
      policy.audit.log_all_actions = true;
      policy.audit.log_scan_results = true;
      continue;
    }
    if (cardId === 'stdout') {
      // stdout is a runtime knob (DEFENSECLAW_LOG=stdout) rather than
      // a webhook entry; we can't capture it in the policy directly,
      // but flipping log_all_actions ensures the gateway emits events
      // that the host shipper can pick up.
      policy.audit.log_all_actions = true;
      continue;
    }
    if (!card.type) continue;
    if (!isValidSink(ans)) continue;
    newWebhooks.push({
      url: ans.url.trim(),
      type: card.type,
      secret_env: ans.secret_env.trim() || undefined,
      min_severity: 'HIGH',
      events: ['block', 'guardrail'],
      enabled: true,
    });
  }
  // De-dupe by URL so toggling on/off doesn't pile up entries.
  policy.webhooks = dedupBy([...policy.webhooks, ...newWebhooks], (w) => w.url);

  return policy;
}

function isValidSink(s: SinkAnswer): boolean {
  if (!s.enabled) return false;
  if (!s.url || !/^https?:\/\//i.test(s.url.trim())) return false;
  return true;
}

function dedupBy<T>(items: T[], key: (item: T) => string): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const item of items) {
    const k = key(item);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(item);
  }
  return out;
}
