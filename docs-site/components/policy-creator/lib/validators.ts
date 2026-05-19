// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Browser-side regex + policy validators. Two layers:
//
// 1) Compile-test the pattern with V8 to catch syntax errors and run
//    the operator's "match" / "no-match" examples through it.
// 2) Static lint for RE2 incompatibilities (Go's regexp package, used
//    by the engine, is RE2-based — no lookaround, no backreferences,
//    no possessive quantifiers, no atomic groups) plus a cheap
//    catastrophic-backtracking heuristic and an anchor sanity check.
//
// The full RE2 round-trip (via re2-wasm) is intentionally NOT loaded
// here — v1 of the wizard uses pattern lints that catch every feature
// gap we've actually seen in production rule packs without paying the
// 700KB re2-wasm download. We can layer it in later behind a button.

import type { Policy, RuleDef, ValidationCode, ValidationFinding } from '../types';

export interface RegexLintResult {
  compiled: boolean;
  error: string | null;
  // Lint findings the wizard renders inline next to the regex input.
  findings: ValidationFinding[];
}

// Translate a Go RE2 pattern to something V8's RegExp can compile.
//
// RE2 supports inline flag groups at the start of a pattern — `(?i)foo`,
// `(?ims)foo` — that V8 rejects with "Invalid group". JS expresses the
// same thing as a separate flags arg to `new RegExp(pattern, flags)`.
//
// We also collapse any *consecutive* leading flag groups (`(?i)(?m)foo`)
// because RE2 treats them as additive. We do NOT touch mid-pattern flag
// scopes like `(?i:foo)` — those are RE2-only and we let the V8 compile
// fail naturally so the operator still sees the lint error.
//
// Returns the translated pattern + the JS flag set so the caller can
// pass both to `new RegExp(...)`.
function toV8(pattern: string, extraFlags: string): { pattern: string; flags: string } {
  let p = pattern;
  const flagSet = new Set(extraFlags.split(''));
  for (;;) {
    const m = p.match(/^\(\?([ims]+)\)/);
    if (!m) break;
    for (const ch of m[1]) flagSet.add(ch);
    p = p.slice(m[0].length);
  }
  return { pattern: p, flags: Array.from(flagSet).join('') };
}

// Patterns Go's regexp/syntax explicitly does not support. Listed by
// order of likelihood so we can give a useful diagnostic on the first
// match. See https://github.com/google/re2/wiki/Syntax for the RE2
// reference and Go's regexp/syntax for the engine's implementation.
const RE2_INCOMPAT: Array<{ probe: RegExp; label: string }> = [
  { probe: /\(\?=|\(\?!|\(\?<=|\(\?<!/, label: 'lookaround (?=, ?!, ?<=, ?<!) is not supported by RE2' },
  { probe: /\\[1-9]/, label: 'backreferences (\\1, \\2 …) are not supported by RE2' },
  { probe: /\(\?>/, label: 'atomic groups (?>) are not supported by RE2' },
  { probe: /[*+?]\+/, label: 'possessive quantifiers (*+, ++, ?+) are not supported by RE2' },
  { probe: /\\k</, label: 'named backreferences (\\k<…>) are not supported by RE2' },
];

const REDOS_ANTIPATTERNS: Array<{ probe: RegExp; label: string }> = [
  // (X+)+, (X*)+, (X+)*  — the classic exponential backtracking shape.
  { probe: /\([^()]*[+*]\)[+*]/, label: 'nested quantifier shape ((..+)+) is prone to catastrophic backtracking' },
  // Disjunction whose alternatives all match the same prefix
  // (a|aa|aaa)+ — secondary check that fires conservatively.
  { probe: /\(([^()|]+\|){2,}[^()]*\)[+*]/, label: 'overlapping alternation under a quantifier may explode on adversarial input' },
];

export function lintRegex(pattern: string): RegexLintResult {
  const findings: ValidationFinding[] = [];
  let compiled = false;
  let error: string | null = null;

  if (!pattern) {
    return {
      compiled: false,
      error: 'pattern is empty',
      findings: [
        {
          level: 'error',
          code: 'REGEX_INVALID',
          message: 'Pattern cannot be empty.',
          location: 'pattern',
        },
      ],
    };
  }

  // 1) Compile in V8 — translate RE2 inline flag groups (`(?i)`, `(?ims)`)
  //    to JS flags first so we don't false-flag valid Go patterns.
  try {
    const v8 = toV8(pattern, '');
    new RegExp(v8.pattern, v8.flags);
    compiled = true;
  } catch (err) {
    error = err instanceof Error ? err.message : String(err);
    findings.push({
      level: 'error',
      code: 'REGEX_INVALID',
      message: error,
      location: 'pattern',
    });
  }

  // 2) RE2 incompatibility lint (always run — even if V8 accepted it,
  //    Go's regexp will still reject lookaround / backrefs).
  for (const probe of RE2_INCOMPAT) {
    if (probe.probe.test(pattern)) {
      findings.push({
        level: 'error',
        code: 'REGEX_RE2_INCOMPAT',
        message: probe.label,
        location: 'pattern',
        fix: 'Re-author without that feature; the engine compiles patterns with Go\'s regexp (RE2).',
      });
    }
  }

  // 3) ReDoS heuristic.
  for (const probe of REDOS_ANTIPATTERNS) {
    if (probe.probe.test(pattern)) {
      findings.push({
        level: 'warning',
        code: 'REGEX_REDOS',
        message: probe.label,
        location: 'pattern',
        fix: 'Tighten the inner quantifier so each character is consumed by exactly one alternative.',
      });
    }
  }

  // 4) Anchor sanity. Patterns intended to bind a token to a known
  //    boundary are far less prone to false positives. We warn (not
  //    error) when neither anchor nor word-boundary appears anywhere.
  if (!/[\^$]|\\b|\\A|\\z/.test(pattern)) {
    findings.push({
      level: 'info',
      code: 'REGEX_ANCHOR_MISSING',
      message: 'Pattern has no anchors (^, $, \\b). It will match anywhere in the input.',
      location: 'pattern',
      fix: 'If the secret/identifier has a known prefix, anchor with ^ or \\b to reduce false positives.',
    });
  }

  return { compiled, error, findings };
}

export interface RegexTestResult {
  text: string;
  expected: 'match' | 'no-match';
  actual: 'match' | 'no-match' | 'error';
  detail?: string;
}

export function testRegex(
  pattern: string,
  flags: string,
  examples: string[],
  counterexamples: string[],
): RegexTestResult[] {
  const out: RegexTestResult[] = [];
  let re: RegExp | null = null;
  try {
    const v8 = toV8(pattern, flags);
    re = new RegExp(v8.pattern, v8.flags);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    for (const text of [...examples, ...counterexamples]) {
      out.push({
        text,
        expected: examples.includes(text) ? 'match' : 'no-match',
        actual: 'error',
        detail,
      });
    }
    return out;
  }

  for (const text of examples) {
    out.push({
      text,
      expected: 'match',
      actual: re.test(text) ? 'match' : 'no-match',
    });
  }
  for (const text of counterexamples) {
    out.push({
      text,
      expected: 'no-match',
      actual: re.test(text) ? 'match' : 'no-match',
    });
  }
  return out;
}

// Validate the entire policy. Used by the bottom bar's "issues" tray
// and the per-section status dots. Order matters: callers iterate the
// returned findings to compute the section status badges.
export function validatePolicy(policy: Policy): ValidationFinding[] {
  const findings: ValidationFinding[] = [];

  if (!policy.name || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(policy.name)) {
    findings.push({
      level: 'error',
      code: 'NAME_INVALID',
      message: 'Policy name must match [a-z0-9][a-z0-9-]{0,63}.',
      location: 'basics.name',
    });
  }

  // Rules: dedupe, validate IDs, lint patterns.
  const seenIds = new Set<string>();
  for (const file of policy.rule_pack.files) {
    for (const rule of file.rules) {
      if (!rule.id) {
        findings.push({
          level: 'error',
          code: 'ID_FORMAT',
          message: `Rule in ${file.filename}.yaml is missing an id.`,
          location: `rules.${file.filename}`,
        });
        continue;
      }
      if (seenIds.has(rule.id)) {
        findings.push({
          level: 'error',
          code: 'ID_DUPLICATE',
          message: `Duplicate rule id "${rule.id}".`,
          location: `rules.${file.filename}.${rule.id}`,
          fix: 'Each rule id must be unique across every rule pack file.',
        });
      } else {
        seenIds.add(rule.id);
      }
      if (!/^[A-Z][A-Z0-9_-]{2,63}$/.test(rule.id)) {
        findings.push({
          level: 'warning',
          code: 'ID_FORMAT',
          message: `Rule id "${rule.id}" should be UPPER_SNAKE_OR_DASH (e.g. SEC-AWS-KEY).`,
          location: `rules.${file.filename}.${rule.id}`,
        });
      }
      const lint = lintRegex(rule.pattern);
      for (const f of lint.findings) {
        findings.push({ ...f, location: `rules.${file.filename}.${rule.id}` });
      }
    }
  }

  // Suppressions: warn on overly broad finding patterns.
  for (const supp of policy.suppressions.finding_suppressions) {
    if (
      !supp.finding_pattern ||
      supp.finding_pattern === '.*' ||
      supp.finding_pattern === '.+' ||
      supp.finding_pattern === '^.*$'
    ) {
      findings.push({
        level: 'warning',
        code: 'SUPP_OVER_BROAD',
        message: `Suppression "${supp.id || '(unnamed)'}" matches every finding. This will silence real signals.`,
        location: `suppressions.finding.${supp.id}`,
        fix: 'Scope the pattern to a finding ID prefix (e.g. ^SEC-AWS-) or specific judge category.',
      });
    }
  }
  for (const tool of policy.suppressions.tool_suppressions) {
    if (
      !tool.tool_pattern ||
      tool.tool_pattern === '.*' ||
      tool.tool_pattern === '.+' ||
      tool.tool_pattern === '^.*$'
    ) {
      findings.push({
        level: 'warning',
        code: 'SUPP_OVER_BROAD',
        message: `Tool suppression matches every tool. This will silence every finding on every tool.`,
        location: `suppressions.tool`,
        fix: 'Scope the regex (e.g. ^(shell|bash)\\.execute$).',
      });
    }
  }

  // Firewall: default-deny with no allow list is a footgun.
  if (
    policy.firewall.default_action === 'deny' &&
    policy.firewall.allowed_domains.length === 0
  ) {
    findings.push({
      level: 'warning',
      code: 'FIREWALL_DEFAULT_DENY_NO_ALLOW',
      message:
        'Firewall default is "deny" but no allowed_domains are configured. Every outbound call from a sandboxed plugin will fail.',
      location: 'firewall.default_action',
      fix: 'Either flip default_action to "allow" with an explicit blocked_destinations list, or add the domains your sandboxed code legitimately needs.',
    });
  }

  // Scanner overrides should not be looser than the base.
  for (const [scanner, overrides] of Object.entries(policy.scanner_overrides)) {
    if (!overrides) continue;
    for (const [sev, triple] of Object.entries(overrides)) {
      const base = policy.skill_actions[sev as keyof typeof policy.skill_actions];
      if (!triple || !base) continue;
      if (base.install === 'block' && triple.install !== 'block') {
        findings.push({
          level: 'warning',
          code: 'SCANNER_OVERRIDE_LOOSER',
          message: `Scanner "${scanner}" allows install at ${sev.toUpperCase()} even though base policy blocks it.`,
          location: `severity-matrix.${scanner}.${sev}.install`,
        });
      }
      if (base.runtime === 'disable' && triple.runtime !== 'disable') {
        findings.push({
          level: 'warning',
          code: 'SCANNER_OVERRIDE_LOOSER',
          message: `Scanner "${scanner}" leaves runtime enabled at ${sev.toUpperCase()} even though base policy disables it.`,
          location: `severity-matrix.${scanner}.${sev}.runtime`,
        });
      }
    }
  }

  // Webhook secrets should reference an env var.
  for (const wh of policy.webhooks) {
    if (wh.enabled && !wh.secret_env) {
      findings.push({
        level: 'warning',
        code: 'WEBHOOK_SECRET_MISSING',
        message: `Webhook ${wh.url} is enabled but has no secret_env. Inbound deliveries can't be verified.`,
        location: 'webhooks',
        fix: 'Add the env-var name (e.g. SLACK_WEBHOOK_SECRET) so the dispatcher can sign requests.',
      });
    }
  }

  // Custom Rego must declare a package.
  for (const snippet of policy.custom_rego) {
    if (!snippet.source.includes('package ')) {
      findings.push({
        level: 'error',
        code: 'CUSTOM_REGO_MISSING_PACKAGE',
        message: `Custom Rego snippet "${snippet.name}" must declare a "package defenseclaw.custom.<name>" line.`,
        location: `custom_rego.${snippet.name}`,
      });
    }
  }

  // Session correlator: catch patterns that can never match (no
  // clauses on any of the three match modes), and reject impossible
  // window sizes. Disabled patterns are skipped so an operator
  // parking a draft doesn't drown in errors.
  const seenPatternIds = new Set<string>();
  for (const p of policy.correlator) {
    if (!p.enabled) continue;
    if (seenPatternIds.has(p.id)) {
      findings.push({
        level: 'error',
        code: 'ID_DUPLICATE',
        message: `Correlator pattern id "${p.id}" appears more than once. IDs are the join key for promoted CORR-* findings; duplicates collide in audit logs.`,
        location: `correlator.${p.id}`,
      });
    } else {
      seenPatternIds.add(p.id);
    }
    const allOf = p.all_of?.length ?? 0;
    const seq = p.sequence?.length ?? 0;
    const fp = p.fingerprint_chain?.length ?? 0;
    if (allOf + seq + fp === 0) {
      findings.push({
        level: 'error',
        code: 'CORRELATOR_PATTERN_EMPTY',
        message: `Correlator pattern "${p.id}" has no clauses on any match mode. It will never fire.`,
        location: `correlator.${p.id}`,
        fix: 'Add at least one clause under all_of, sequence, or fingerprint_chain — or disable the pattern.',
      });
    }
    if (!Number.isInteger(p.window_events) || p.window_events <= 0) {
      findings.push({
        level: 'error',
        code: 'CORRELATOR_WINDOW_INVALID',
        message: `Correlator pattern "${p.id}" has window_events=${p.window_events}. Must be a positive integer.`,
        location: `correlator.${p.id}.window_events`,
      });
    } else if (p.window_events > 1000) {
      findings.push({
        level: 'warning',
        code: 'CORRELATOR_WINDOW_INVALID',
        message: `Correlator pattern "${p.id}" window_events=${p.window_events} is very large. The session buffer caps at a few hundred findings; values above that effectively mean "the whole session".`,
        location: `correlator.${p.id}.window_events`,
      });
    }
  }

  // Cisco AI Defense: when the operator enables the lane, demand an
  // env-var-shaped reference (UPPER_SNAKE) — not a literal key value.
  // The wizard never accepts inline secrets, but a paste-in-haste can
  // smuggle one through if we don't lint here.
  const aid = policy.cisco_ai_defense;
  if (aid.enabled || aid.api_key_env || aid.endpoint) {
    if (!aid.api_key_env) {
      findings.push({
        level: 'warning',
        code: 'CISCO_AID_KEY_ENV_MISSING',
        message:
          'Cisco AI Defense block is populated but api_key_env is empty. The gateway will skip the AID lane silently until an env-var name is supplied.',
        location: 'cisco_ai_defense.api_key_env',
        fix: 'Set api_key_env to the env var the gateway should read (e.g. CISCO_AI_DEFENSE_API_KEY).',
      });
    } else if (!/^[A-Z_][A-Z0-9_]{2,63}$/.test(aid.api_key_env)) {
      findings.push({
        level: 'error',
        code: 'CISCO_AID_KEY_ENV_MISSING',
        message: `Cisco AI Defense api_key_env "${aid.api_key_env}" is not a valid env-var name. The wizard expects the NAME of the env var (e.g. CISCO_AI_DEFENSE_API_KEY), not the key value.`,
        location: 'cisco_ai_defense.api_key_env',
        fix: 'Use UPPER_SNAKE_CASE matching [A-Z_][A-Z0-9_]+ — the gateway looks up the actual secret via os.Getenv() at boot.',
      });
    }
  }

  return findings;
}

/** Helper: count findings by level. */
export function summarize(findings: ValidationFinding[]): {
  errors: number;
  warnings: number;
  info: number;
} {
  return findings.reduce(
    (acc, f) => {
      if (f.level === 'error') acc.errors += 1;
      else if (f.level === 'warning') acc.warnings += 1;
      else acc.info += 1;
      return acc;
    },
    { errors: 0, warnings: 0, info: 0 },
  );
}

/** Suggest a unique id by appending a numeric suffix. */
export function uniqueRuleId(base: string, taken: Set<string>): string {
  if (!taken.has(base)) return base;
  let i = 2;
  while (taken.has(`${base}-${i}`)) i += 1;
  return `${base}-${i}`;
}

// Re-export the rule type for the regex-input component's convenience.
export type { RuleDef, ValidationCode };
