// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Question library for the Quick Start interview. Five logical groups
// cover the high-traffic policy decisions; the apply.ts mapper turns
// answers into a fully-realized `Policy` on every change.
//
// We deliberately keep this file pure data + simple types so it can be
// imported from both the UI (quick-start/index.tsx) and the mapping
// layer (quick-start/apply.ts) without dragging React into the latter.

import type { SeverityUpper } from '../types';

// --- Q1: posture (single select) -------------------------------------------

export const POSTURES = [
  {
    id: 'permissive',
    // Renamed from "Observe" — the underlying `permissive` preset still
    // blocks CRITICAL findings at install time and quarantines CRITICAL
    // files, so "Observe" (which implies *never* block) was misleading.
    // "Permissive" matches both the preset ID and the actual behaviour.
    title: 'Permissive',
    description:
      'Log everything; only CRITICAL findings block installs. Best for the first week of a pilot or a SOC team that wants visibility without operational risk.',
  },
  {
    id: 'default',
    title: 'Balanced',
    description:
      'Block CRITICAL findings, alert on HIGH, log MEDIUM. Sensible production default for most teams.',
  },
  {
    id: 'strict',
    title: 'Strict',
    description:
      'Block at MEDIUM+, ask before any sandboxed install, hold HIGH+ verdicts for human approval. Pick this for regulated workloads.',
  },
] as const;

export type PostureId = (typeof POSTURES)[number]['id'];

// --- Q2: what to block (multi select) --------------------------------------

/** Logical bucket for the block-card grid in the wizard's "Block" step.
 *  Purely a UX grouping — the apply.ts mapper doesn't read it. */
export type BlockCategory = 'data' | 'network' | 'code' | 'llm' | 'multi_step';

export const BLOCK_CATEGORIES: ReadonlyArray<{
  id: BlockCategory;
  title: string;
  blurb: string;
}> = [
  {
    id: 'data',
    title: 'Data leaks',
    blurb: 'Credentials, PII, and sensitive paths the agent should never read or send.',
  },
  {
    id: 'network',
    title: 'Network exfiltration',
    blurb: 'Outbound destinations commonly used to siphon data out of a sandbox.',
  },
  {
    id: 'code',
    title: 'Code execution',
    blurb: 'Shell commands and tool calls that can hose the box.',
  },
  {
    id: 'llm',
    title: 'LLM-layer attacks',
    blurb: 'Prompt-shape patterns aimed at the model itself.',
  },
  {
    id: 'multi_step',
    title: 'Multi-step attack patterns',
    blurb: 'Session-level patterns where each step looks benign but the sequence does not. Powered by the Layer-5 correlator.',
  },
];

export interface BlockCard {
  id: string;
  title: string;
  description: string;
  /** Which group this card renders under in the wizard. */
  category: BlockCategory;
  /** Rule IDs (cross-file) toggled to enabled when this card is checked. */
  ruleIds: string[];
  /** Hostnames added to the firewall block list. */
  destinations?: string[];
  /** Categories of guardrail patterns this card adds. Drives the
   *  guardrail.patterns map so the existing engine catches them
   *  without needing a brand-new rule pack file. */
  guardrailPatterns?: Array<{ category: string; patterns: string[]; severity: SeverityUpper }>;
  /** Correlator pattern IDs that this card forces to enabled. Lets a
   *  card opt the operator into Layer-5 detection without requiring
   *  them to crack open the Playground's Correlator section. */
  correlatorPatternIds?: string[];
  /** Open this docs page when the user clicks "see cookbook". */
  cookbookHref?: string;
}

export const BLOCK_CARDS: BlockCard[] = [
  {
    id: 'secrets',
    category: 'data',
    title: 'Hardcoded secrets in prompts',
    description:
      'AWS access keys, OpenAI keys, GitHub tokens, JWTs, private keys, Slack webhooks. Catches credentials accidentally pasted into prompts before they reach an LLM provider.',
    ruleIds: [
      'SEC-AWS-KEY',
      'SEC-OPENAI-V2',
      'SEC-GITHUB-TOKEN',
      'SEC-PRIVKEY',
      'SEC-JWT',
      'SEC-SLACK-WEBHOOK',
      'SEC-STRIPE',
      'SEC-GCP',
    ],
    cookbookHref: '/docs/policies/regex-cookbook',
  },
  {
    id: 'prompt_injection',
    category: 'llm',
    title: 'Prompt injection',
    description:
      'System-prompt overrides, role overrides, jailbreak chains. Detects user input attempting to bypass guardrails or escalate the agent\u2019s capabilities.',
    ruleIds: [
      'INJ-SYS-OVERRIDE',
      'INJ-ROLE-OVERRIDE',
      'INJ-IGNORE-PREV',
      'INJ-JAILBREAK',
    ],
    guardrailPatterns: [
      {
        category: 'injection',
        patterns: [
          'ignore (?:all )?previous',
          'system prompt:',
          'you are (?:now )?(?:a |an )?',
        ],
        severity: 'HIGH',
      },
    ],
    cookbookHref: '/docs/policies/regex-cookbook',
  },
  {
    id: 'exfiltration',
    category: 'network',
    title: 'Exfiltration to known leak sinks',
    description:
      'RequestBin, HookBin, Burp Collaborator, ngrok, webhook.site. The most common destinations for exfiltrated data when an attacker doesn\u2019t bother hiding.',
    ruleIds: ['C2-REQUESTBIN', 'C2-HOOKBIN', 'C2-BURP', 'C2-NGROK', 'C2-WEBHOOKSITE'],
    destinations: [
      'requestbin.com',
      'hookbin.com',
      'burpcollaborator.net',
      'ngrok.io',
      'webhook.site',
    ],
    cookbookHref: '/docs/policies/regex-cookbook',
  },
  {
    id: 'cloud_metadata',
    category: 'network',
    title: 'Cloud metadata access (IMDS)',
    description:
      'AWS IMDS at 169.254.169.254, GCP metadata at metadata.google.internal, Azure IMDS. Exposing these from a sandboxed agent leaks credentials with one curl.',
    ruleIds: [],
    destinations: [
      '169.254.169.254',
      'fd00:ec2::254',
      'metadata.google.internal',
      'metadata.azure.com',
    ],
  },
  {
    id: 'destructive_shell',
    category: 'code',
    title: 'Destructive shell commands',
    description:
      'rm -rf /, dd if=, mkfs, fdisk, shred, :(){:|:&};:. Catches the canonical "make the disk dance" patterns before they hit a sandbox.',
    ruleIds: ['CMD-RM-RF', 'CMD-DD', 'CMD-MKFS', 'CMD-FORK-BOMB', 'CMD-SHRED'],
    cookbookHref: '/docs/policies/regex-cookbook',
  },
  {
    id: 'sensitive_paths',
    category: 'data',
    title: 'Sensitive file paths',
    description:
      '~/.ssh, ~/.aws, ~/.kube, /etc/shadow, .env files, gh-cli config. Prevents the agent from reading or writing config that leaks long-lived credentials.',
    ruleIds: ['PATH-SSH', 'PATH-AWS', 'PATH-KUBE', 'PATH-SHADOW', 'PATH-DOTENV'],
    cookbookHref: '/docs/policies/regex-cookbook',
  },
  {
    id: 'pii_enterprise',
    category: 'data',
    title: 'PII / enterprise data leakage',
    description:
      'SSN, internal hostnames, employee IDs, financial routing numbers. Most useful when the agent talks to public LLM providers.',
    ruleIds: ['PII-SSN', 'ENT-INTERNAL-HOST', 'ENT-EMP-ID', 'PII-ROUTING'],
    cookbookHref: '/docs/policies/regex-cookbook',
  },
  {
    id: 'trust_exploit',
    category: 'llm',
    title: 'Trust / impersonation exploits',
    description:
      'Role overrides, fake function-call results, "you are an admin" prompts. Catches the social-engineering vector against agents.',
    ruleIds: ['TRUST-ROLE-OVERRIDE', 'TRUST-FAKE-RESULT', 'TRUST-ADMIN-CLAIM'],
    cookbookHref: '/docs/policies/regex-cookbook',
  },
  {
    id: 'cognitive',
    category: 'llm',
    title: 'Cognitive / manipulation patterns',
    description:
      'Authority-claim, urgency, fake citations, false consensus. Lower-confidence patterns that flag suspicious narrative shape rather than concrete payloads.',
    ruleIds: ['COG-AUTHORITY', 'COG-URGENCY', 'COG-FAKE-CITE'],
    cookbookHref: '/docs/policies/regex-cookbook',
  },
  {
    id: 'lethal_trifecta',
    category: 'multi_step',
    title: 'Lethal trifecta (Willison)',
    description:
      'Session combines untrusted ingress + sensitive data access + external egress. The three ingredients of indirect-prompt-injection exfil. Catches sessions where each step looked HIGH/MEDIUM individually but the combination is CRITICAL.',
    ruleIds: [],
    correlatorPatternIds: ['LETHAL-TRIFECTA', 'TRIFECTA-WITH-FINGERPRINT-MATCH'],
    cookbookHref: '/docs/policies#layer-5--session-correlator',
  },
  {
    id: 'escalation_chain',
    category: 'multi_step',
    title: 'Escalation chain across turns',
    description:
      'MEDIUM → HIGH → HIGH severity progression inside the same session — attacker iterating on a prompt to get past a guardrail. Promoted to CRITICAL when the chain completes.',
    ruleIds: [],
    correlatorPatternIds: ['ESCALATION-CHAIN'],
    cookbookHref: '/docs/policies#layer-5--session-correlator',
  },
  {
    id: 'destructive_flow',
    category: 'multi_step',
    title: 'Destructive shell after sensitive read',
    description:
      'rm -rf / mkfs / dd-if invoked in the same session as a prior sensitive-access finding (~/.ssh, ~/.aws, /etc/shadow). Indicates active exploitation rather than reconnaissance.',
    ruleIds: [],
    correlatorPatternIds: ['DESTRUCTIVE-FLOW'],
    cookbookHref: '/docs/policies#layer-5--session-correlator',
  },
];

// --- Q3: what to allow (multi select + free-form) --------------------------

export interface AllowCard {
  id: string;
  title: string;
  description: string;
  /** Tool name regex added to tool_suppressions. */
  toolPattern?: string;
  /** Finding IDs the tool suppression silences. */
  suppressFindings?: string[];
  /** Domains added to firewall.allowed_domains. */
  domains?: string[];
  /** First-party allow-list entries (target_name globs). */
  firstParty?: string[];
  cookbookHref?: string;
}

export const ALLOW_CARDS: AllowCard[] = [
  {
    id: 'cosmetic_shell',
    title: 'Cosmetic shell commands (git status, ls, pwd)',
    description:
      'These are read-only, always safe, and the noisiest source of false-positive injection findings. Suppress them and your alert volume drops by ~60%.',
    toolPattern: '^(?:shell|bash|sh)\\.execute$',
    suppressFindings: ['JUDGE-INJ-COSMETIC', 'CMD-LS', 'CMD-PWD'],
    cookbookHref: '/docs/policies/suppression-cookbook',
  },
  {
    id: 'first_party_plugins',
    title: 'First-party plugins (your org\u2019s code)',
    description:
      'Skills and MCP servers shipped by your organization should never get blocked. Add the org/* glob below; matches bypass admission scans.',
    firstParty: ['cisco-ai-defense/*'],
  },
  {
    id: 'internal_domains',
    title: 'Internal domains (corp network)',
    description:
      'Sandboxed agents that legitimately fetch from internal APIs need their domains whitelisted in the firewall.',
    domains: ['*.corp.internal', '*.internal.example.com'],
  },
  {
    id: 'dev_tools',
    title: 'Known dev tools (Cursor / Claude Code / Codex)',
    description:
      'IDE assistants generate noisy traffic that\u2019s usually fine. Suppress the standard noise without disabling the rule packs.',
    toolPattern: '^(?:cursor|claude-code|codex|aider)\\.[a-z_]+$',
    suppressFindings: ['JUDGE-INJ-COSMETIC'],
    cookbookHref: '/docs/policies/suppression-cookbook',
  },
];

// --- Q4: response posture (single select) ----------------------------------

export const RESPONSES = [
  {
    id: 'log_only',
    title: 'Log silently',
    description:
      'Record everything to the audit log; never block, never prompt. Best for shadow-mode evaluation.',
    block_threshold: 4 as const, // CRITICAL only
    alert_threshold: 1 as const, // any LOW logs
    hilt_enabled: false,
    hilt_min: 'CRITICAL' as SeverityUpper,
  },
  {
    id: 'alert',
    title: 'Alert me on high+',
    description:
      'Send guardrail/firewall alerts to your sinks for HIGH and CRITICAL. Does not pause the agent. Recommended starting point.',
    block_threshold: 4 as const,
    alert_threshold: 3 as const, // HIGH+
    hilt_enabled: false,
    hilt_min: 'HIGH' as SeverityUpper,
  },
  {
    id: 'ask',
    title: 'Ask first (HILT) on medium+',
    description:
      'Pause the agent at MEDIUM and HIGH and wait for a human to approve / deny. CRITICAL still hard-blocks.',
    block_threshold: 4 as const,
    alert_threshold: 2 as const,
    hilt_enabled: true,
    hilt_min: 'MEDIUM' as SeverityUpper,
  },
  {
    id: 'block',
    title: 'Hard block on medium+',
    description:
      'Block MEDIUM, HIGH, and CRITICAL. Use this when false positives are an acceptable cost (regulated workloads, restricted data).',
    block_threshold: 2 as const, // MEDIUM+
    alert_threshold: 1 as const,
    hilt_enabled: false,
    hilt_min: 'CRITICAL' as SeverityUpper,
  },
] as const;

export type ResponseId = (typeof RESPONSES)[number]['id'];

// --- Q5: where events go (multi select + inline config) --------------------

export interface SinkCard {
  id: string;
  title: string;
  description: string;
  /** Whether this sink needs additional config (URL, env-var). */
  configFields?: Array<{ key: 'url' | 'secret_env'; label: string; placeholder: string }>;
  type?: 'slack' | 'webex' | 'pagerduty' | 'generic';
}

export const SINK_CARDS: SinkCard[] = [
  {
    id: 'local_file',
    title: 'Local audit log',
    description:
      'Append every event to ~/.defenseclaw/audit.jsonl. Always-on default; recommended even when you also wire a remote sink.',
  },
  {
    id: 'stdout',
    title: 'stdout / journald',
    description:
      'Write structured JSON events to stdout. Useful for container deployments where journald or a log shipper picks them up.',
  },
  {
    id: 'splunk',
    title: 'Splunk HEC',
    description:
      'Forward block/alert events to Splunk\u2019s HTTP Event Collector. Token is read from the env var you provide \u2014 never hardcoded.',
    type: 'generic',
    configFields: [
      { key: 'url', label: 'HEC URL', placeholder: 'https://splunk.example.com:8088/services/collector/event' },
      { key: 'secret_env', label: 'Token env var', placeholder: 'SPLUNK_HEC_TOKEN' },
    ],
  },
  {
    id: 'slack',
    title: 'Slack webhook',
    description:
      'Post HIGH/CRITICAL events into a Slack channel via incoming-webhook. Signing secret is read from the env var you provide.',
    type: 'slack',
    configFields: [
      { key: 'url', label: 'Webhook URL', placeholder: 'https://hooks.slack.com/services/T0000/B0000/abcdef' },
      { key: 'secret_env', label: 'Signing-secret env var', placeholder: 'SLACK_WEBHOOK_SECRET' },
    ],
  },
  {
    id: 'generic_webhook',
    title: 'Generic webhook',
    description:
      'POST events to any HTTP endpoint that accepts JSON. Use this for SOAR platforms, custom collectors, or PagerDuty.',
    type: 'generic',
    configFields: [
      { key: 'url', label: 'Webhook URL', placeholder: 'https://soar.example.com/defenseclaw' },
      { key: 'secret_env', label: 'HMAC env var (optional)', placeholder: 'WEBHOOK_HMAC_SECRET' },
    ],
  },
];

// --- Aggregate answers shape -----------------------------------------------

export interface SinkAnswer {
  enabled: boolean;
  url: string;
  secret_env: string;
}

export interface Answers {
  posture: PostureId;
  block: Set<string>;
  allow: Set<string>;
  /** Free-form first-party allow-list globs the user added beyond the
   *  defaults in `first_party_plugins`. One per line in the input. */
  firstPartyExtra: string[];
  /** Free-form additional firewall allow domains. */
  domainsExtra: string[];
  response: ResponseId;
  sinks: Record<string, SinkAnswer>;
}

export function defaultAnswers(): Answers {
  const sinks: Answers['sinks'] = {};
  for (const s of SINK_CARDS) {
    sinks[s.id] = {
      enabled: s.id === 'local_file', // default-on
      url: '',
      secret_env: '',
    };
  }
  return {
    posture: 'default',
    block: new Set<string>(),
    allow: new Set<string>(),
    firstPartyExtra: [],
    domainsExtra: [],
    response: 'alert',
    sinks,
  };
}

// JSON helpers — Sets don't survive JSON.stringify, so we expose
// (de)serialisers used by the localStorage layer in index.tsx.

export interface SerializedAnswers {
  posture: PostureId;
  block: string[];
  allow: string[];
  firstPartyExtra: string[];
  domainsExtra: string[];
  response: ResponseId;
  sinks: Record<string, SinkAnswer>;
}

export function serializeAnswers(a: Answers): SerializedAnswers {
  return {
    posture: a.posture,
    block: Array.from(a.block),
    allow: Array.from(a.allow),
    firstPartyExtra: [...a.firstPartyExtra],
    domainsExtra: [...a.domainsExtra],
    response: a.response,
    sinks: { ...a.sinks },
  };
}

export function deserializeAnswers(raw: unknown): Answers {
  const base = defaultAnswers();
  if (!raw || typeof raw !== 'object') return base;
  const r = raw as Partial<SerializedAnswers>;
  return {
    posture: (r.posture ?? base.posture) as PostureId,
    block: new Set<string>(Array.isArray(r.block) ? r.block : []),
    allow: new Set<string>(Array.isArray(r.allow) ? r.allow : []),
    firstPartyExtra: Array.isArray(r.firstPartyExtra) ? r.firstPartyExtra : [],
    domainsExtra: Array.isArray(r.domainsExtra) ? r.domainsExtra : [],
    response: (r.response ?? base.response) as ResponseId,
    sinks: { ...base.sinks, ...(r.sinks ?? {}) },
  };
}
