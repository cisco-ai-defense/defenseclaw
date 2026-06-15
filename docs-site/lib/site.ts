// Centralised site identity. Every metadata, OG, JSON-LD, and footer
// surface reads from this module so a future rebrand only needs to
// touch a single file.
export const site = {
  name: 'DefenseClaw',
  tagline: 'Security governance for OpenClaw and agentic AI runtimes.',
  description:
    'DefenseClaw is the Cisco governance layer for AI coding agents. ' +
    'Scan skills, MCP servers, plugins, and generated code before they run. ' +
    'Inspect prompts, completions, tool calls, and sandbox activity at runtime. ' +
    'Export durable audit evidence to SQLite, JSONL, OTLP, Splunk, and webhooks.',
  organization: {
    name: 'Cisco Systems, Inc.',
    legalName: 'Cisco Systems, Inc.',
    // Anchors the parent-org link in the footer + JSON-LD. Points
    // at the public Cisco AI Security project hub rather than a
    // sub-brand surface so the lockup reads as "Cisco · DefenseClaw".
    url: 'https://cisco-ai-defense.github.io/',
    logo: '/images/cisco-logo.png',
    sameAs: [
      'https://github.com/cisco-ai-defense/defenseclaw',
      'https://discord.com/invite/nKWtDcXxtx',
      'https://cisco-ai-defense.github.io/',
    ],
  },
  repo: {
    owner: 'cisco-ai-defense',
    name: 'defenseclaw',
    url: 'https://github.com/cisco-ai-defense/defenseclaw',
    discord: 'https://discord.com/invite/nKWtDcXxtx',
  },
  product: {
    name: 'DefenseClaw',
    license: 'Apache-2.0',
    licenseUrl: 'https://opensource.org/licenses/Apache-2.0',
    operatingSystem: 'macOS, Linux',
    applicationCategory: 'SecurityApplication',
  },
} as const;

// SITE_URL is also re-exposed via NEXT_PUBLIC_SITE_URL in
// next.config.mjs so client components can compose absolute URLs
// (canonical, OG, JSON-LD) without leaking deploy-target details
// into the source tree.
export const siteUrl =
  process.env.NEXT_PUBLIC_SITE_URL ?? 'https://cisco-ai-defense.github.io/defenseclaw';

// basePath without the trailing slash. Used by sitemap + canonical
// URL composition. Handles both '' (custom domain at root) and a
// project-pages subpath like '/defenseclaw'.
export const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? '';

export const defaultKeywords = [
  'Cisco',
  'DefenseClaw',
  'AI agent security',
  'AI coding agent guardrail',
  'prompt injection',
  'OpenClaw',
  'Claude Code',
  'Codex',
  'Cursor',
  'Windsurf',
  'GitHub Copilot CLI',
  'Gemini CLI',
  'MCP scanner',
  'AI policy',
  'AI audit',
  'OTLP',
  'Splunk',
  'human in the loop',
  'HITL',
];
