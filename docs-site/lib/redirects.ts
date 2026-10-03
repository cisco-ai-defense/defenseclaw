// Old docs URLs that moved when the navigation was reorganised. Each key
// is the old slug under /docs; the value is the page that now owns the
// topic. The docs catch-all route pre-renders a small "moved" page for
// every key (static export has no server-side redirects), so bookmarks,
// search results and links printed by the CLI keep working.
//
// When you move a page: `git mv` it, add its old slug here, and update
// internal links to the new URL. Keep entries forever.
export const legacyRedirects: Record<string, string> = {
  setup: '/docs/reference/setup-commands/',
  'setup/guardrail': '/docs/guardrail/',
  'setup/guardrail/aliases': '/docs/guardrail/aliases/',
  'setup/guardrail/multi-connector': '/docs/guardrail/multi-connector/',
  'setup/guardrail/switching-connectors': '/docs/guardrail/switching-connectors/',
  'setup/guardrail/disabling': '/docs/guardrail/disabling/',
  'setup/semantic-routing': '/docs/guardrail/semantic-routing/',
  'setup/unified-llm-key': '/docs/guardrail/unified-llm-key/',
  'setup/sandbox': '/docs/sandboxes/guide/',
  'setup/sandbox-policy': '/docs/sandboxes/policy-packs/',
  'setup/skill-scanner': '/docs/scanning/skill-scanner/',
  'setup/mcp-scanner': '/docs/scanning/mcp-scanner/',
  'setup/registries': '/docs/scanning/registries/',
  'setup/webhooks': '/docs/observability/webhooks/',
  'setup/enterprise-deployment': '/docs/enterprise/secure-client/',
  defaults: '/docs/policies/defaults/',
  benchmarks: '/docs/guardrail/benchmarks/',
  'llm-judge-benchmark': '/docs/guardrail/llm-judge-benchmark/',
  'capability-matrix': '/docs/connectors/capability-matrix/',
  openclaw: '/docs/connectors/openclaw-integration/',
  'reference/redaction': '/docs/observability/redaction/',
  'connectors/tool-call-state': '/docs/policies/cel/tool-call-state/',
};

export function legacyRedirectFor(slug: string[] | undefined): string | undefined {
  return legacyRedirects[(slug ?? []).join('/')];
}
