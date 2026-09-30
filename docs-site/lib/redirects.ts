/**
 * Legacy docs URLs that moved. The site is a static export, so
 * next.config redirects do nothing; instead the docs catch-all route
 * renders a small client-side redirect page for each key below.
 *
 * Keys are slugs with no leading `/docs/` and no trailing slash.
 * `to` is a site path (starting with `/docs`), optionally with a hash.
 *
 * scripts/validate-links.ts fails when a target does not resolve and
 * when a content link still points at a key.
 */
export const legacyRedirects: Record<string, { to: string; title: string }> = {
  openclaw: {
    to: '/docs/connectors/openclaw',
    title: 'OpenClaw connector',
  },
  'setup/guardrail/switching-connectors': {
    to: '/docs/setup/guardrail/multi-connector#replace-a-connector',
    title: 'Replace a connector',
  },
  'get-started/windows/capabilities-commands': {
    to: '/docs/connectors#platform-support',
    title: 'Connector platform support',
  },
  'get-started/windows/connectors-enforcement': {
    to: '/docs/connectors#platform-support',
    title: 'Connector platform support',
  },
  'get-started/windows/managed-enterprise': {
    to: '/docs/enterprise/windows',
    title: 'Windows enterprise deployment',
  },
  'connectors/tool-call-state': {
    to: '/docs/policies/cel/tool-call-state',
    title: 'Stateful connector lifecycle',
  },
};

/** Split a redirect target into its path and optional hash (with `#`). */
export function splitTarget(to: string): { path: string; hash: string } {
  const i = to.indexOf('#');
  return i === -1 ? { path: to, hash: '' } : { path: to.slice(0, i), hash: to.slice(i) };
}
