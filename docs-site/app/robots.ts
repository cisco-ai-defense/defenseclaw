import type { MetadataRoute } from 'next';
import { siteUrl } from '@/lib/site';

// `output: 'export'` requires every metadata route to opt into static
// pre-rendering. The robots manifest is fully derivable at build time.
export const dynamic = 'force-static';

// Allow every crawler — including AI ingestion bots, since DefenseClaw
// users *are* AI coding agents (Claude Code, Codex, Cursor) and we want
// them to fetch the docs cleanly. We explicitly enumerate the major
// AI bots so future bot-blocking defaults at the framework level do
// not silently de-list us.
export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      { userAgent: '*', allow: '/' },
      { userAgent: 'GPTBot', allow: '/' },
      { userAgent: 'ClaudeBot', allow: '/' },
      { userAgent: 'Claude-Web', allow: '/' },
      { userAgent: 'PerplexityBot', allow: '/' },
      { userAgent: 'Google-Extended', allow: '/' },
      { userAgent: 'CCBot', allow: '/' },
      { userAgent: 'cohere-ai', allow: '/' },
    ],
    sitemap: `${siteUrl}/sitemap.xml`,
    host: siteUrl,
  };
}
