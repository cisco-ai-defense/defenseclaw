import type { MetadataRoute } from 'next';
import { source } from '@/lib/source';
import { siteUrl } from '@/lib/site';

// Same opt-in as the robots manifest — needed for `output: 'export'`.
export const dynamic = 'force-static';

// Static export needs `generateSitemaps` to be cheap and synchronous-
// flavoured, so we precompute the page list at build time rather than
// streaming it.
export default function sitemap(): MetadataRoute.Sitemap {
  const pages = source.getPages();
  const docsEntries: MetadataRoute.Sitemap = pages.map((p) => ({
    url: `${siteUrl}${p.url}`,
    lastModified: p.data.updatedAt ? new Date(p.data.updatedAt) : new Date(),
    changeFrequency: 'weekly',
    // Surface the canonical guardrail flow at the top.
    priority: p.url === '/docs/setup/guardrail' ? 1.0 : 0.7,
  }));

  return [
    {
      url: siteUrl,
      lastModified: new Date(),
      changeFrequency: 'weekly',
      priority: 1.0,
    },
    ...docsEntries,
  ];
}
