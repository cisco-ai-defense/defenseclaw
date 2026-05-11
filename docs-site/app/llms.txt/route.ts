import { source } from '@/lib/source';
import { site, siteUrl } from '@/lib/site';

// Static-export friendly llms.txt route: returns the page index in
// the convention popularised by https://llmstxt.org/. AI agents that
// adopt the convention can discover the catalog and crawl from here:
//   * One human URL per page (`page.url`).
//   * One AI-friendly Markdown URL per page (`<page.url>llms.md`)
//     — pointing into app/(docs)/docs/[[...slug]]/llms.md/route.ts
//     which emits per-page processed Markdown at build time.
// The richer single-fetch corpus lives at /llms-full.txt.
export const dynamic = 'force-static';
export const revalidate = false;

export function GET() {
  const pages = source.getPages();
  const lines: string[] = [];
  lines.push(`# Cisco · ${site.name}`);
  lines.push('');
  lines.push(`> ${site.description}`);
  lines.push('');
  lines.push(`> Markdown corpus: ${siteUrl}/llms-full.txt`);
  lines.push('');
  lines.push('## Documentation');
  for (const p of pages) {
    const title = p.data.title;
    const desc = p.data.description ? ` — ${p.data.description}` : '';
    // Markdown URL is a sibling of the page's index.html under the
    // same `/docs/<slug>/` directory, so AI agents can fetch
    // structured prose without scraping HTML.
    const mdUrl = `${siteUrl}${p.url.replace(/\/?$/, '/')}llms.md`;
    lines.push(`- [${title}](${siteUrl}${p.url})${desc}`);
    lines.push(`  - Markdown: ${mdUrl}`);
  }
  return new Response(lines.join('\n'), {
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
  });
}
