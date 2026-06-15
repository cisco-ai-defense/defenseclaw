import { source } from '@/lib/source';
import { site, siteUrl } from '@/lib/site';
import { getLLMText } from '@/lib/get-llm-text';

// Concatenated post-processed Markdown corpus of every documentation
// page, surfaced at /llms-full.txt for AI assistants that want a
// single-fetch ingestion path.
//
// Each page is rendered through `getLLMText`, which strips MDX
// components down to plain Markdown via Fumadocs' processed-markdown
// pipeline. AI agents see prose, fenced code, and tables — never raw
// `<Card>` / `<Flow>` JSX — so retrieval quality stays high.
export const dynamic = 'force-static';
export const revalidate = false;

export async function GET() {
  const pages = source.getPages();
  const header = [
    `# Cisco · ${site.name} (full corpus)`,
    '',
    `> ${site.description}`,
    '',
    `> Live site: ${siteUrl}`,
    '',
  ].join('\n');

  const sections = await Promise.all(pages.map(getLLMText));

  return new Response([header, ...sections].join('\n\n'), {
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
  });
}
