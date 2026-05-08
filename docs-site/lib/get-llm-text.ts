import { source } from '@/lib/source';
import { siteUrl } from '@/lib/site';

// Single helper used by every LLM-facing surface — `/docs/<slug>.md`,
// `/llms-full.txt`, and any AI integration we layer on top later.
// Centralising the formatting means LLM output stays consistent: an
// agent fetching one page sees the same shape as a corpus dump.
//
// Reads `page.data.getText('processed')`, which is the post-rehype/
// remark Markdown produced by Fumadocs MDX once
// `postprocess.includeProcessedMarkdown` is enabled in
// `source.config.ts`. That output drops MDX components in favour of
// plain Markdown, so `<Card>`, `<Flow>`, and friends become readable
// prose / code fences instead of raw JSX literals.
export async function getLLMText(
  page: (typeof source)['$inferPage'],
): Promise<string> {
  const processed = await page.data.getText('processed');
  const url = `${siteUrl}${page.url}`;
  const title = page.data.title;
  const description = page.data.description;
  const header = description
    ? `# ${title}\n\nURL: ${url}\n\n> ${description}\n`
    : `# ${title}\n\nURL: ${url}\n`;
  return `${header}\n${processed}`;
}
