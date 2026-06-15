import { defineConfig, defineDocs, frontmatterSchema, metaSchema } from 'fumadocs-mdx/config';
import { z } from 'zod';

// Frontmatter contract surfaced by the docs/ tree. We extend the default
// schema with a `keywords` array so per-page SEO can be authored inline
// without a separate metadata sidecar.
export const docs = defineDocs({
  dir: 'content/docs',
  docs: {
    schema: frontmatterSchema.extend({
      keywords: z.array(z.string()).optional(),
      updatedAt: z.string().optional(),
      authors: z
        .array(z.object({ name: z.string(), url: z.string().url().optional() }))
        .optional(),
    }),
    // Cache the post-processed Markdown for every page on `page.data`.
    // This is what `getLLMText` reads to build the per-page Markdown
    // served at `/docs/<slug>.md`, the concatenated `/llms-full.txt`,
    // and any future AI integration. Generating this once at build
    // time means we don't have to re-run the MDX pipeline at request
    // time (which `output: 'export'` doesn't support anyway).
    postprocess: {
      includeProcessedMarkdown: true,
    },
  },
  meta: {
    schema: metaSchema,
  },
});

export default defineConfig({
  mdxOptions: {
    // Diagrams render server-side via the <Flow> and <Sequence>
    // components in components/diagram/*. SVG is baked directly into
    // the static HTML so crawlers, screen readers, and slow connections
    // all get the same rendered output as the operator on the page.
    rehypeCodeOptions: {
      themes: {
        light: 'catppuccin-latte',
        dark: 'catppuccin-mocha',
      },
    },
  },
});
