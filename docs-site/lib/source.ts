import { docs } from '@/.source/server';
import { loader } from 'fumadocs-core/source';

// Single source of truth for resolving MDX content into routes,
// breadcrumbs, sitemap entries, and search index records. The
// `baseUrl` is intentionally `/docs` (not `BASE_PATH/docs`); the
// Next.js `basePath` config prepends the GitHub Pages prefix at link
// generation time, so duplicating it here would double-encode every
// internal href.
export const source = loader({
  baseUrl: '/docs',
  source: docs.toFumadocsSource(),
});
