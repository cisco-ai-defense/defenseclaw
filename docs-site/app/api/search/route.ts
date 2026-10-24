import { source } from '@/lib/source';
import { createSearchIndexOptions } from '@/lib/search-index';
import { flexsearchFromSource } from 'fumadocs-core/search/flexsearch';

// Export a prefix-search index with short, build-local record IDs. Full
// substring indexing and repeated page URLs made the old payload 183 MB
// decoded, before the browser even allocated its in-memory search maps.
// URLs and heading anchors remain in the stored results, not the index IDs.
export const dynamic = 'force-static';
export const revalidate = false;

export const { staticGET: GET } = flexsearchFromSource(
  source,
  createSearchIndexOptions(source.getPages()),
);
