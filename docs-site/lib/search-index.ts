import type { Index } from 'fumadocs-core/search/flexsearch';

interface SearchPage {
  url: string;
  data: {
    title: string;
    description?: string;
    structuredData: Index['structuredData'] | (() => Promise<Index['structuredData']>);
  };
}

// Budget decoded JSON: transfer compression does not bound parsing and
// index-import memory on an iPhone. Leave room for documentation growth.
export const SEARCH_INDEX_MAX_BYTES = 32 * 1024 * 1024;

export function assertSearchIndexSize(bytes: number) {
  if (bytes > SEARCH_INDEX_MAX_BYTES) {
    throw new Error(
      `Search index is ${bytes} decoded bytes; limit is ${SEARCH_INDEX_MAX_BYTES}. `
      + 'Reduce the search index before deploying: oversized indexes can reload mobile tabs.',
    );
  }
}

export function createSearchIndexOptions(pages: readonly SearchPage[]) {
  // These IDs are private to a single exported index. Using page URLs here
  // repeats long paths in every token posting; short IDs keep prefix search
  // affordable without dropping page text, headings, or result links.
  const ids = new Map(pages.map((page, index) => [page.url, index.toString(36)]));

  return {
    document: { tokenize: 'forward' as const },
    async buildIndex(page: SearchPage): Promise<Index> {
      const id = ids.get(page.url);
      if (id === undefined) throw new Error(`Search page is not registered: ${page.url}`);
      const structuredData = typeof page.data.structuredData === 'function'
        ? await page.data.structuredData()
        : page.data.structuredData;
      return {
        id,
        title: page.data.title,
        description: page.data.description,
        url: page.url,
        structuredData,
      };
    },
  };
}
