'use client';

import {
  SearchDialog,
  SearchDialogClose,
  SearchDialogContent,
  SearchDialogHeader,
  SearchDialogIcon,
  SearchDialogInput,
  SearchDialogList,
  SearchDialogOverlay,
  type SharedProps,
} from 'fumadocs-ui/components/dialog/search';
import { useDocsSearch } from 'fumadocs-core/search/client';
import { flexsearchStaticClient } from 'fumadocs-core/search/client/flexsearch-static';

// Custom search dialog wired to the static FlexSearch index emitted
// by app/api/search/route.ts. It runs entirely in the browser — the
// JSON index is fetched once, cached in module scope by
// `flexsearchStaticClient`, and queried locally on every keystroke.
//
// We compose the basePath (project pages: /defenseclaw, custom domain
// or local dev: '') so the index URL resolves correctly everywhere
// the static export is served.
const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? '';

export default function DefenseClawSearchDialog(props: SharedProps) {
  const { search, setSearch, query } = useDocsSearch({
    client: flexsearchStaticClient({
      from: `${basePath}/api/search`,
    }),
  });

  return (
    <SearchDialog
      search={search}
      onSearchChange={setSearch}
      isLoading={query.isLoading}
      {...props}
    >
      <SearchDialogOverlay />
      <SearchDialogContent>
        <SearchDialogHeader>
          <SearchDialogIcon />
          <SearchDialogInput />
          <SearchDialogClose />
        </SearchDialogHeader>
        <SearchDialogList items={query.data !== 'empty' ? query.data : null} />
      </SearchDialogContent>
    </SearchDialog>
  );
}
