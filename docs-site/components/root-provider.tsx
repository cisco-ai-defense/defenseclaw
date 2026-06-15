'use client';

import { RootProvider } from 'fumadocs-ui/provider/next';
import type { ReactNode } from 'react';
import dynamic from 'next/dynamic';

// Client wrapper around Fumadocs's RootProvider so we can hand it the
// custom (FlexSearch-backed) SearchDialog component reference. Server
// layouts can't pass component types across the server/client
// boundary, so the wrapper imports the dialog itself and threads it
// in via `search.SearchDialog`.
//
// We pull the dialog in via `next/dynamic` with `ssr: false` because
// `flexsearchStaticClient` issues a `fetch('/<basePath>/api/search')`
// at construction time. Relative URLs aren't valid in Node's native
// fetch (used during SSG/prerender), so eagerly importing the dialog
// crashes the static export. Deferring to client-only mount lets the
// browser resolve the URL against `window.location.origin` and the
// search index loads on first interaction.
const SearchDialog = dynamic(() => import('./search'), { ssr: false });

export default function ClientRootProvider({
  children,
}: {
  children: ReactNode;
}) {
  return (
    <RootProvider
      search={{
        SearchDialog,
      }}
    >
      {children}
    </RootProvider>
  );
}
