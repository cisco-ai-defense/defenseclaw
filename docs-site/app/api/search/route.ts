import { source } from '@/lib/source';
import { flexsearchFromSource } from 'fumadocs-core/search/flexsearch';

// FlexSearch index, exported as one JSON document under
// `/api/search` and consumed by the custom SearchDialog component
// (see components/search.tsx) via `flexsearchStaticClient`.
//
// Why FlexSearch over the previous Orama-static backend:
//   * smaller wire payload (FlexSearch's exported index compresses
//     better against repetitive token vocabularies — typical wins of
//     20–40% for technical docs);
//   * faster cold-start in the browser (no schema/runtime to boot);
//   * tag filter support if we ever want per-section scoping.
//
// `dynamic = 'force-static'` + `revalidate = false` keep this safe
// under `output: 'export'` (no per-request handler, just one JSON
// emitted at build time).
export const dynamic = 'force-static';
export const revalidate = false;

export const { staticGET: GET } = flexsearchFromSource(source);
