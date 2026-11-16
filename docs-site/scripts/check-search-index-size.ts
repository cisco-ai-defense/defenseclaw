import { statSync } from 'node:fs';
import { resolve } from 'node:path';
import { assertSearchIndexSize, SEARCH_INDEX_MAX_BYTES } from '../lib/search-index';

// Next exports this static route as an extensionless file. Missing output
// must fail too, rather than silently shipping a site with broken search.
const file = resolve('out/api/search');
const bytes = statSync(file).size;
assertSearchIndexSize(bytes);
console.log(`[check-search-index-size] ${bytes} decoded bytes (limit ${SEARCH_INDEX_MAX_BYTES}).`);
