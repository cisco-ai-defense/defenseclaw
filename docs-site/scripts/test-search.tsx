import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { renderToString } from 'react-dom/server';
import { flexsearch, type Index } from 'fumadocs-core/search/flexsearch';
import { flexsearchStaticClient } from 'fumadocs-core/search/client/flexsearch-static';
import { SearchProvider } from 'fumadocs-ui/contexts/search';
import ClientRootProvider, { searchProviderOptions } from '../components/root-provider';
import {
  assertSearchIndexSize,
  createSearchIndexOptions,
  SEARCH_INDEX_MAX_BYTES,
} from '../lib/search-index';

const page = {
  url: '/docs/a-long-section-name/runtime-guardrails-and-policy-configuration',
  data: {
    title: 'Runtime guardrails',
    description: 'Configure deterministic protections.',
    structuredData: {
      headings: [{ id: 'blocking', content: 'Blocking mode' }],
      contents: [{ heading: 'blocking', content: 'Guardrails inspect tool calls and enforce policy.' }],
    },
  },
};

async function exportFixture() {
  const options = createSearchIndexOptions([page]);
  return flexsearch({
    indexes: [await options.buildIndex(page)],
    document: options.document,
  }).export();
}

describe('search startup', () => {
  it('renders the real root provider without mounting the client-only search dialog', () => {
    const html = renderToString(
      <ClientRootProvider><main>Documentation remains available</main></ClientRootProvider>,
    );
    assert.match(html, /Documentation remains available/);
    let mounts = 0;
    function ProbeDialog() {
      mounts += 1;
      return null;
    }
    // Exercise the real Fumadocs provider with our production options. A
    // closed dialog must never mount and initialize its static client.
    renderToString(
      <SearchProvider {...searchProviderOptions} SearchDialog={ProbeDialog}>
        <main>Documentation</main>
      </SearchProvider>,
    );
    assert.equal(mounts, 0, 'Closed search must not initialize its client');
  });
});

describe('compact search index', () => {
  it('round-trips prefix queries through the real static client with page and heading links intact', async () => {
    const payload = await exportFixture();
    const originalFetch = globalThis.fetch;
    let fetches = 0;
    globalThis.fetch = async () => {
      fetches += 1;
      return Response.json(payload);
    };
    try {
      assert.equal(fetches, 0, 'Search must not fetch before the dialog creates its client');
      const client = flexsearchStaticClient({ from: '/compact-search-regression' });
      assert.equal(fetches, 1, 'Opening search should load the index once');
      const results = await client.search('guard');
      assert.ok(results.some((result) => result.type === 'page' && result.url === page.url));
      assert.ok(results.some((result) => result.type === 'text' && result.url === `${page.url}#blocking`));
      assert.deepEqual(await client.search('uardrails'), [], 'Search matches word prefixes, not interior substrings');
      const heading = await client.search('block');
      assert.ok(heading.some((result) => result.type === 'heading' && result.url === `${page.url}#blocking`));
      const description = await client.search('determin');
      assert.ok(description.some((result) => result.type === 'text' && result.url === page.url));
      assert.equal(fetches, 1, 'Search queries should reuse the loaded index');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('handles lazy page data and rejects unregistered pages', async () => {
    const lazy = { ...page, data: { ...page.data, structuredData: async () => page.data.structuredData } };
    const options = createSearchIndexOptions([lazy]);
    assert.deepEqual((await options.buildIndex(lazy)).structuredData, page.data.structuredData);
    await assert.rejects(options.buildIndex({ ...page, url: '/not-registered' }), /not registered/);
  });

  it('reduces an identifier-heavy index without removing searchable content', async () => {
    const options = createSearchIndexOptions([page]);
    const compact = await options.buildIndex(page);
    const technicalText = Array.from({ length: 40 }, (_, index) =>
      `enterprise_guardrail_policy_configuration_reference_${index}`).join(' ');
    const data: Index = {
      ...compact,
      structuredData: {
        headings: [],
        contents: [{ heading: undefined, content: technicalText }],
      },
    };
    const optimized = await flexsearch({ indexes: [data], document: options.document }).export();
    const original = await flexsearch({ indexes: [{ ...data, id: page.url }] }).export();
    assert.ok(JSON.stringify(optimized).length < JSON.stringify(original).length / 2);
    assert.ok(JSON.stringify(optimized).includes(technicalText));
  });
});

describe('decoded search index budget', () => {
  it('accepts the boundary and rejects growth and the deployed 183 MB regression', () => {
    assert.doesNotThrow(() => assertSearchIndexSize(SEARCH_INDEX_MAX_BYTES));
    assert.throws(() => assertSearchIndexSize(SEARCH_INDEX_MAX_BYTES + 1), /Reduce the search index/);
    assert.throws(() => assertSearchIndexSize(183_543_911), /oversized indexes can reload mobile tabs/);
  });
});
