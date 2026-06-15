# DefenseClaw documentation site

Cisco · DefenseClaw narrative documentation, built with [Fumadocs](https://www.fumadocs.dev) on top of Next.js. Statically exported and deployed to GitHub Pages on every push to `main`.

## Local development

```bash
cd docs-site
npm install
npm run dev      # http://localhost:3000
```

The dev server picks the `BASE_PATH` env var as the basePath; if unset, it defaults to `/defenseclaw` to mirror the GitHub Pages deployment. Run with `BASE_PATH=` to develop with no basePath:

```bash
BASE_PATH= npm run dev
```

## Build

```bash
BASE_PATH=/defenseclaw npm run build       # static export to ./out
npx serve out                              # smoke-test the export
```

The build pre-renders every docs page, every dynamic OG image, the FlexSearch index, the sitemap, robots.txt, the `llms.txt` + `llms-full.txt` corpora, and a per-page `llms.md` Markdown sibling next to every `index.html` (emitted by the `postbuild` script).

## Quality gates

```bash
npm run lint                    # next lint
npm run validate-links          # static link checker (next-validate-link, hermetic)
npm run check-diagram-widths    # postbuild gate against the article-column budget
```

`validate-links` walks every `.mdx` under `content/docs/`, builds a slug catalog, and validates every `<a href>` plus `<Card href>` reference against it. Internal-only — never hits the network — so it's safe to run in pre-merge CI.

`check-diagram-widths` runs automatically as part of `postbuild` after `npm run build`. It walks every static HTML page under `out/`, extracts every `<Flow>` / `<Sequence>` natural width from the lightbox `data-natural-width` attribute, and:

- Warns above **1168px** (the article column max-width on `xl:` breakpoints).
- **Fails** above **1500px** unless the diagram opted in via `<Flow oversize />` / `<Sequence oversize />`.

Authoring contract for new diagrams lives in [`components/diagram/AUTHORING.md`](components/diagram/AUTHORING.md).

## Authoring

- All MDX lives under `content/docs/`. Add a page by dropping an MDX file and listing it in the local `meta.json`.
- Frontmatter contract is defined in `source.config.ts` — extends Fumadocs' built-in schema with optional `keywords`, `updatedAt`, and `authors` arrays.
- The MDX components registry lives in `components/mdx-components.tsx`. Anything you reference unqualified in MDX (`<Tabs>`, `<Steps>`, `<Flow>`, `<Sequence>`, `<CapabilityMatrix>`, ...) must be exported from there.

## SEO assets

| File | Purpose |
| --- | --- |
| `app/sitemap.ts` | XML sitemap. Driven by Fumadocs `source.getPages()`. |
| `app/robots.ts` | robots.txt. Allows every major AI ingestion bot. |
| `app/llms.txt/route.ts` | Index of the docs corpus per [llmstxt.org](https://llmstxt.org). Advertises both human URLs and per-page `llms.md` URLs. |
| `app/llms-full.txt/route.ts` | Full processed-Markdown corpus (one-fetch ingestion). Uses Fumadocs's `getText('processed')` via `lib/get-llm-text.ts`. |
| `scripts/build-page-markdown.ts` | Postbuild step that drops a per-page `llms.md` next to each page's `index.html`. Loader-free — walks `content/docs/` directly. |
| `app/api/search/route.ts` | Static FlexSearch index (`fumadocs-core/search/flexsearch`). The dialog at `components/search.tsx` queries it through `flexsearchStaticClient`. |
| `app/icon.svg` | Cisco-blue bridge mark used for favicons + browser tab icon. |
| `app/docs-og/[...slug]/route.tsx` | Per-page OG images, 1200x630 PNG, pre-rendered at build time. |
| `components/structured-data.tsx` | JSON-LD: Organization, WebSite, BreadcrumbList, TechArticle, SoftwareSourceCode, FAQPage. |

## Deployment

The `docs-site.yml` workflow at the repo root builds with `BASE_PATH=/defenseclaw` and deploys via `actions/deploy-pages` on every push to `main`. Custom domain? Set `BASE_PATH=` and update `SITE_URL` in the workflow.

## Not maintained here

The legacy `docs/` Markdown corpus at the repo root is **not** mirrored or replaced by this site. It stays for historical reference and per-feature deep dives that have not yet been re-authored. New documentation should land under `docs-site/content/docs/`.
