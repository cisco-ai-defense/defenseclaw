# DefenseClaw documentation site

Cisco · DefenseClaw narrative documentation, built with [Fumadocs](https://www.fumadocs.dev) on top of Next.js. Statically exported and deployed to GitHub Pages on every push to `main`.

## Local development

```bash
cd docs-site
npm ci
npm run dev      # http://localhost:3000/defenseclaw/
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
npm run validate-links          # internal MDX links and anchors
npm run validate-snippets       # bash syntax in docs/ and site shell fences
npm run test:policy-creator      # policy-creator unit tests
npm run test:feature-demos       # feature-demo data/component tests
npm run build                    # static export plus postbuild checks
```

`validate-links` walks every `.mdx` under `content/docs/`, builds a slug catalog, and validates every `<a href>` plus `<Card href>` reference against it. Internal-only — never hits the network — so it's safe to run in pre-merge CI.

`check-diagram-widths` runs automatically as part of `postbuild` after `npm run build`. It walks every static HTML page under `out/`, extracts every `<Flow>` / `<Sequence>` natural width from the lightbox `data-natural-width` attribute, and:

- Warns above the **840px** ideal article-canvas width.
- **Fails** above **1168px** unless the diagram opted in via `<Flow oversize />` / `<Sequence oversize />`.

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

The [`.github/workflows/docs-site.yml`](../.github/workflows/docs-site.yml) workflow builds with `BASE_PATH=/defenseclaw` and deploys via `actions/deploy-pages` on every push to `main`. Custom domain? Set `BASE_PATH=` and update `SITE_URL` in the workflow.

## Documentation ownership

End-user installation, setup, workflows, capabilities, and product reference are
canonical under `content/docs/` and published at
[`https://cisco-ai-defense.github.io/defenseclaw/docs/`](https://cisco-ai-defense.github.io/defenseclaw/docs/).
Repository Markdown is reserved for contributor workflows, implementation and
architecture details, design/history, test fixtures, and package-local context.
It should link to the canonical site page instead of repeating user-facing
instructions. When product behavior changes, update the relevant MDX in the
same change.
