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

## Support matrix data

Every "what works where" table on the site renders from one typed file, `data/support-matrix.ts`:

- the connector-by-OS table on `/docs/support-matrix`, the "Platform support" section of the connectors index, and the one-line `<ConnectorSupport id="...">` strip on each connector page;
- the feature-by-edition table (`/docs/support-matrix#features`);
- the enterprise route table (`/docs/support-matrix#enterprise`).

The renderers live in `components/support-matrix/`. Edit the data file, never the tables in MDX.

Where the values come from:

| Field | Source |
| --- | --- |
| OS allowed at all | `internal/gateway/connector/platform_support.go` |
| Minimum agent version | `cli/defenseclaw/inventory/hook_contracts.json` (`agent_version`), plus `internal/enterprisehooks/agent_floor_standalone.go` for floors that are not gated per user |
| Block, native ask, fail closed | imported from `data/capability-matrix.json` (do not edit that file for the matrix; Go tests read it) |
| Enterprise route | `RouteFor` in `internal/enterprisepolicy/types.go` |
| Status | the release certification results |

Status rules: a cell is `supported` only when the code allows it **and** a live certification test of that edition, OS and surface passed. If the code allows it but nothing was verified live, it is `preview`. If the code refuses it, it is `unsupported`. If the edition doesn't include the feature, it is `not-offered`. Never mark a cell `supported` by hand without a passing live test.

Regenerating before a release:

1. Run the maintainers' matrix generator against the current certification results. It is kept outside this repository with the rest of the certification tooling. Its preview mode prints the changes, and its write mode rewrites the `BEGIN GENERATED` block in `data/support-matrix.ts` in place.
2. The generator also sets `asOf` to the date of the snapshot, which the table footers print. Don't edit the generated block by hand.
3. Run `npm run build` and look over `/docs/support-matrix`. The diff in `support-matrix.ts` should only touch statuses and `asOf`, unless a connector or platform was added in code.

OpenClaw, ZeptoClaw (proxy mode) and the Copilot VS Code extension are left out of these tables on purpose. Their own pages are unchanged.

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
