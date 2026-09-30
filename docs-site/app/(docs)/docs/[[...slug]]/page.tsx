import { source } from '@/lib/source';
import { canonicalUrl, site, defaultKeywords } from '@/lib/site';
import { DocsPage, DocsBody, DocsTitle, DocsDescription } from 'fumadocs-ui/page';
import { notFound } from 'next/navigation';
import type { Metadata } from 'next';
import { mdxComponents } from '@/components/mdx-components';
import { BreadcrumbSchema, TechArticleSchema } from '@/components/structured-data';
import { ConnectorBrand } from '@/components/connector-brand';
import matrix from '@/data/capability-matrix.json';
import { legacyRedirects, splitTarget } from '@/lib/redirects';
import { LegacyRedirect } from '@/components/legacy-redirect';

const connectorIds = new Set(matrix.connectors.map((connector) => connector.id));

interface PageParams {
  params: Promise<{ slug?: string[] }>;
}

export default async function Page({ params }: PageParams) {
  const slug = (await params).slug;
  const page = source.getPage(slug);
  if (!page) {
    const redirect = legacyRedirects[(slug ?? []).join('/')];
    if (redirect) return <LegacyRedirect to={redirect.to} title={redirect.title} />;
    notFound();
  }

  const MDX = page.data.body;
  const url = canonicalUrl(page.url);

  // Breadcrumb segments are derived from the page tree, not the URL,
  // so dynamic intermediate folders (e.g. "stories") still surface
  // their human-friendly title rather than the slug.
  const crumbs = buildBreadcrumbs(slug ?? []);
  const connectorId =
    slug?.length === 2 && slug[0] === 'connectors' && connectorIds.has(slug[1])
      ? slug[1]
      : null;

  // Default to wide-article (`full: true`) for every docs page. Most of
  // our pages contain at least one wide artifact — capability matrix,
  // CLI flag tables, Flow diagrams — and the narrower 900px column
  // forces horizontal scrolling on 1920px+ monitors. Authors who want
  // the narrower prose-only column for a long-form story page can
  // still opt out explicitly by adding `full: false` to that page's
  // frontmatter.
  const fullWidth = page.data.full ?? true;

  return (
    <DocsPage
      toc={page.data.toc}
      full={fullWidth}
      tableOfContent={{
        enabled: page.data.toc.length > 0,
        style: 'clerk',
      }}
      role="main"
    >
      <BreadcrumbSchema crumbs={crumbs} />
      <TechArticleSchema
        title={page.data.title}
        description={page.data.description ?? site.description}
        url={url}
        dateModified={page.data.updatedAt}
      />
      <DocsTitle>
        {connectorId ? (
          <span className="docs-title-with-brand">
            <ConnectorBrand id={connectorId} />
            <span>{page.data.title}</span>
          </span>
        ) : page.data.title}
      </DocsTitle>
      {page.data.description ? (
        <DocsDescription>{page.data.description}</DocsDescription>
      ) : null}
      <DocsBody>
        <MDX components={mdxComponents} />
      </DocsBody>
    </DocsPage>
  );
}

export async function generateStaticParams() {
  // Legacy URLs that no longer have a real page get a static redirect
  // page. The sitemap, llms.txt and OG routes enumerate `source` pages
  // only, so these stay out of them.
  const redirectParams = Object.keys(legacyRedirects)
    .filter((key) => !source.getPage(key.split('/')))
    .map((key) => ({ slug: key.split('/') }));
  return [...source.generateParams(), ...redirectParams];
}

export async function generateMetadata({ params }: PageParams): Promise<Metadata> {
  const slug = (await params).slug;
  const page = source.getPage(slug);
  if (!page) {
    const redirect = legacyRedirects[(slug ?? []).join('/')];
    if (!redirect) return {};
    const { path } = splitTarget(redirect.to);
    return {
      title: `Moved: ${redirect.title}`,
      robots: { index: false, follow: true },
      alternates: { canonical: canonicalUrl(path) },
    };
  }

  const canonical = canonicalUrl(page.url);
  const ogPath = `/docs-og${
    page.url.endsWith('/') ? page.url.slice(0, -1) : page.url
  }.png`;

  // Per-page canonical URL keeps the indexed surface stable across
  // basePath swaps (project pages → custom domain). The OG image
  // route (see app/docs-og/[...slug]) renders one PNG per docs page
  // at build time so the social card always reflects the current
  // headline.
  return {
    title: page.data.title,
    description: page.data.description ?? site.description,
    keywords: page.data.keywords ?? defaultKeywords,
    alternates: { canonical },
    authors: page.data.authors ?? [{ name: 'Cisco', url: site.organization.url }],
    openGraph: {
      type: 'article',
      title: page.data.title,
      description: page.data.description ?? site.description,
      url: canonical,
      siteName: `Cisco · ${site.name}`,
      images: [
        {
          url: ogPath,
          width: 1200,
          height: 630,
          alt: page.data.title,
        },
      ],
      locale: 'en_US',
    },
    twitter: {
      card: 'summary_large_image',
      title: page.data.title,
      description: page.data.description ?? site.description,
      images: [ogPath],
    },
  };
}

function buildBreadcrumbs(slug: string[]): { name: string; url: string }[] {
  const out: { name: string; url: string }[] = [
    { name: 'Docs', url: '/docs' },
  ];
  let acc = '/docs';
  for (const seg of slug) {
    acc += `/${seg}`;
    const page = source.getPage(acc.replace(/^\/docs\/?/, '').split('/').filter(Boolean));
    // Folder labels can exist in Fumadocs meta without a corresponding
    // landing page. Do not advertise those 404 routes in breadcrumb JSON-LD.
    if (!page) continue;
    out.push({
      name: page.data.title,
      url: acc,
    });
  }
  return out;
}
