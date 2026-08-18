import { canonicalUrl, site, siteUrl } from '@/lib/site';

// Centralised JSON-LD emitter. Each helper returns a `<script>` tag
// with `application/ld+json`, so they can be composed at any layer
// (root layout, docs page, individual MDX page) without leaking the
// underlying schema.org shape into surrounding markup. We
// deliberately avoid `next/script` because static export needs the
// payload inlined into the HTML — search engines should not have to
// wait for client-side hydration to discover entities.

interface JsonLdProps {
  data: Record<string, unknown> | Record<string, unknown>[];
}

function JsonLd({ data }: JsonLdProps) {
  return (
    <script
      type="application/ld+json"
      // eslint-disable-next-line react/no-danger -- payload is built locally from typed inputs
      dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }}
    />
  );
}

export function OrganizationSchema() {
  return (
    <JsonLd
      data={{
        '@context': 'https://schema.org',
        '@type': 'Organization',
        name: site.organization.name,
        legalName: site.organization.legalName,
        url: site.organization.url,
        logo: `${siteUrl}${site.organization.logo}`,
        sameAs: site.organization.sameAs,
      }}
    />
  );
}

export function WebSiteSchema() {
  return (
    <JsonLd
      data={{
        '@context': 'https://schema.org',
        '@type': 'WebSite',
        name: `Cisco · ${site.name}`,
        url: canonicalUrl(),
      }}
    />
  );
}

export function SoftwareSourceCodeSchema() {
  return (
    <JsonLd
      data={{
        '@context': 'https://schema.org',
        '@type': 'SoftwareSourceCode',
        name: site.name,
        codeRepository: site.repo.url,
        programmingLanguage: ['Python', 'Go', 'TypeScript'],
        license: site.product.licenseUrl,
        author: {
          '@type': 'Organization',
          name: site.organization.name,
          url: site.organization.url,
        },
      }}
    />
  );
}

export function BreadcrumbSchema({ crumbs }: { crumbs: { name: string; url: string }[] }) {
  if (crumbs.length === 0) return null;
  return (
    <JsonLd
      data={{
        '@context': 'https://schema.org',
        '@type': 'BreadcrumbList',
        itemListElement: crumbs.map((c, i) => ({
          '@type': 'ListItem',
          position: i + 1,
          name: c.name,
          item: canonicalUrl(c.url),
        })),
      }}
    />
  );
}

export function TechArticleSchema({
  title,
  description,
  url,
  dateModified,
}: {
  title: string;
  description: string;
  url: string;
  dateModified?: string;
}) {
  return (
    <JsonLd
      data={{
        '@context': 'https://schema.org',
        '@type': 'TechArticle',
        headline: title,
        description,
        mainEntityOfPage: { '@type': 'WebPage', '@id': url },
        author: { '@type': 'Organization', name: site.organization.name, url: site.organization.url },
        publisher: {
          '@type': 'Organization',
          name: site.organization.name,
          logo: { '@type': 'ImageObject', url: `${siteUrl}${site.organization.logo}` },
        },
        // Article dates are optional. A shared placeholder date is less useful
        // than omitting the property; publish a modified date only when the
        // page has explicit provenance in frontmatter.
        ...(dateModified ? { dateModified } : {}),
      }}
    />
  );
}

export function FAQPageSchema({
  questions,
}: {
  questions: { question: string; answer: string }[];
}) {
  return (
    <JsonLd
      data={{
        '@context': 'https://schema.org',
        '@type': 'FAQPage',
        mainEntity: questions.map((q) => ({
          '@type': 'Question',
          name: q.question,
          acceptedAnswer: { '@type': 'Answer', text: q.answer },
        })),
      }}
    />
  );
}

export function SoftwareApplicationSchema() {
  return (
    <JsonLd
      data={{
        '@context': 'https://schema.org',
        '@type': 'SoftwareApplication',
        name: site.product.name,
        applicationCategory: site.product.applicationCategory,
        operatingSystem: site.product.operatingSystem,
        offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
        url: canonicalUrl(),
        publisher: { '@type': 'Organization', name: site.organization.name },
        license: site.product.licenseUrl,
      }}
    />
  );
}
