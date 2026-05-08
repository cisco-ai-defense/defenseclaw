import './global.css';
import type { Metadata, Viewport } from 'next';
import { Banner } from 'fumadocs-ui/components/banner';
import { JetBrains_Mono, Inter } from 'next/font/google';
import { site, siteUrl, defaultKeywords } from '@/lib/site';
import { OrganizationSchema, WebSiteSchema, SoftwareSourceCodeSchema } from '@/components/structured-data';
import ClientRootProvider from '@/components/root-provider';
import RepoStats from '@/components/repo-stats';

// Self-hosted via next/font so we never hit a runtime CDN — both for
// privacy (no third-party calls from end-user browsers) and to keep
// CWV stable. The `display: 'swap'` keeps text rendering before the
// custom face is ready, avoiding a FOIT cliff on the landing page.
const inter = Inter({
  subsets: ['latin'],
  display: 'swap',
  variable: '--font-sans',
});

const mono = JetBrains_Mono({
  subsets: ['latin'],
  display: 'swap',
  variable: '--font-mono',
});

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title: {
    default: `${site.name} — ${site.tagline}`,
    template: `%s · ${site.name}`,
  },
  description: site.description,
  applicationName: site.name,
  generator: 'Fumadocs',
  keywords: defaultKeywords,
  authors: [{ name: 'Cisco', url: site.organization.url }],
  creator: 'Cisco Systems, Inc.',
  publisher: 'Cisco Systems, Inc.',
  formatDetection: {
    email: false,
    address: false,
    telephone: false,
  },
  openGraph: {
    type: 'website',
    siteName: `Cisco · ${site.name}`,
    title: `${site.name} — ${site.tagline}`,
    description: site.description,
    url: siteUrl,
    images: [
      {
        url: '/docs-og/index.png',
        width: 1200,
        height: 630,
        alt: `Cisco · ${site.name}`,
      },
    ],
    locale: 'en_US',
  },
  twitter: {
    card: 'summary_large_image',
    title: `${site.name} — ${site.tagline}`,
    description: site.description,
    creator: '@CiscoSecure',
    site: '@CiscoSecure',
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      'max-image-preview': 'large',
      'max-snippet': -1,
      'max-video-preview': -1,
    },
  },
  alternates: {
    canonical: '/',
  },
};

export const viewport: Viewport = {
  themeColor: [
    { media: '(prefers-color-scheme: dark)', color: '#0a0a0a' },
    { media: '(prefers-color-scheme: light)', color: '#ffffff' },
  ],
  width: 'device-width',
  initialScale: 1,
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html
      lang="en"
      className={`${inter.variable} ${mono.variable}`}
      suppressHydrationWarning
    >
      <body className="flex min-h-screen flex-col font-sans antialiased">
        {/* JSON-LD lives at the document root so every page inherits
         * the Organization + WebSite + SoftwareSourceCode entities.
         * Page-level breadcrumbs and TechArticle schemas are layered
         * on by the docs layout. */}
        <OrganizationSchema />
        <WebSiteSchema />
        <SoftwareSourceCodeSchema />
        {/* Custom client-side provider wires the FlexSearch-backed
            SearchDialog into Fumadocs's RootProvider. The static
            JSON index is emitted by app/api/search/route.ts and the
            client picks it up via the basePath-aware URL configured
            inside components/search.tsx. */}
        <ClientRootProvider>
          <Banner
            id="cisco-official"
            variant="rainbow"
            changeLayout={false}
            className="text-center text-xs font-medium tracking-wide"
          >
            <span className="opacity-90">Official Cisco project</span>
            <span aria-hidden className="mx-2 opacity-60">
              ·
            </span>
            <span>
              <a
                href={site.repo.url}
                className="underline-offset-2 hover:underline"
                rel="noreferrer"
              >
                {site.repo.owner}/{site.repo.name}
              </a>
            </span>
            {/* Stars + forks fetched once at build time, refreshed on
                mount in the browser. Renders nothing if both calls
                fail so the banner gracefully falls back. */}
            <RepoStats />
          </Banner>
          {children}
        </ClientRootProvider>
      </body>
    </html>
  );
}
