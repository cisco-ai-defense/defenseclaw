import './global.css';
import type { Metadata, Viewport } from 'next';
import localFont from 'next/font/local';
import { canonicalUrl, siteUrl, defaultKeywords, site } from '@/lib/site';
import { OrganizationSchema, WebSiteSchema, SoftwareSourceCodeSchema } from '@/components/structured-data';
import ClientRootProvider from '@/components/root-provider';

// Pin local WOFF2 assets so static builds and browsers never depend on
// Google Fonts. `swap` renders text while each font loads.
const inter = localFont({
  src: '../node_modules/@fontsource-variable/inter/files/inter-latin-wght-normal.woff2',
  weight: '100 900',
  display: 'swap',
  variable: '--font-sans',
});

const mono = localFont({
  src: '../node_modules/@fontsource-variable/jetbrains-mono/files/jetbrains-mono-latin-wght-normal.woff2',
  weight: '100 800',
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
    url: canonicalUrl(),
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
    canonical: canonicalUrl(),
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
        {/* The "Official Cisco project · cisco-ai-defense/defenseclaw"
            rainbow banner used to live here. The same affordances —
            repo link + star/fork counts + the official-Cisco framing
            — already render in the navbar and on the landing-page
            hero pill, so the banner was redundant chrome. Removing it
            also reclaims ~28px of vertical space above the fold on
            every page. */}
        <ClientRootProvider>{children}</ClientRootProvider>
      </body>
    </html>
  );
}
