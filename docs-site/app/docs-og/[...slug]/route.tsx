import { ImageResponse } from 'next/og';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { source } from '@/lib/source';
import { site } from '@/lib/site';

// Cisco-branded dynamic OpenGraph image. We render at the canonical
// 1200x630 social size with a dark canvas + the Cisco brand accent
// so the unfurled card matches the site visuals. `dynamic =
// 'force-static'` keeps the route compatible with `output: 'export'`
// — Next prerenders one PNG per docs page at build time using
// `generateStaticParams` below.
export const dynamic = 'force-static';
export const contentType = 'image/png';
export const size = { width: 1200, height: 630 };

// Read the Cisco bridge mark from disk once and inline it as a
// data URL so the satori renderer in next/og does not need to hit
// the filesystem (or the network) per page during static export.
async function loadCiscoLogo(): Promise<string> {
  const path = resolve(process.cwd(), 'public/images/cisco-logo.png');
  const bytes = await readFile(path);
  return `data:image/png;base64,${bytes.toString('base64')}`;
}

export async function generateStaticParams() {
  const pages = source.getPages();
  // The OG route is `app/docs-og/[...slug]/route.tsx` and Next stores
  // the `.png` suffix as part of the last slug segment when the
  // request is `/docs-og/some/page.png`. We reproduce that by
  // appending the suffix to the final slug entry.
  return pages.map((p) => {
    // p.url shape: "/docs/foo/bar"
    const segments = p.url.split('/').filter(Boolean); // ["docs","foo","bar"]
    if (segments.length === 0) return { slug: ['index.png'] };
    const last = segments[segments.length - 1];
    return {
      slug: [...segments.slice(0, -1), `${last}.png`],
    };
  });
}

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ slug: string[] }> },
) {
  const { slug } = await params;
  // Strip the trailing ".png" off the final segment so we can resolve
  // the matching docs page via Fumadocs' source loader.
  const cleaned = [...slug];
  const last = cleaned.pop() ?? 'index.png';
  cleaned.push(last.replace(/\.png$/, ''));
  // The OG slug already begins with "docs/...". Drop the leading
  // "docs" so it matches the `getPage(slug)` contract.
  const docsSlug = cleaned[0] === 'docs' ? cleaned.slice(1) : cleaned;
  const page = source.getPage(docsSlug.length > 0 ? docsSlug : undefined);

  const title = page?.data.title ?? site.name;
  const description = page?.data.description ?? site.tagline;
  const section =
    docsSlug.length > 1 ? docsSlug[0].replace(/-/g, ' ').toUpperCase() : 'DOCS';
  const ciscoLogo = await loadCiscoLogo();

  return new ImageResponse(
    (
      <div
        style={{
          height: '100%',
          width: '100%',
          display: 'flex',
          flexDirection: 'column',
          background: 'linear-gradient(135deg, #050a14 0%, #0a1626 70%, #04263b 100%)',
          color: '#fff',
          padding: 64,
          fontFamily: 'sans-serif',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 18 }}>
          {/* eslint-disable-next-line @next/next/no-img-element -- next/og's satori needs a plain <img> */}
          <img
            src={ciscoLogo}
            alt="Cisco"
            width={64}
            height={64}
            style={{ borderRadius: 6 }}
          />
          <div style={{ display: 'flex', flexDirection: 'column', lineHeight: 1 }}>
            <span style={{ fontSize: 28, fontWeight: 900, letterSpacing: -1 }}>
              Cisco
            </span>
            <span style={{ fontSize: 28, fontWeight: 900, letterSpacing: -1, color: '#049fd9' }}>
              {site.name}
            </span>
          </div>
        </div>

        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
          <span
            style={{
              fontSize: 18,
              color: '#049fd9',
              fontWeight: 600,
              letterSpacing: 2,
              marginBottom: 12,
            }}
          >
            {section}
          </span>
          <span
            style={{
              fontSize: title.length > 40 ? 56 : 72,
              fontWeight: 700,
              lineHeight: 1.05,
              letterSpacing: -1.5,
              maxWidth: 980,
            }}
          >
            {title}
          </span>
          {description ? (
            <span
              style={{
                marginTop: 20,
                fontSize: 24,
                lineHeight: 1.4,
                color: '#a4b5c4',
                maxWidth: 940,
              }}
            >
              {description.length > 160 ? `${description.slice(0, 157)}…` : description}
            </span>
          ) : null}
        </div>

        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontSize: 18,
            color: '#7fb8d8',
            borderTop: '1px solid rgba(127,184,216,0.25)',
            paddingTop: 24,
          }}
        >
          <span>github.com/{site.repo.owner}/{site.repo.name}</span>
          <span>Apache-2.0 · Official Cisco project</span>
        </div>
      </div>
    ),
    { ...size },
  );
}
