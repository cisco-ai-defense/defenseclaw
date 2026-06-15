import { createMDX } from 'fumadocs-mdx/next';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const withMDX = createMDX();
const rootDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = dirname(rootDir);

const rawBase = process.env.BASE_PATH ?? '/defenseclaw';
// Empty string is the convention for "no basePath" in Next.js. Treat
// "/" as equivalent to empty so contributors can run with BASE_PATH=/
// without breaking asset URLs.
const basePath = rawBase === '/' || rawBase === '' ? '' : rawBase;

/** @type {import('next').NextConfig} */
const config = {
  reactStrictMode: true,
  output: 'export',
  trailingSlash: true,
  basePath,
  // assetPrefix needs the trailing slash so /_next/* asset URLs resolve
  // correctly under GitHub Pages' subpath hosting.
  assetPrefix: basePath ? `${basePath}/` : undefined,
  images: {
    // Required for static export — Next's image optimizer needs a server.
    unoptimized: true,
  },
  turbopack: {
    root: repoRoot,
    resolveAlias: {
      tailwindcss: `${rootDir}/node_modules/tailwindcss/index.css`,
    },
  },
  experimental: {
    // We render mermaid as a client component, so server bundling stays clean.
    optimizePackageImports: ['fumadocs-ui', 'fumadocs-core'],
  },
  // Surface the basePath into client + server runtime so links and OG image
  // routes can compose absolute URLs without environment-specific code.
  env: {
    NEXT_PUBLIC_BASE_PATH: basePath,
    NEXT_PUBLIC_SITE_URL:
      process.env.SITE_URL ?? 'https://cisco-ai-defense.github.io/defenseclaw',
  },
};

export default withMDX(config);
