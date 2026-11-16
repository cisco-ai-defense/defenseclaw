// Static link validator for the docs site. Walks every MDX page,
// resolves `<a href>` and the `href` attribute on registered MDX
// components (e.g. `<Card href="/docs/...">`) against the live page
// tree, and reports anything that 404s.
//
// We deliberately avoid importing `lib/source` here because it would
// transitively import every MDX file (and any image referenced from
// those files) through the Fumadocs MDX bundler — that machinery
// only runs reliably inside Next.js. Walking `content/docs/`
// directly lets us build the slug catalog without booting the
// bundler.
//
// Run with `npm run validate-links`. The check is hermetic — it
// never touches the network for internal links — so it can ship in
// pre-merge CI without flaking on flaky upstreams.
import {
  type FileObject,
  printErrors,
  scanURLs,
  validateFiles,
} from 'next-validate-link';
import { readFile, readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import GithubSlugger from 'github-slugger';
import { legacyRedirects } from '../lib/redirects';

const CONTENT_ROOT = resolve(process.cwd(), 'content/docs');

interface MdxFile {
  absolutePath: string;
  slugs: string[];
  url: string;
  content: string;
  headings: string[];
}

async function listMdxFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...(await listMdxFiles(full)));
    } else if (entry.isFile() && entry.name.endsWith('.mdx')) {
      out.push(full);
    }
  }
  return out;
}

function pathToSlugs(absPath: string): string[] {
  const relPath = relative(CONTENT_ROOT, absPath).replace(/\\/g, '/');
  const noExt = relPath.replace(/\.mdx$/, '');
  // A "(group)" folder groups pages in the sidebar without adding a URL
  // segment, as in Fumadocs's own slug builder.
  const segs = noExt.split('/').filter((seg) => !/^\(.+\)$/.test(seg));
  if (segs[segs.length - 1] === 'index') segs.pop();
  return segs;
}

function slugsToUrl(slugs: string[]): string {
  return slugs.length === 0 ? '/docs/' : `/docs/${slugs.join('/')}/`;
}

// Pull headings from a Markdown body so the validator can match `#anchor`
// references. This mirrors Fumadocs's remark-heading plugin, which sets the
// ids on the built pages: a trailing `[#custom-id]` wins, otherwise the
// heading's plain text goes through github-slugger, with one slugger per page
// so repeated headings get `-1`, `-2` suffixes. Lines inside fenced code
// blocks are not headings.
function headingText(raw: string): string {
  return raw
    .replace(/`([^`]*)`/g, '$1')
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/<[^>]+>/g, '')
    .replace(/(\*\*|__|\*|_)(\S(?:.*?\S)?)\1/g, '$2')
    .replace(/\\([\\`*_{}[\]()#+\-.!<>|])/g, '$1');
}

function extractHeadings(body: string): string[] {
  const slugger = new GithubSlugger();
  const slugs: string[] = [];
  let fence: string | null = null;
  for (const line of body.split(/\r?\n/)) {
    const fenceMatch = /^\s*(`{3,}|~{3,})/.exec(line);
    if (fenceMatch) {
      if (fence === null) fence = fenceMatch[1];
      else if (line.trim().startsWith(fence)) fence = null;
      continue;
    }
    if (fence !== null) continue;
    const m = /^(#{1,6})\s+(.+?)\s*$/.exec(line);
    if (!m) continue;
    const custom = /\s*\[#([^\]]+?)\]\s*$/.exec(m[2]);
    const slug = custom ? custom[1] : slugger.slug(headingText(m[2]));
    if (slug) slugs.push(slug);
  }
  return slugs;
}

// `next-validate-link` parses the content as MDX. Authors freely
// drop placeholder syntax like `<connector>` in YAML frontmatter
// description fields (where Next/Fumadocs MDX doesn't care because
// frontmatter is parsed as YAML, not body MDX). Stripping the
// frontmatter block before handing content to the validator keeps
// those legal-but-MDX-unfriendly fields from crashing the parser.
function stripFrontmatter(raw: string): string {
  const m = /^---\r?\n[\s\S]*?\r?\n---\r?\n?/.exec(raw);
  return m ? raw.slice(m[0].length) : raw;
}

async function buildPages(): Promise<MdxFile[]> {
  if (!existsSync(CONTENT_ROOT)) {
    throw new Error(
      `[validate-links] ${CONTENT_ROOT} not found — is this docs-site/?`,
    );
  }
  const paths = await listMdxFiles(CONTENT_ROOT);
  const out: MdxFile[] = [];
  for (const absolutePath of paths) {
    const raw = await readFile(absolutePath, 'utf-8');
    const content = stripFrontmatter(raw);
    const slugs = pathToSlugs(absolutePath);
    out.push({
      absolutePath,
      slugs,
      url: slugsToUrl(slugs),
      content,
      headings: extractHeadings(content),
    });
  }
  return out;
}

// Redirect hygiene (lib/redirects.ts). A key that is also a real page would
// never be served as a redirect; a value that is itself a key would chain;
// an anchor in a value is overwritten by the old URL's #hash.
function checkRedirects(pages: MdxFile[]): string[] {
  const real = new Set(pages.map((page) => page.slugs.join('/')));
  const keys = new Set(Object.keys(legacyRedirects));
  const errors: string[] = [];
  for (const [key, value] of Object.entries(legacyRedirects)) {
    if (real.has(key)) {
      errors.push(`redirect key "${key}" is also a real page; remove one of them`);
    }
    if (value.includes('#')) {
      errors.push(`redirect "${key}" target "${value}" must not carry an anchor`);
    }
    const target = value.replace(/^\/docs\/?/, '').replace(/\/$/, '');
    if (keys.has(target)) {
      errors.push(`redirect "${key}" points at "${value}", which is itself a redirect`);
    }
  }
  return errors;
}

async function checkLinks() {
  const pages = await buildPages();
  const redirectErrors = checkRedirects(pages);
  if (redirectErrors.length > 0) {
    for (const message of redirectErrors) console.error(`[validate-links] ${message}`);
    process.exit(1);
  }
  // Every docs page and every redirect slug (the site pre-renders a "moved"
  // page for each one) is a valid link target.
  const docsRoutes = [
    ...pages.map((page) => ({
      value: { slug: page.slugs },
      hashes: page.headings,
    })),
    ...Object.keys(legacyRedirects).map((key) => ({
      value: { slug: key.split('/') },
      hashes: [] as string[],
    })),
  ];
  const scanned = await scanURLs({
    preset: 'next',
    // Pass the public catch-all route explicitly. tinyglobby returns
    // POSIX-style paths even on Windows, while node:path.dirname uses the
    // host separator; relying on app-directory discovery therefore collapsed
    // the route to "/" on Windows and reported every valid docs link as a
    // 404. join() gives next-validate-link the separator it expects on either
    // platform.
    pages: [join('docs', '[[...slug]]', 'page.tsx')],
    populate: {
      'docs/[[...slug]]': docsRoutes,
      // The same route as app-directory discovery finds it. Without this
      // key the discovered route gets the default population, a /docs/(.+)
      // fallback that accepts every docs link, real or not.
      '(docs)/docs/[[...slug]]': docsRoutes,
    },
  });

  // The site is exported with trailing slashes, so /docs/a and /docs/a/ are
  // the same page. The scan registers the bare form only.
  for (const [url, meta] of [...scanned.urls]) {
    if (!url.endsWith('/')) scanned.urls.set(`${url}/`, meta);
  }

  // Negative check: a docs URL with no page must not resolve. This fails the
  // run if a catch-all fallback ever accepts every docs link again.
  const probes = ['/docs/validate-links-negative-probe', '/docs/validate-links-negative-probe/'];
  const probe = probes.find(
    (url) => scanned.urls.has(url) || scanned.fallbackUrls.some((fallback) => fallback.url.test(url)),
  );
  if (probe) {
    console.error(
      `[validate-links] the route scan accepts ${probe}, which has no page: a catch-all fallback would hide broken links`,
    );
    process.exit(1);
  }

  const files: FileObject[] = pages.map((page) => ({
    path: page.absolutePath,
    content: page.content,
    url: page.url,
  }));

  printErrors(
    await validateFiles(files, {
      scanned,
      markdown: {
        // The MDX components below accept `href` and Fumadocs's
        // default validator only knows about `<a>`. Adding them here
        // keeps "broken Card link" caught before merge.
        components: {
          Card: { attributes: ['href'] },
          Cards: { attributes: ['href'] },
        },
      },
      // The docs corpus uses leading-slash URLs almost exclusively.
      // We ask the validator to treat relative refs as URLs (resolved
      // against the page's own URL) so a stray `./neighbour` still
      // gets checked instead of being silently ignored.
      checkRelativePaths: 'as-url',
    }),
    true,
  );
}

void checkLinks();
