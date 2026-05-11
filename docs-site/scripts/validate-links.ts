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
  const segs = noExt.split('/');
  if (segs[segs.length - 1] === 'index') segs.pop();
  return segs;
}

function slugsToUrl(slugs: string[]): string {
  return slugs.length === 0 ? '/docs/' : `/docs/${slugs.join('/')}/`;
}

// Pull h2/h3 headings from a Markdown body so the validator can
// match `#anchor` references. Mirrors GitHub's slug rules
// (lowercase, dashes, strip non-word chars) — close enough to
// Fumadocs's TOC-builder for practical link checking.
function extractHeadings(body: string): string[] {
  const slugs: string[] = [];
  for (const line of body.split(/\r?\n/)) {
    const m = /^(#{1,6})\s+(.+?)\s*$/.exec(line);
    if (!m) continue;
    if (m[1].length < 2) continue; // skip h1 (page title)
    const slug = m[2]
      .toLowerCase()
      .replace(/[^\w\s-]/g, '')
      .trim()
      .replace(/\s+/g, '-');
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

async function checkLinks() {
  const pages = await buildPages();
  const scanned = await scanURLs({
    preset: 'next',
    populate: {
      'docs/[[...slug]]': pages.map((page) => ({
        value: { slug: page.slugs },
        hashes: page.headings,
      })),
    },
  });

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
