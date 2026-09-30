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
import { legacyRedirects, splitTarget } from '../lib/redirects';

const CONTENT_ROOT = resolve(process.cwd(), 'content/docs');

interface MdxFile {
  absolutePath: string;
  slugs: string[];
  url: string;
  content: string;
  headings: string[];
  // Lines removed with the frontmatter, to report file line numbers.
  lineOffset: number;
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

// Pull headings from a Markdown body so the validator can match
// `#anchor` references. This mirrors Fumadocs's remark-heading
// plugin: an explicit `## Title [#custom-id]` wins; otherwise the
// flattened heading text goes through github-slugger, with one
// slugger per page so duplicate headings get `-1`, `-2`, ...
// Headings inside fenced code blocks are ignored.
const CUSTOM_ID = /\s*\[#([^\]]+?)]\s*$/;

// Approximate mdast flattening: keep the text of inline code, link
// text and JSX children; drop markup that contributes no text.
function flattenInline(text: string): string {
  const parts = text.split(/(`+)([\s\S]*?)\1/);
  let out = '';
  // split() with two capture groups yields [plain, ticks, code, plain, ...].
  for (let i = 0; i < parts.length; i += 3) {
    out += stripMarkup(parts[i] ?? '');
    if (i + 2 < parts.length) out += parts[i + 2];
  }
  return out;
}

function stripMarkup(text: string): string {
  return text
    .replace(/!\[([^\]]*)]\([^)]*\)/g, '$1')
    .replace(/\[([^\]]*)]\([^)]*\)/g, '$1')
    .replace(/<\/?[A-Za-z][^>]*>/g, '')
    .replace(/(\*\*|__)(.+?)\1/g, '$2')
    .replace(/(^|[^\w*])\*(?!\s)([^*]+?)\*(?!\w)/g, '$1$2')
    .replace(/(^|[^\w])_(?!\s)([^_]+?)_(?![\w])/g, '$1$2')
    .replace(/\\([\\`*_{}\[\]()#+\-.!<>|~])/g, '$1');
}

function extractHeadings(body: string): string[] {
  const slugger = new GithubSlugger();
  const slugs: string[] = [];
  let fence: { char: string; len: number } | null = null;
  for (const line of body.split(/\r?\n/)) {
    const f = /^\s*(`{3,}|~{3,})/.exec(line);
    if (f) {
      const char = f[1][0];
      const len = f[1].length;
      if (!fence) fence = { char, len };
      else if (fence.char === char && len >= fence.len && /^\s*(`+|~+)\s*$/.test(line)) fence = null;
      continue;
    }
    if (fence) continue;
    const m = /^ {0,3}(#{1,6})\s+(.+?)\s*#*\s*$/.exec(line);
    if (!m) continue;
    let text = m[2];
    const custom = CUSTOM_ID.exec(text);
    if (custom) {
      slugs.push(custom[1]);
      continue;
    }
    text = flattenInline(text);
    const slug = slugger.slug(text);
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
      lineOffset: raw.slice(0, raw.length - content.length).split('\n').length - 1,
    });
  }
  return out;
}

function normalizePath(path: string): string {
  const trimmed = path.replace(/\/+$/, '');
  return `${trimmed}/`;
}

// Legacy redirects (lib/redirects.ts). Returns the number of errors.
function checkRedirects(pages: MdxFile[]): number {
  let errors = 0;
  const byUrl = new Map(pages.map((page) => [page.url, page]));
  for (const [key, { to }] of Object.entries(legacyRedirects)) {
    const sourceUrl = `/docs/${key}/`;
    if (byUrl.has(sourceUrl)) {
      console.warn(
        `[validate-links] warning: redirect source ${sourceUrl} is still a real page; the page wins until it is removed.`,
      );
    }
    const { path, hash } = splitTarget(to);
    const target = byUrl.get(normalizePath(path));
    if (!target) {
      console.error(`[validate-links] redirect ${sourceUrl} -> ${to}: target page does not exist.`);
      errors += 1;
    } else if (hash && !target.headings.includes(hash.slice(1))) {
      console.error(`[validate-links] redirect ${sourceUrl} -> ${to}: anchor ${hash} does not exist on the target.`);
      errors += 1;
    }
  }

  // Content must link the new URL, never a redirect source.
  const keys = Object.keys(legacyRedirects)
    .sort((a, b) => b.length - a.length)
    .map((key) => key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  const linkPattern = new RegExp(`/docs/(${keys.join('|')})(?=[/#?)"'\\s>]|$)`, 'g');
  for (const page of pages) {
    const lines = page.content.split(/\r?\n/);
    lines.forEach((line, index) => {
      for (const match of line.matchAll(linkPattern)) {
        const rel = relative(process.cwd(), page.absolutePath);
        console.error(
          `[validate-links] ${rel}:${index + 1 + page.lineOffset}: links redirect source /docs/${match[1]}; link ${legacyRedirects[match[1]].to} instead.`,
        );
        errors += 1;
      }
    });
  }
  return errors;
}

async function checkLinks() {
  const pages = await buildPages();
  const redirectErrors = checkRedirects(pages);
  const realUrls = new Set(pages.map((page) => page.url));
  // Redirect sources without a real page are still served (as a
  // redirect), so they are valid URLs; checkRedirects reports any
  // content link that uses one.
  const redirectEntries = Object.keys(legacyRedirects)
    .filter((key) => !realUrls.has(`/docs/${key}/`))
    .map((key) => ({ value: { slug: key.split('/') }, hashes: [] as string[] }));
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
      'docs/[[...slug]]': pages.map((page) => ({
        value: { slug: page.slugs },
        hashes: page.headings,
      })).concat(redirectEntries),
    },
  });

  const files: FileObject[] = pages.map((page) => ({
    path: page.absolutePath,
    content: page.content,
    url: page.url,
  }));

  const results = await validateFiles(files, {
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
  });
  printErrors(results, false);
  const linkErrors = results.reduce((n, r) => n + r.errors.length, 0);
  if (linkErrors + redirectErrors > 0) {
    console.error(
      `[validate-links] ${linkErrors} broken link(s), ${redirectErrors} redirect error(s).`,
    );
    process.exit(1);
  }
}

void checkLinks();
