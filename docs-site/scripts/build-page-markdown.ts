// Postbuild step: emit `<page>/llms.md` next to every page's
// `index.html` in the static export.
//
// Why a script instead of a route handler? Under `output: 'export'`
// + `trailingSlash: true`, dynamic catch-all routes can't emit a
// file at the same path that's also a directory for deeper slugs
// — `/docs/foo` would need to be both a markdown file and the
// folder containing `/docs/foo/bar`. Sidestepping the routing
// machinery entirely lets us write `out/docs/foo/llms.md` next to
// `out/docs/foo/index.html`, no conflicts, no rewrites needed.
//
// We deliberately don't import `lib/source` here — that pulls in
// `.source/server.ts` which static-imports every MDX module via the
// Fumadocs MDX loader, which only works inside Next's bundler.
// Walking `content/docs/` ourselves is loader-free and matches the
// same URL convention that Fumadocs MDX uses (file path → slug).
//
// Wired as `npm run postbuild` so CI / GitHub Pages publish picks
// up the markdown corpus without any extra glue.
import { mkdir, writeFile, readFile, readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { siteUrl } from '../lib/site';

const CONTENT_ROOT = resolve(process.cwd(), 'content/docs');

// Next's static export writes file paths WITHOUT the configured
// `basePath` (the prefix is applied by GitHub Pages at serve time,
// not by the export). We follow the same convention here so the
// llms.md files land next to their HTML siblings — `/docs/foo/`
// resolves to `out/docs/foo/index.html`, and we want
// `out/docs/foo/llms.md`.

interface MdxFile {
  absolutePath: string;
  slugs: string[];
  title: string;
  description?: string;
}

// Recursively collect every `.mdx` file under `content/docs`,
// skipping `meta.json` and any nested directories that should be
// hidden from the docs tree (none today, but keep the filter cheap
// in case authors add `.draft` files later).
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

// Translate a content-root-relative `.mdx` path into the slug array
// used by Fumadocs source. `index.mdx` collapses to its parent dir,
// matching the routing semantics of `[[...slug]]`.
function pathToSlugs(absPath: string): string[] {
  const relPath = relative(CONTENT_ROOT, absPath).replace(/\\/g, '/');
  const noExt = relPath.replace(/\.mdx$/, '');
  const segs = noExt.split('/');
  if (segs[segs.length - 1] === 'index') segs.pop();
  return segs;
}

// Tiny, single-document YAML frontmatter parser — covers the subset
// our docs actually use: leading `---` block, simple `key: value`
// lines, and `key: [list]` / quoted strings. We avoid pulling in
// `gray-matter` to keep the script's dep surface zero.
function parseFrontmatter(raw: string): {
  data: Record<string, string>;
  body: string;
} {
  const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(raw);
  if (!match) return { data: {}, body: raw };
  const block = match[1];
  const body = raw.slice(match[0].length);
  const data: Record<string, string> = {};
  for (const line of block.split(/\r?\n/)) {
    const m = /^([A-Za-z0-9_-]+):\s*(.*)$/.exec(line);
    if (!m) continue;
    let value = m[2].trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    data[m[1]] = value;
  }
  return { data, body };
}

function slugsToUrl(slugs: string[]): string {
  return slugs.length === 0 ? '/docs/' : `/docs/${slugs.join('/')}/`;
}

function urlToOutPath(outDir: string, url: string): string {
  const trimmed = url.replace(/^\/+/, '').replace(/\/+$/, '');
  return resolve(outDir, trimmed, 'llms.md');
}

async function run() {
  const outDir = resolve(process.cwd(), 'out');
  if (!existsSync(outDir)) {
    console.error(
      `[build-page-markdown] ${outDir} does not exist — run \`next build\` first.`,
    );
    process.exit(1);
  }
  if (!existsSync(CONTENT_ROOT)) {
    console.error(
      `[build-page-markdown] ${CONTENT_ROOT} not found — is this docs-site/?`,
    );
    process.exit(1);
  }

  const mdxPaths = await listMdxFiles(CONTENT_ROOT);
  const pages: MdxFile[] = [];
  for (const absPath of mdxPaths) {
    const raw = await readFile(absPath, 'utf-8');
    const { data } = parseFrontmatter(raw);
    if (!data.title) {
      // Fumadocs requires a title; skip authoring drafts that omit it
      // rather than ship a placeholder LLM page.
      continue;
    }
    pages.push({
      absolutePath: absPath,
      slugs: pathToSlugs(absPath),
      title: data.title,
      description: data.description,
    });
  }

  let written = 0;
  for (const page of pages) {
    const url = slugsToUrl(page.slugs);
    const target = urlToOutPath(outDir, url);
    const raw = await readFile(page.absolutePath, 'utf-8');
    const header = page.description
      ? `# ${page.title}\n\nURL: ${siteUrl}${url}\n\n> ${page.description}\n\n`
      : `# ${page.title}\n\nURL: ${siteUrl}${url}\n\n`;
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, header + raw, 'utf-8');
    written++;
  }
  console.log(
    `[build-page-markdown] wrote ${written} llms.md files alongside ${pages.length} pages.`,
  );
}

void run();
