// Postbuild SEO contract for the static GitHub Pages export.
//
// This validates the generated artifact instead of only checking source code,
// so it catches framework URL normalization, missing dynamic OG routes, and
// sitemap/page drift before deployment.
import { access, readFile, readdir } from 'node:fs/promises';
import { extname, join, resolve } from 'node:path';

const OUT_DIR = resolve(process.cwd(), 'out');
const CONTENT_DIR = resolve(process.cwd(), 'content/docs');
const SITE_ROOT = (
  process.env.SITE_URL ??
  process.env.NEXT_PUBLIC_SITE_URL ??
  'https://cisco-ai-defense.github.io/defenseclaw'
).replace(/\/+$/, '');
const CANONICAL_ROOT = `${SITE_ROOT}/`;
const site = new URL(CANONICAL_ROOT);
const errors: string[] = [];

async function listMdxFiles(dir: string): Promise<string[]> {
  const files: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await listMdxFiles(path)));
    } else if (entry.isFile() && entry.name.endsWith('.mdx')) {
      files.push(path);
    }
  }
  return files;
}

function decodeXml(value: string): string {
  return value
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'");
}

function getAttribute(tag: string, name: string): string | undefined {
  const match = new RegExp(`\\b${name}=["']([^"']+)["']`, 'i').exec(tag);
  return match?.[1];
}

function findLink(html: string, rel: string): string | undefined {
  for (const tag of html.match(/<link\b[^>]*>/gi) ?? []) {
    if (getAttribute(tag, 'rel') === rel) return getAttribute(tag, 'href');
  }
  return undefined;
}

function findMeta(
  html: string,
  attribute: 'name' | 'property',
  value: string,
): string | undefined {
  for (const tag of html.match(/<meta\b[^>]*>/gi) ?? []) {
    if (getAttribute(tag, attribute) === value) return getAttribute(tag, 'content');
  }
  return undefined;
}

function siteRelativePath(url: URL): string | undefined {
  if (url.origin !== site.origin || !url.pathname.startsWith(site.pathname)) {
    return undefined;
  }
  return decodeURIComponent(url.pathname.slice(site.pathname.length));
}

function collectStrings(value: unknown, out: string[]): void {
  if (typeof value === 'string') {
    out.push(value);
  } else if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, out);
  } else if (value && typeof value === 'object') {
    for (const item of Object.values(value)) collectStrings(item, out);
  }
}

function validateStructuredData(html: string, pageUrl: string): void {
  for (const tag of html.match(/<script\b[^>]*>[\s\S]*?<\/script>/gi) ?? []) {
    const openTag = tag.slice(0, tag.indexOf('>') + 1);
    if (getAttribute(openTag, 'type') !== 'application/ld+json') continue;

    const raw = tag.slice(tag.indexOf('>') + 1, tag.lastIndexOf('</script>'));
    let data: unknown;
    try {
      data = JSON.parse(raw);
    } catch (error) {
      errors.push(`${pageUrl}: invalid JSON-LD (${String(error)})`);
      continue;
    }

    const strings: string[] = [];
    collectStrings(data, strings);
    for (const value of strings) {
      if (!value.startsWith('http://') && !value.startsWith('https://')) continue;
      let url: URL;
      try {
        url = new URL(value);
      } catch {
        continue;
      }
      const relative = siteRelativePath(url);
      if (
        relative !== undefined &&
        !url.search &&
        !url.hash &&
        extname(url.pathname) === '' &&
        !url.pathname.endsWith('/')
      ) {
        errors.push(`${pageUrl}: JSON-LD contains non-canonical internal URL ${value}`);
      }
    }
  }
}

async function validatePage(loc: string): Promise<void> {
  let url: URL;
  try {
    url = new URL(loc);
  } catch {
    errors.push(`Sitemap contains invalid URL: ${loc}`);
    return;
  }

  if (!loc.endsWith('/')) {
    errors.push(`Sitemap URL is missing its canonical trailing slash: ${loc}`);
  }
  const relative = siteRelativePath(url);
  if (relative === undefined) {
    errors.push(`Sitemap URL is outside ${CANONICAL_ROOT}: ${loc}`);
    return;
  }

  const htmlPath = resolve(OUT_DIR, relative.replace(/\/+$/, ''), 'index.html');
  let html: string;
  try {
    html = await readFile(htmlPath, 'utf8');
  } catch {
    errors.push(`${loc}: missing exported page ${htmlPath}`);
    return;
  }

  if (!/<title>[^<]+<\/title>/i.test(html)) {
    errors.push(`${loc}: missing non-empty title`);
  }
  if (!findMeta(html, 'name', 'description')) {
    errors.push(`${loc}: missing meta description`);
  }

  const canonical = findLink(html, 'canonical');
  if (canonical !== loc) {
    errors.push(`${loc}: canonical is ${canonical ?? 'missing'}`);
  }

  const ogImage = findMeta(html, 'property', 'og:image');
  if (!ogImage) {
    errors.push(`${loc}: missing og:image`);
  } else {
    try {
      const imageUrl = new URL(ogImage);
      const imageRelative = siteRelativePath(imageUrl);
      if (imageRelative === undefined) {
        errors.push(`${loc}: og:image is outside ${CANONICAL_ROOT}: ${ogImage}`);
      } else {
        await access(resolve(OUT_DIR, imageRelative));
      }
    } catch {
      errors.push(`${loc}: og:image does not exist in the export: ${ogImage}`);
    }
  }

  validateStructuredData(html, loc);
}

async function run() {
  const sitemap = await readFile(join(OUT_DIR, 'sitemap.xml'), 'utf8');
  const locations = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) =>
    decodeXml(match[1]),
  );
  const mdxFiles = await listMdxFiles(CONTENT_DIR);
  const expectedPages = mdxFiles.length + 1;

  if (locations.length !== expectedPages) {
    errors.push(
      `sitemap has ${locations.length} URLs; expected ${expectedPages} (${mdxFiles.length} docs + home)`,
    );
  }
  if (new Set(locations).size !== locations.length) {
    errors.push('sitemap contains duplicate URLs');
  }

  await Promise.all(locations.map(validatePage));

  if (errors.length > 0) {
    for (const error of errors) console.error(`[validate-seo-output] ${error}`);
    process.exit(1);
  }

  console.log(
    `[validate-seo-output] validated ${locations.length} canonical pages and their social images.`,
  );
}

void run();
