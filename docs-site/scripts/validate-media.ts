// Media and page gate for the docs site.
//
// The 1.0.4 docs rewrite dropped videos, terminal replays, demos and
// screenshots from the pages while the files stayed in public/, and no
// check noticed. This script makes that a CI failure:
//
//   1. Every media reference in an MDX page resolves: <Video src> needs
//      public/videos/<src>.mp4 and public/images/posters/<poster|src>.jpg;
//      every image path under /images/ or /videos/ exists.
//   2. Every file under public/images and public/videos is referenced by a
//      page or by site code, or listed in data/media-allowlist.json with a
//      reason.
//   3. data/media-ledger.json records, per page, the videos, images, demos
//      and terminal replays it shows. A recorded item that disappears from
//      its page fails the check unless the ledger marks it
//      `"retired": "<reason>"`. A page that moved keeps its items if the
//      redirect target now shows them.
//   4. data/page-ledger.json lists every published slug. A slug that is
//      neither a page nor a key in lib/redirects.ts fails the check.
//
// `npm run validate-media` checks. `npm run validate-media -- --update`
// rewrites both ledgers from the current pages and keeps retired entries,
// so a deliberate removal shows up as one reviewed line in the diff.
//
// With DOCS_BASE_REF set (for example origin/main) it also warns when a
// page loses more than 40% or more than 1,000 words against that ref. The
// warning never fails the run.
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, relative, resolve } from 'node:path';
import { legacyRedirects } from '../lib/redirects';

const ROOT = process.cwd();
const CONTENT = resolve(ROOT, 'content/docs');
const PUBLIC = resolve(ROOT, 'public');
const MEDIA_LEDGER = resolve(ROOT, 'data/media-ledger.json');
const PAGE_LEDGER = resolve(ROOT, 'data/page-ledger.json');
const ALLOWLIST = resolve(ROOT, 'data/media-allowlist.json');
const CODE_DIRS = ['app', 'components', 'lib'].map((d) => resolve(ROOT, d));

type PageMedia = {
  videos: string[];
  images: string[];
  demos: string[];
  replays: number;
};
type LedgerEntry = PageMedia & { retired?: Record<string, string> };
type MediaLedger = Record<string, LedgerEntry>;

async function walk(dir: string, keep: (name: string) => boolean): Promise<string[]> {
  const out: string[] = [];
  if (!existsSync(dir)) return out;
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, e.name);
    if (e.isDirectory()) out.push(...(await walk(full, keep)));
    else if (e.isFile() && keep(e.name)) out.push(full);
  }
  return out;
}

function slugOf(abs: string): string {
  const segs = relative(CONTENT, abs)
    .replace(/\\/g, '/')
    .replace(/\.mdx$/, '')
    .split('/')
    .filter((s) => !/^\(.+\)$/.test(s));
  if (segs[segs.length - 1] === 'index') segs.pop();
  return segs.join('/');
}

function uniq(xs: string[]): string[] {
  return [...new Set(xs)].sort();
}

function mediaOf(text: string): PageMedia {
  const videos: string[] = [];
  const posters: string[] = [];
  for (const m of text.matchAll(/<Video\b([^>]*?)\/?>/gs)) {
    const src = /\bsrc="([^"]+)"/.exec(m[1])?.[1];
    if (!src) continue;
    videos.push(src);
    posters.push(/\bposter="([^"]+)"/.exec(m[1])?.[1] ?? src);
  }
  const images: string[] = [];
  for (const m of text.matchAll(/!\[[^\]]*\]\(\s*(\/(?:images|videos)\/[^)\s]+)/g)) images.push(m[1]);
  for (const m of text.matchAll(/\bsrc=["'](\/(?:images|videos)\/[^"']+)["']/g)) images.push(m[1]);
  const demos: string[] = [];
  for (const m of text.matchAll(/<DefenseClawDemo\b([^>]*?)\/?>/gs)) {
    const s = /\bscenario="([^"]+)"/.exec(m[1])?.[1];
    if (s) demos.push(s);
  }
  const replays = [...text.matchAll(/<TerminalAnimation\b/g)].length;
  return {
    videos: uniq(videos),
    images: uniq([...images, ...posters.map((p) => `/images/posters/${p}.jpg`)]),
    demos: uniq(demos),
    replays,
  };
}

function wordCount(text: string): number {
  const body = text.replace(/^---[\s\S]*?---/, '');
  return body.split(/\s+/).filter(Boolean).length;
}

async function main(): Promise<void> {
  const update = process.argv.includes('--update');
  const errors: string[] = [];
  const warnings: string[] = [];

  const pages = new Map<string, { file: string; text: string; media: PageMedia }>();
  for (const f of await walk(CONTENT, (n) => n.endsWith('.mdx'))) {
    const text = await readFile(f, 'utf8');
    pages.set(slugOf(f), { file: relative(ROOT, f), text, media: mediaOf(text) });
  }

  // 1. Every reference resolves.
  const referenced = new Set<string>();
  for (const [slug, p] of pages) {
    for (const v of p.media.videos) {
      const mp4 = `/videos/${v}.mp4`;
      referenced.add(mp4);
      if (!existsSync(join(PUBLIC, mp4))) errors.push(`${p.file}: <Video src="${v}"> has no public${mp4}`);
    }
    for (const img of p.media.images) {
      referenced.add(img);
      if (!existsSync(join(PUBLIC, img))) errors.push(`${p.file}: ${img} does not exist under public/ (page ${slug || 'index'})`);
    }
  }

  // Site code (landing page, components) may reference media too.
  for (const f of (await Promise.all(CODE_DIRS.map((d) => walk(d, (n) => /\.(tsx?|css|mdx?)$/.test(n))))).flat()) {
    const text = await readFile(f, 'utf8');
    for (const m of text.matchAll(/["'`(](\/(?:images|videos)\/[^"'`)\s]+)/g)) referenced.add(m[1]);
  }

  // 2. Every media file is used or allowlisted.
  const allow: Record<string, string> = existsSync(ALLOWLIST) ? JSON.parse(await readFile(ALLOWLIST, 'utf8')) : {};
  const files = [
    ...(await walk(join(PUBLIC, 'images'), () => true)),
    ...(await walk(join(PUBLIC, 'videos'), () => true)),
  ].map((f) => '/' + relative(PUBLIC, f).replace(/\\/g, '/'));
  for (const f of files) {
    if (referenced.has(f)) continue;
    if (allow[f]) continue;
    errors.push(`public${f} is not referenced by any page or site code; use it, delete it, or list it in data/media-allowlist.json with a reason`);
  }
  for (const f of Object.keys(allow)) {
    if (!allow[f] || !allow[f].trim()) errors.push(`data/media-allowlist.json: ${f} needs a reason`);
  }

  // 3. Media ledger: nothing recorded disappears silently.
  const ledger: MediaLedger = existsSync(MEDIA_LEDGER) ? JSON.parse(await readFile(MEDIA_LEDGER, 'utf8')) : {};
  const shownBy = (slug: string): PageMedia | undefined => {
    if (pages.has(slug)) return pages.get(slug)!.media;
    const target = legacyRedirects[slug];
    if (target) {
      const t = target.replace(/^\/docs\/?/, '').replace(/#.*$/, '').replace(/\/$/, '');
      return pages.get(t)?.media;
    }
    return undefined;
  };
  if (!update) {
    for (const [slug, entry] of Object.entries(ledger)) {
      const now = shownBy(slug);
      const retired = entry.retired ?? {};
      const check = (kind: 'videos' | 'images' | 'demos', items: string[]) => {
        for (const it of items) {
          if (retired[it]) continue;
          if (!now || !now[kind].includes(it)) {
            errors.push(`${slug || 'index'}: ${kind.slice(0, -1)} ${it} was shown here and is gone; put it back or mark it retired with a reason in data/media-ledger.json`);
          }
        }
      };
      check('videos', entry.videos);
      check('images', entry.images);
      check('demos', entry.demos);
      if ((now?.replays ?? 0) < entry.replays && !retired['replays']) {
        errors.push(`${slug || 'index'}: had ${entry.replays} terminal replays, now ${now?.replays ?? 0}; put them back or set retired.replays with a reason`);
      }
    }
  }

  // 4. Page ledger: every published slug stays reachable.
  const pageLedger: string[] = existsSync(PAGE_LEDGER) ? JSON.parse(await readFile(PAGE_LEDGER, 'utf8')) : [];
  if (!update) {
    for (const slug of pageLedger) {
      if (!pages.has(slug) && !(slug in legacyRedirects)) {
        errors.push(`page ${slug || 'index'} was published and now has neither a page nor a redirect in lib/redirects.ts`);
      }
    }
  }

  // Shrink warning against a base ref.
  const base = process.env.DOCS_BASE_REF;
  if (base) {
    for (const [slug, p] of pages) {
      let old = '';
      try {
        old = execFileSync('git', ['show', `${base}:docs-site/${p.file}`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
      } catch {
        continue;
      }
      const a = wordCount(old);
      const b = wordCount(p.text);
      if (a > 0 && (a - b > 1000 || (a - b) / a > 0.4)) {
        warnings.push(`${slug || 'index'}: ${a} -> ${b} words against ${base}; check nothing true was lost`);
      }
    }
  }

  if (update) {
    const next: MediaLedger = {};
    for (const [slug, p] of [...pages].sort(([a], [b]) => a.localeCompare(b))) {
      const m = p.media;
      const retired = ledger[slug]?.retired;
      if (m.videos.length || m.images.length || m.demos.length || m.replays || retired) {
        next[slug] = { ...m, ...(retired ? { retired } : {}) };
      }
    }
    for (const [slug, entry] of Object.entries(ledger)) {
      if (!next[slug] && entry.retired) next[slug] = entry;
    }
    const slugs = uniq([...pageLedger, ...pages.keys()]);
    await writeFile(MEDIA_LEDGER, JSON.stringify(next, null, 2) + '\n');
    await writeFile(PAGE_LEDGER, JSON.stringify(slugs, null, 2) + '\n');
    console.log(`updated data/media-ledger.json (${Object.keys(next).length} pages) and data/page-ledger.json (${slugs.length} slugs)`);
  }

  for (const w of warnings) console.warn(`warning: ${w}`);
  if (errors.length) {
    for (const e of errors) console.error(`error: ${e}`);
    console.error(`\n${errors.length} media/page problem(s).`);
    process.exit(1);
  }
  console.log(`media and pages ok: ${pages.size} pages, ${files.length} media files`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
