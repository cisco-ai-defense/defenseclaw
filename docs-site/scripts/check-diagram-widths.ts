// Postbuild gate: walks the static export and refuses any diagram
// (Flow or Sequence) whose natural width crosses our hard limit
// without an explicit opt-in. Runs after `next build` so we lint
// the actual SSR HTML, not a guess based on source-time props.
//
// Thresholds match the CSS layout in app/global.css:
//   ARTICLE_WIDTH_TARGET = 1168px  → ideal cap; warn above this
//   ARTICLE_WIDTH_HARD_LIMIT = 1500px → fail above this unless opted in
//
// Opt-out: `<Flow oversize />` / `<Sequence oversize />`. Both add
// `data-oversize="true"` to the figure element via lightbox.tsx,
// which we look for here. The lightbox affordance is then the
// readable detail path for those diagrams.
import { existsSync } from 'node:fs';
import { readFile, readdir } from 'node:fs/promises';
import { join, relative, resolve } from 'node:path';

const OUT_ROOT = resolve(process.cwd(), 'out');

// Keep these in sync with components/diagram/shared.ts. We don't
// import from there to avoid pulling tsx through the React tree at
// postbuild time (the lightbox is a client component).
const ARTICLE_WIDTH_TARGET = 1168;
const ARTICLE_WIDTH_HARD_LIMIT = 1500;

interface DiagramHit {
  file: string;
  width: number;
  height: number;
  ariaLabel: string;
  oversize: boolean;
}

async function listHtmlFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...(await listHtmlFiles(full)));
    } else if (entry.isFile() && entry.name.endsWith('.html')) {
      out.push(full);
    }
  }
  return out;
}

// We identify diagrams by the `data-natural-width` attribute the
// lightbox emits on its `<figure>` wrapper. That attribute is unique
// to Flow/Sequence (no other component emits it) and survives
// minification because Next.js doesn't rewrite data-* on HTML.
//
// Pulling the width off the figure means we don't have to parse the
// SVG viewBox separately and we get the exact value the engine
// computed, not whatever rounding survived attribute serialization.
// Width/height are rounded to integers in the engine, but accept
// trailing fractional digits defensively in case a future code path
// emits a non-integer dimension. Without that the gate silently
// skips the diagram and reports zero hits.
const FIGURE_RE =
  /<figure\b([^>]*?\bdata-natural-width="(\d+(?:\.\d+)?)"[^>]*?\bdata-natural-height="(\d+(?:\.\d+)?)"[^>]*?)>([\s\S]*?)<\/figure>/g;

function parseOversize(figureAttrs: string): boolean {
  return /data-oversize="true"/.test(figureAttrs);
}

// Best-effort label for the error message: pull the SVG's
// `aria-label`. When the author passed a caption it's the caption
// text; otherwise the engine fills in "Flow diagram"/"Sequence
// diagram".
function parseAriaLabel(body: string): string {
  const m = /<svg\b[^>]*\baria-label="([^"]+)"/.exec(body);
  return m?.[1] ?? '(no aria-label)';
}

async function scan(): Promise<DiagramHit[]> {
  const hits: DiagramHit[] = [];
  const files = await listHtmlFiles(OUT_ROOT);
  for (const file of files) {
    const html = await readFile(file, 'utf-8');
    FIGURE_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = FIGURE_RE.exec(html)) !== null) {
      const figureAttrs = m[1] ?? '';
      const width = Math.round(Number(m[2]));
      const height = Math.round(Number(m[3]));
      const body = m[4] ?? '';
      hits.push({
        file: relative(process.cwd(), file),
        width,
        height,
        ariaLabel: parseAriaLabel(body),
        oversize: parseOversize(figureAttrs),
      });
    }
  }
  return hits;
}

async function run() {
  if (!existsSync(OUT_ROOT)) {
    console.warn(
      `[check-diagram-widths] no out/ directory at ${OUT_ROOT}; skipping. Did you run \`next build\`?`,
    );
    return;
  }

  const hits = await scan();
  if (hits.length === 0) {
    console.log('[check-diagram-widths] no diagrams found in out/.');
    return;
  }

  const warnings: DiagramHit[] = [];
  const failures: DiagramHit[] = [];
  for (const h of hits) {
    if (h.width > ARTICLE_WIDTH_HARD_LIMIT) {
      if (h.oversize) {
        // Author opted in. Note it in the log but don't fail.
        warnings.push(h);
      } else {
        failures.push(h);
      }
    } else if (h.width > ARTICLE_WIDTH_TARGET) {
      warnings.push(h);
    }
  }

  console.log(
    `[check-diagram-widths] scanned ${hits.length} diagram(s) across out/.`,
  );

  if (warnings.length > 0) {
    console.warn(
      `[check-diagram-widths] ${warnings.length} diagram(s) above ${ARTICLE_WIDTH_TARGET}px ideal cap (will scale-to-fit at desktop, lightbox is the readable path):`,
    );
    for (const w of warnings) {
      const tag = w.oversize ? ' [oversize]' : '';
      console.warn(
        `  - ${w.file}: ${w.width}x${w.height}px — "${w.ariaLabel}"${tag}`,
      );
    }
  }

  if (failures.length > 0) {
    console.error(
      `\n[check-diagram-widths] FAIL: ${failures.length} diagram(s) above ${ARTICLE_WIDTH_HARD_LIMIT}px hard limit:`,
    );
    for (const f of failures) {
      console.error(
        `  - ${f.file}: ${f.width}x${f.height}px — "${f.ariaLabel}"`,
      );
    }
    console.error(
      `\nFix one of:\n` +
        `  1. Flip <Flow direction="LR"> to direction="TB" — usually halves natural width.\n` +
        `  2. Add <Flow compact> — tightens spacing ~15-20%.\n` +
        `  3. Shorten participant labels (Sequence) — long labels widen every spanning column.\n` +
        `  4. Split a long pipeline into two stacked diagrams.\n` +
        `  5. As last resort, <Flow oversize /> or <Sequence oversize /> — the lightbox affordance becomes the readable path.\n` +
        `See docs-site/components/diagram/AUTHORING.md.`,
    );
    process.exitCode = 1;
  }
}

void run();
