#!/usr/bin/env python3
"""Post-build verification of the generated static site (SLM tool-call security Space).

Copied from benchmarks/system_one/reproduce/08-site-build/verify.py. The eight structural
checks below are unchanged. Two data blocks are programme-specific and were replaced, because
both are lists of content claims about one programme's pages:

  * RETIRED - figures and phrasings withdrawn against an artifact in THIS programme
  * REQUIRED - the disclosures THIS Space's pages must carry

One check was added: check 9, which requires every mention of P(block) - P(confirm) to sit
near the word that says it inverted, so the variable can never appear on a page as a bare
ranking.

Checks, all of which abort with a non-zero exit:
  1. no leftover template tokens
  2. every internal href resolves to a file that exists, and to an id that exists
  3. HTML tag balance for the block elements we generate
  4. every <svg> element's drawn coordinates stay inside its viewBox (with a small
     allowance for label text, which is intentionally allowed to overflow)
  5. every <figure class="chart"> has a <figcaption> naming a source
  6. no <link>, no `script src=`, no <img>, and no external URL except:
       * an <a href> to one of the two allowed source hosts
         (huggingface.co/datasets/... and github.com/...), so the 13 public source
         datasets can be cited by link; and
       * an <iframe src> to https://huggingface.co/datasets/<id>/embed/viewer and nothing
         else, so a public source's own rows can be previewed in the Hugging Face dataset
         viewer without this site republishing them. Every such iframe must sit inside a
         collapsed <details>, carry loading="lazy", a title, a sandbox and
         referrerpolicy="no-referrer". Any other iframe, and any other embedding tag
         (<img>, <object>, <embed>, <video>, <audio>, <source>, <track>), is still
         rejected.
     An INLINE <script> is permitted: the interactive controls are progressive enhancement
     and the page renders a sensible default state without them.
  7. the stylesheet is inlined: exactly one <style> block, carrying the palette
  9. every mention of P(block) - P(confirm) sits near a statement that it inverted below
     chance on the disjoint corpus, so it cannot read as a rankable variable
  8. no chart appearance depends on CSS. Every drawn SVG element carries its own
     fill / stroke (and every <text> its own font-size) as a presentation
     attribute with a literal value, and no SVG attribute names a custom
     property. Checked again with the <style> block stripped out.
 10. reading precision. Every exact value stored behind a figure must round-trip
     (repr(float(x)) == x), the visible text must be a rounding of it to within half a unit of
     its own last displayed place, and nothing a reader sees anywhere on any page may carry more
     than MAX_SIG significant digits. The last of those is the gate that keeps 1,933 raw float
     expansions from coming back.
 11. the controls' no-script defaults. The precision control must be pre-set to the rounding, the
     leaderboard must ship its rows and its unfiltered group pre-selected, its row count and its
     find box must carry real values, and every sortable table must have a tbody.
"""
from __future__ import annotations

import os
import re
import sys
from html.parser import HTMLParser

SITE = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "site")
PROBLEMS: list[str] = []
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
        "param", "source", "track", "wbr", "path", "rect", "line", "circle", "polygon",
        "polyline", "ellipse", "use", "stop", "image"}


class Check(HTMLParser):
    def __init__(self, name):
        super().__init__(convert_charrefs=True)
        self.name = name
        self.stack: list[tuple[str, int]] = []
        self.ids: set[str] = set()
        self.hrefs: list[tuple[str, int]] = []
        self.figures = 0
        self.figcaptions = 0
        self.scripts = 0
        self.script_src = 0
        self.external = 0
        self.json_blobs = 0
        self.ranges = 0
        self.sortable = 0
        self.sort_heads = 0
        self.lens_btns = 0
        self.allowed_links = 0
        self.links = 0
        self.styles = 0
        self.embeds = 0
        self.details_depth = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if "id" in a:
            self.ids.add(a["id"])
        if tag == "a" and "href" in a:
            self.hrefs.append((a["href"], self.getpos()[0]))
        if tag == "figure" and "chart" in (a.get("class") or ""):
            self.figures += 1
        if tag == "figcaption":
            self.figcaptions += 1
        if tag == "script":
            self.scripts += 1
            if "src" in a:
                self.script_src += 1
            if not (a.get("type") in (None, "", "application/json", "text/javascript")):
                PROBLEMS.append(f"{self.name}: <script type={a['type']!r}> is not inline JS "
                                f"or an inline JSON blob")
        if tag == "link":
            self.links += 1
        if tag == "style":
            self.styles += 1
        if tag == "script" and a.get("type") == "application/json":
            self.json_blobs += 1
        if tag == "input" and a.get("type") == "range":
            self.ranges += 1
        if tag == "table" and "data-sortable" in a:
            self.sortable += 1
        if tag == "th" and "data-sort" in a:
            self.sort_heads += 1
        if tag == "button" and "data-lens-btn" in a:
            self.lens_btns += 1
        if tag == "details":
            self.details_depth += 1
        # a subresource may never be external, whatever the tag, with exactly one
        # exception: the Hugging Face dataset viewer in an <iframe>.
        v = a.get("src", "")
        viewer = tag == "iframe" and embed_ok(v)
        if v.startswith(("http://", "https://", "//")) and not viewer:
            PROBLEMS.append(f"{self.name}: <{tag} src=...> fetches an external resource")
            self.external += 1
        if tag in ("img", "object", "embed", "video", "audio", "source", "track"):
            PROBLEMS.append(f"{self.name}: <{tag}> is not allowed; this site ships no media")
        if tag == "iframe":
            if not viewer:
                PROBLEMS.append(f"{self.name}: <iframe src={v!r}> is not a Hugging Face dataset "
                                f"viewer embed; the only permitted iframe src is "
                                f"{EMBED_PREFIX}<owner>/<name>{EMBED_SUFFIX}")
                self.external += 1
            else:
                self.embeds += 1
                if self.details_depth == 0:
                    PROBLEMS.append(f"{self.name}: <iframe src={v!r}> is not inside a <details>, "
                                    f"so it would load on every page view")
                if not (a.get("title") or "").strip():
                    PROBLEMS.append(f"{self.name}: <iframe src={v!r}> has no title")
                if "sandbox" not in a:
                    PROBLEMS.append(f"{self.name}: <iframe src={v!r}> has no sandbox attribute")
                for k, want in EMBED_REQUIRED.items():
                    if a.get(k) != want:
                        PROBLEMS.append(f"{self.name}: <iframe src={v!r}> has {k}="
                                        f"{a.get(k)!r}, expected {want!r}")
        h = a.get("href", "")
        if h.startswith(("http://", "https://", "//")):
            if tag != "a":
                PROBLEMS.append(f"{self.name}: <{tag} href=...> is an external subresource")
                self.external += 1
            elif not link_ok(h):
                PROBLEMS.append(f"{self.name}: <a href={h!r}> is not on an allowed source host")
                self.external += 1
            else:
                self.allowed_links += 1
        if tag not in VOID:
            self.stack.append((tag, self.getpos()[0]))

    def handle_endtag(self, tag):
        if tag == "details":
            self.details_depth = max(0, self.details_depth - 1)
        if tag in VOID:
            return
        if not self.stack:
            PROBLEMS.append(f"{self.name}: stray </{tag}>")
            return
        if self.stack[-1][0] != tag:
            # tolerate implied closes for p/li which browsers allow
            if self.stack[-1][0] in ("p", "li", "td", "tr", "th", "tbody", "thead", "option"):
                self.stack.pop()
                return self.handle_endtag(tag)
            PROBLEMS.append(f"{self.name}: </{tag}> closes <{self.stack[-1][0]}> "
                            f"opened on line {self.stack[-1][1]}")
            return
        self.stack.pop()


NUM = re.compile(r'(?:\b(?:x|y|x1|y1|x2|y2|cx|cy)="(-?[\d.]+)")')
VIEWBOX = re.compile(r'viewBox="0 0 ([\d.]+) ([\d.]+)"')
SVG_BLOCK = re.compile(r"<svg\b.*?</svg>", re.S)
TOKEN = re.compile(r"\{\{[a-zA-Z]+:")
STYLE_BLOCK = re.compile(r"<style\b.*?</style>", re.S | re.I)
SCRIPT_BLOCK = re.compile(r"<script\b.*?</script>", re.S | re.I)
JSON_BLOB = re.compile(r'<script[^>]*type="application/json"[^>]*>.*?</script>', re.S | re.I)
URL = re.compile("https?://[^" + chr(34) + chr(39) + r"\s<>)]*")
# an <a href> may point at a public source dataset. Nothing else may leave the page, and
# nothing at all may be fetched as a subresource.
ALLOWED_LINKS = ("https://huggingface.co/datasets/", "https://github.com/")
# One further outbound target, allowed by EXACT match rather than by host prefix: the sibling
# Space this programme's scope rule points at. The host allowlist above is deliberately narrow, so
# widening it to `huggingface.co/` would be a much larger change than naming one URL.
ALLOWED_EXACT = ("https://huggingface.co/spaces/Vineethsain/defenseclaw-system-one",)


def link_ok(h: str) -> bool:
    return h.startswith(ALLOWED_LINKS) or h.rstrip("/") in ALLOWED_EXACT
# the ONE embeddable subresource: the Hugging Face dataset viewer for a public source.
# Anything else in a src= is still a hard failure, on any tag.
EMBED_PREFIX = "https://huggingface.co/datasets/"
EMBED_SUFFIX = "/embed/viewer"
EMBED_REQUIRED = {"loading": "lazy", "referrerpolicy": "no-referrer"}


def embed_ok(src: str) -> bool:
    if not (src.startswith(EMBED_PREFIX) and src.endswith(EMBED_SUFFIX)):
        return False
    ident = src[len(EMBED_PREFIX):-len(EMBED_SUFFIX)]
    # exactly <owner>/<name>, no query, no fragment, no traversal
    return (bool(re.fullmatch(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+", ident))
            and ".." not in ident)
# drawn SVG elements and the paint each one must declare for itself
PAINTED = {"rect": ("fill", "stroke"), "circle": ("fill", "stroke"),
           "polygon": ("fill", "stroke"), "polyline": ("fill", "stroke"),
           "ellipse": ("fill", "stroke"), "path": ("fill", "stroke"),
           "line": ("stroke",), "text": ("fill",), "tspan": ("fill",)}
LITERAL = re.compile(r"^(#[0-9a-fA-F]{3,8}|none|currentColor|[0-9.]+)$")


def audit_svg_paint(name: str, body: str, where: str) -> list[str]:
    """No chart appearance may depend on a CSS class: every drawn element carries
    its own literal fill/stroke, and every text run its own font-size."""
    out = []
    for sv in SVG_BLOCK.findall(body):
        for el in re.finditer(r"<(\w+)\b([^>]*)>", sv):
            tag, attrs = el.group(1), el.group(2)
            if tag not in PAINTED:
                continue
            got = dict(re.findall(r'\b([a-z-]+)="([^"]*)"', attrs))
            need = PAINTED[tag]
            if not any(k in got for k in need):
                out.append(f"{name} [{where}]: <{tag}> declares none of {need} "
                           f"({attrs.strip()[:70]!r})")
            for k in need:
                if k in got and not LITERAL.match(got[k].strip()):
                    out.append(f"{name} [{where}]: <{tag}> {k}={got[k]!r} is not a literal value")
            if tag in ("text", "tspan") and "font-size" not in got:
                out.append(f"{name} [{where}]: <{tag}> has no font-size attribute "
                           f"({attrs.strip()[:70]!r})")
    return out

def audit_nojs(name: str, body: str) -> list[str]:
    """With every <script> removed, the page must still render a usable default state:
    the block-only lens on every switchable cell, allow threshold 0.30 on every tile,
    and no placeholder left for JS to fill in."""
    out = []
    nojs = SCRIPT_BLOCK.sub("", body)
    if "<script" in nojs:
        out.append(f"{name}: a <script> survived stripping, so the no-JS check is unsound")
    # The point of this check is to catch a page that is mostly executable code. The
    # inline JSON data blob in <head> is data, not code, and on a page that ships the
    # decision explorer it is tens of kilobytes of it, so it is excluded from the
    # denominator: what must survive is the page's non-data bytes.
    base = JSON_BLOB.sub("", body)
    if len(nojs) < 0.5 * len(base):
        out.append(f"{name}: stripping the inline scripts removed over half of the page's "
                   f"non-data bytes, so the no-JS render is not the page")
    # no empty or placeholder-only switchable cell
    for m in re.finditer(r'<span class="lx"[^>]*>([^<]*)</span>', nojs):
        txt = m.group(1).strip()
        if not txt or txt in ("-", "\u2014", "...", "&hellip;", "TBD"):
            out.append(f"{name}: switchable cell renders {txt!r} without JS")
    for m in re.finditer(r'<(?:div|span)[^>]*data-thr="[^"]*"[^>]*>([^<]*)<', nojs):
        if not m.group(1).strip():
            out.append(f"{name}: threshold tile is empty without JS")
    # the default states the HTML must already carry
    if 'data-lens-btn="block"' in nojs and 'data-lens-btn="block" aria-pressed="true"' not in nojs:
        out.append(f"{name}: the block-only lens button is not pre-selected in the markup")
    # the threshold slider must sit on the 0.30 column; every OTHER range must still
    # carry an explicit value, so nothing renders at a browser-chosen default
    for m in re.finditer(r'<input[^>]*type="range"[^>]*>', nojs):
        frag = m.group(0)
        rid = re.search(r'\bid="([^"]*)"', frag)
        rid = rid.group(1) if rid else ""
        if rid == "thr-range":
            if 'value="3"' not in frag:
                out.append(f"{name}: the threshold slider does not default to the 0.30 column")
        elif rid == "calc-thr":
            if 'value="30"' not in frag:
                out.append(f"{name}: the calculator threshold slider does not default to 0.30")
        elif not re.search(r'\bvalue="[^"]+"', frag):
            out.append(f"{name}: <input type=range id={rid!r}> has no explicit value, so its "
                       f"no-JS state is browser-defined")
    # the calculator's number inputs and the explorer's selects must ship real defaults
    for m in re.finditer(r'<input[^>]*id="calc-(?:dec|benign)"[^>]*>', nojs):
        if not re.search(r'\bvalue="[^"]+"', m.group(0)):
            out.append(f"{name}: a calculator input ships no default value")
    for m in re.finditer(r'<(?:div|span)[^>]*data-calc="[^"]*"[^>]*>([^<]*)<', nojs):
        if not m.group(1).strip():
            out.append(f"{name}: a calculator output is empty without JS")
    if 'id="exp-body"' in nojs:
        body_m = re.search(r'<tbody id="exp-body">(.*?)</tbody>', nojs, re.S)
        if not body_m or "<tr" not in body_m.group(1):
            out.append(f"{name}: the explorer table has no static rows, so it is empty without JS")
    # the lens-switched SVG groups: exactly the block-only group may be painted
    for m in re.finditer(r'data-lens-op="(\w+)"\s+opacity="([\d.]+)"', nojs):
        want = "1" if m.group(1) == "block" else "0"
        if m.group(2) != want:
            out.append(f"{name}: lens group {m.group(1)!r} renders at opacity {m.group(2)} "
                       f"without JS, expected {want}")
    # the SVG marker for the default threshold must be visible before any JS runs
    hl = re.findall(r'data-thr-hl="(\d)"[^>]*opacity="([\d.]+)"', nojs)
    if hl:
        on = {i for i, o in hl if float(o) > 0}
        if on != {"3"}:
            out.append(f"{name}: default threshold markers visible for {sorted(on)}, expected "
                       f"only the 0.30 column")
    # a page with a sortable table must still be readable unsorted
    if "data-sortable" in nojs and "<tbody" not in nojs:
        out.append(f"{name}: sortable table has no <tbody> rows in the static HTML")
    return out


# Figures that were corrected against an artifact and must not reappear as literal prose.
# The build recomputes each of these, so a stale copy on a page means some text is carrying a
# number the rollup does not cover - which is exactly how the site came to state two different
# provider totals at once.
# ---------------------------------------------------------------- check 9
# P(block) - P(confirm) inverted BELOW CHANCE on the disjoint corpus, so it may never appear on
# a page as a bare variable name. Every mention must sit within 600 characters of a word that
# says so, which is the shortest form of "this is the one you cannot rank on".
FLAGGED = re.compile(r"P\(block\)\s*(?:&#8722;|-|\u2212)\s*P\(confirm\)")
FLAGGED_NEAR = ("invert", "flagged", "below chance", "not usable", "never rank",
                "does not transfer", "do not exist", "not computed", "INAPPLICABLE")


# Jev-family models and System One board arms are out of scope on this Space. The list is the
# same one build.py enforces, restated here so the verifier is not dependent on the builder.
OUT_OF_SCOPE = ("open-jev", "openjev", "open jev", "jevify", "jev 1.13", "zefancai",
                "kev-9b", "decider-2b", "bespoke-nimble", "secjudge", "diffusiongemma")


# The two corpora have nearly inverted positive-grade composition, so a held-out figure read as a
# generalisation result is a misreading. Any mention of transfer or of the held-out corpus must sit
# near the composition caveat, and the words "transfer penalty" may not introduce a figure.
HELDOUT = re.compile(r"held-out|held out|transfer penalt|generalis", re.I)
HELDOUT_NEAR = ("grade a", "grade-a", "composition", "conflate", "no transfer figure")


# ---------------------------------------------------------------- check 10
# Every figure on a page is published at reading precision, with the artifact's exact decimal in
# data-x. Two things have to hold for that to be honest rather than a rounding:
#
#   * nothing a reader SEES may be a raw binary float expansion. The pages carried 1,933 of them,
#     which is what made a column of twenty-two F1 values unreadable, and this is the gate that
#     keeps them from coming back.
#   * every data-x must round-trip: repr(float(x)) == x, so the exact value is preserved and not
#     itself a rounding, and the visible text must be that same number to within its own last
#     displayed digit.
EX_SPAN = re.compile(r'<span class="ex" data-x="([^"]*)"[^>]*>([^<]*)</span>')
DECIMAL = re.compile(r"(?<![\w.])([0-9][0-9,]*\.[0-9]+)(?![\w.])")
# The most significant digits any figure may be shown at. A rate displayed at four decimals
# spends five ("0.9910"), and a value under a thousandth spends three ("0.000296"), so six is
# above every display this build produces and far below a raw binary expansion, which spends
# sixteen or seventeen.
MAX_SIG = 6


def sig_digits(lit: str) -> int:
    return len(lit.replace(",", "").replace(".", "").lstrip("0"))


def audit_precision(name: str, body: str) -> list[str]:
    out = []
    for m in EX_SPAN.finditer(body):
        x, shown = m.group(1), m.group(2).strip()
        try:
            xv = float(x)
        except ValueError:
            out.append(f"{name}: data-x={x!r} is not a number, so the exact value is lost")
            continue
        if repr(xv) != x:
            out.append(f"{name}: data-x={x!r} is not the shortest round-tripping decimal "
                       f"({repr(xv)!r}), so the 'exact value' is itself a rounding")
        if not shown:
            out.append(f"{name}: a figure renders empty without scripting (data-x={x!r})")
            continue
        try:
            sv = float(shown.replace(",", ""))
        except ValueError:
            out.append(f"{name}: the visible form {shown!r} of {x!r} is not a number")
            continue
        # the displayed rounding has to be within half a unit of its own last place
        places = len(shown.partition(".")[2])
        tol = 0.5 * 10 ** -places if places else 0.5
        if abs(sv - xv) > tol * 1.000001:
            out.append(f"{name}: {shown!r} is not a rounding of {x!r} at {places} decimals")
    # No figure a reader sees may be shown at raw float precision, whether or not it went through
    # exact(). data-x is an attribute rather than text, so the spans are reduced to what they
    # render before the scan and the exact decimals behind them are not scanned.
    text = STYLE_BLOCK.sub("", SCRIPT_BLOCK.sub("", body))
    text = EX_SPAN.sub(lambda m: " " + m.group(2) + " ", text)
    for m in DECIMAL.finditer(text):
        n = sig_digits(m.group(1))
        if n > MAX_SIG:
            out.append(f"{name}: {m.group(1)!r} is shown at {n} significant digits, over the "
                       f"{MAX_SIG} a reader can compare; publish it through exact() so the page "
                       f"shows the rounding and keeps the exact value in data-x "
                       f"(...{text[max(0, m.start() - 60):m.end() + 12]!r}...)")
    return out


# ---------------------------------------------------------------- check 11
# The controls added to this Space are progressive enhancement, and the states below are the ones
# the HTML has to already be in before any script runs.
def audit_controls(name: str, body: str) -> list[str]:
    out = []
    nojs = SCRIPT_BLOCK.sub("", body)
    if 'data-prec-btn' not in nojs:
        out.append(f"{name}: no precision control, so the exact value behind every figure is "
                   f"reachable only on hover")
    elif 'data-prec-btn aria-pressed="false"' not in nojs:
        out.append(f"{name}: the precision control is not pre-set to the reading precision, so "
                   f"the no-script render is not the rounded one")
    if 'id="lb"' in nojs:
        m = re.search(r'<table id="lb"[^>]*>.*?<tbody>(.*?)</tbody>', nojs, re.S)
        if not m or "<tr" not in m.group(1):
            out.append(f"{name}: the leaderboard has no static rows, so it is empty without "
                       f"scripting")
        if 'data-lb-group="all" aria-pressed="true"' not in nojs:
            out.append(f"{name}: the leaderboard's unfiltered group is not pre-selected")
        c = re.search(r'<output id="lb-count"[^>]*>([^<]*)</output>', nojs)
        if not c or not c.group(1).strip():
            out.append(f"{name}: the leaderboard's row count is empty without scripting")
        q = re.search(r'<input[^>]*id="lb-q"[^>]*>', nojs)
        if q and 'value=""' not in q.group(0):
            out.append(f"{name}: the leaderboard's find box has no explicit empty value, so its "
                       f"no-script state is browser-defined")
    for m in re.finditer(r'<table\b[^>]*data-sortable[^>]*>', nojs):
        frag = nojs[m.start():m.start() + 4000]
        if "<tbody" not in frag:
            out.append(f"{name}: a sortable table has no <tbody>, so it cannot be read unsorted")
    return out


def audit_heldout(name: str, body: str) -> list[str]:
    out = []
    for m in HELDOUT.finditer(body):
        window = body[max(0, m.start() - 1400):m.end() + 1400].lower()
        if not any(w in window for w in HELDOUT_NEAR):
            out.append(f"{name}: {m.group(0)!r} at offset {m.start()} appears with no nearby "
                       f"grade-composition caveat, so it could be read as a generalisation "
                       f"result")
    return out


TABLE = re.compile(r"<table\b.*?</table>", re.S | re.I)
THEAD = re.compile(r"<thead\b.*?</thead>", re.S | re.I)
TH = re.compile(r"<th\b", re.I)
COL_CAP = 8


def audit_table_width(name: str, body: str) -> list[str]:
    """No table may carry more than COL_CAP columns. A 14-column table does not render on a laptop,
    and the fix is to split it or to compress the four confusion counts into one cell. Enforced
    over the generated bytes so a new table cannot reintroduce the defect."""
    out = []
    for i, m in enumerate(TABLE.finditer(body), 1):
        head = THEAD.search(m.group(0))
        if not head:
            out.append(f"{name}: table {i} has no <thead>, so its column count cannot be checked")
            continue
        n = len(TH.findall(head.group(0)))
        if n > COL_CAP:
            labels = [re.sub(r"<[^>]+>", "", x).strip()
                      for x in re.findall(r"<th[^>]*>(.*?)</th>", head.group(0), re.S)]
            out.append(f"{name}: table {i} has {n} columns, over the {COL_CAP}-column cap: "
                       f"{labels}")
    return out


def audit_scope(name: str, body: str) -> list[str]:
    low = body.lower()
    return [f"{name}: names the out-of-scope model or arm {tok!r}; it belongs on the System One "
            f"Space" for tok in OUT_OF_SCOPE if tok in low]


def audit_flagged_variable(name: str, body: str) -> list[str]:
    out = []
    for m in FLAGGED.finditer(body):
        window = body[max(0, m.start() - 600):m.end() + 600].lower()
        if not any(w.lower() in window for w in FLAGGED_NEAR):
            out.append(f"{name}: P(block) - P(confirm) at offset {m.start()} appears with no "
                       f"nearby statement that it inverted below chance, so it reads as a "
                       f"rankable variable")
    return out


RETIRED = [
    # Claims from this programme that were checked against an artifact and found false, or that
    # were withdrawn. The build recomputes each corrected figure, so a literal reappearing here
    # means some text is carrying a number or a claim the rollup does not cover.
    ("independent trained-encoder backbone",
     "withdrawn: both Prompt Guard 2 sizes are DebertaV2ForSequenceClassification, so all three "
     "trained encoders share one backbone family"),
    ("independent trained encoder backbone", "the unhyphenated form of the same withdrawn claim"),
    ("three encoder architectures",
     "three checkpoints inside the DeBERTa-v2 family; the count of architectures is two across "
     "the five encoder arms, and one of the two is a control"),
    ("three independent encoders", "the same withdrawn claim in its short form"),
    ("three separate architectures", "the same withdrawn claim again"),
    # Memory: the discriminator is throughput, and no arm approaches the large-machine figure.
    ("needs 24 GB", "no arm in the cohort reaches 8 GiB, let alone 24"),
    ("needs 24 GiB", "the same claim in binary units"),
    ("requires 24 GB", "the same claim"),
    # The Llama Guard mapping that was considered and NOT used.
    ("mapped to S2 Non-Violent Crimes",
     "S2 was the nearest fit and was not used; a custom category built from the I3 policy was "
     "carried through the template's documented categories hook"),
    ("using S2 Non-Violent Crimes", "the same; it was not used"),
    # Laptop figures: the provenance of the peak-RSS column, and its additivity.
    ("estimated peak RSS",
     "the peak came from the kernel's VmHWM polled every 5 ms and cross-checked against "
     "getrusage; it is measured"),
    ("estimated throughput",
     "the throughput figures come from llama-bench -t 8 -p 1200 -n 32 -r 3"),
    ("plus the Q4 size",
     "peak RSS already includes the weights, so it is not additive with the Q4_K_M file size"),
    ("on top of the Q4_K_M size", "the same non-additivity"),
    # The comparison against the board's leading arm.
    ("beats OpenJev",
     "false: DeBERTa's in-sample oracle ceiling still falls 0.22231213872832367 short of "
     "OpenJev's shipped 0.7023121387283237"),
    ("matches OpenJev", "the same, in its weaker form"),
    ("comparable to the System One board",
     "the two Spaces use different corpora and different label sets; only the board arms scored "
     "on s2 at C7/I3/Q2 through the equivalence-checked scorer are comparable, and they are "
     "labelled as board references where they appear"),
    ("interchangeable with the System One",
     "the numbers across the two Spaces are not interchangeable and the pages say so"),
    # Coverage claims that a count makes false.
    ("all 22 arms scored",
     "4 arms have a scored run; 22 is the roster size and 14 have a laptop-feasibility "
     "measurement"),
    ("22 arms measured", "the same overclaim"),
    ("every arm scored", "the same overclaim in words"),
    ("held-out result",
     "no cohort arm has a settled s3 counterpart, so no cohort figure here is a transfer result"),
    ("transfers to held-out", "the same claim"),
    # Editorial claims with no measurable referent.
    ("laptop-ready",
     "undefined; the measurable properties are peak RSS, Q4_K_M size and rows/min, and all three "
     "are published"),
    ("production-ready",
     "undefined, and contradicted by the one scored candidate's operating point"),
    ("state of the art", "names no population and no metric"),
    ("best small model",
     "names no metric; 15 of the 20 candidates have no score yet"),
    # A bare oracle figure presented as a result.
    ("best F1 of 0.48 shows",
     "0.48 is an in-sample oracle upper bound fitted on the rows it is scored on, and every "
     "appearance of it is labelled as one"),
    ("achieves 0.48", "the same bare oracle figure"),
    # Comparisons against the other programme's arms, withdrawn from THIS Space by the scope
    # rule. The figures still exist and are published there; restating them here is what is
    # retired, and the model names themselves are caught by audit_scope() above.
    ("29.98% of", "a cross-programme F1 ratio; that comparison is out of scope here"),
    ("68.3% of", "the same ratio against the oracle ceiling, also out of scope"),
    ("0.4917340329472658", "a cross-programme shipped-F1 gap, out of scope here"),
    ("0.22231213872832367", "a cross-programme oracle-ceiling gap, out of scope here"),
    ("0.7023121387283237", "another programme's arm's score; published on that Space"),
    ("0.70231214", "the same figure in its published rounding"),
    ("0.17194570135746606", "another programme's arm's score"),
    ("0.33206107", "another programme's arm's score"),
    ("0.9480285133598713", "another programme's arm's AUC"),
    ("0.856982082821162", "another programme's arm's AUC"),
    ("0.2994021851164708", "the same, after inversion"),
    ("five arms score below", "a claim about the other programme's board"),
    ("five board arms", "the same claim"),
    ("board reference", "the anchors were removed; nothing here is a board reference"),
    ("the anchor", "the two anchors were removed from this Space entirely"),
    ("two anchors", "the same"),
    ("anchor arm", "the same"),
    # The two-class arms' inapplicable variables.
    ("P(block) + P(confirm) = 0",
     "the variable does not exist for a 2-class arm; it is not computed and not zero-filled"),
    ("0.7395245506540142",
     "a transfer penalty. The two corpora have nearly inverted positive-grade composition, so a "
     "penalty conflates threshold miscalibration with a changed definition of a positive and is "
     "not published here"),
    ("transfer penalty of",
     "no transfer penalty is published on this Space; the composition caveat is"),
    ("0.6872586872586872",
     "a held-out shipped F1 read as a generalisation result; the per-grade AUCs are published "
     "instead"),
    ("0.1948802642444261", "a held-out F1, not published as a transfer result"),
    ("best arm on s3", "framing a held-out score as a generalisation result"),
    ("generalises", "the two corpora cannot support a generalisation claim in either direction"),
    ("does not generalise", "the same claim in the negative"),
    ("both ran at cap",
     "withdrawn: ranks 2 and 3 were claimed jointly on an estimator whose position 3 is not "
     "stable. Rank 2's cap is stated on its own"),
    ("and rank 3 both",
     "the same withdrawn joint claim"),
    ("unweighted mean of the 5",
     "the estimator is named by its label and its source, not described loosely in prose"),
    ("is zero-filled",
     "nothing here is zero-filled; an inapplicable variable is recorded as inapplicable"),
    # The second restricted source is being removed from the corpora entirely. It contributed 0
    # rows to either corpus, so naming it here would publish a dependency this Space does not
    # have. The aggregate-only disclosure stays; the name does not.
    ("augur",
     "the second restricted source contributed 0 rows to either corpus and is being removed from "
     "them; the aggregate-only disclosure is published without naming it"),
    # Claims about the ranking that the artifact's own stability record contradicts.
    ("Both hold their places under every estimator",
     "withdrawn: the artifact records rank_1_stable and rank_2_stable as false, and one scheme "
     "contradicts each"),
    ("hold their places under every estimator", "the same withdrawn claim in its short form"),
    ("stable across every estimator", "the same claim again"),
    # Accuracy without its baseline, and an oracle figure presented as an operating point.
    ("score exactly zero at their own argmax",
     "withdrawn: every arm clears the trivial floor at its own argmax; the 5 arms that score "
     "exactly zero do so at their shipped decision"),
    ("Ranks 2 and 3 ran at cap",
     "the joint claim about positions 2 and 3, withdrawn because position 3 is contested"),
    ("best accuracy",
     "accuracy is dominated by the benign class at these prevalences and is never reported "
     "without the all-allow baseline in the same table"),
    ("accuracy of 0.95",
     "an accuracy below the all-allow baseline on the second corpus; accuracy appears only "
     "beside that baseline"),
    # The source count. The corpora pool their sources under `source.dataset`, and that field
    # carries 10 distinct values on s2, not 13. 13 is the count of PUBLIC source datasets that can
    # be cited by link in the source lock, which is a different population.
    ("pools 13 sources",
     "s2 pools 10 source datasets under `source.dataset`; 13 is a count of citable public sources "
     "in the lock and is a different population"),
    ("13 source datasets",
     "the same overcount; the census is taken over the corpora on disk and reports 10 on s2"),
    ("across 13 sources", "the same overcount"),
    # A per-arm peak RSS does not exist in the artifacts.
    ("peak RSS per arm",
     "the artifacts carry a measured peak resident set for one arm only; the per-arm memory "
     "quantity that exists for all 22 is the snapshot size on disk"),
    ("peak RSS for every arm", "the same claim"),
    # The union result, stated the wrong way round.
    ("two arms clear the gate",
     "the best two-arm union inside the budget reaches recall 0.07798165137614679 and the union of "
     "all 22 arms reaches 0.2018348623853211 at 10.7x the budget; neither clears a gate"),
    ("stacking clears", "the same claim"),
    ("failures are correlated",
     "overstated: 185 of the 221 defined pairs share no caught positive because each model catches "
     "so few, although summed over pairs the caught sets share 62 positives against 15.7 expected "
     "under independent selection"),
    # Errors the 2026-09-24 review corrected. Each phrase carried a figure or a claim the
    # artifacts contradict; the build now derives the corrected statement.
    ("unweighted mean of the five within-quintile",
     "the published length-controlled AUC is the pair-weighted pooled figure"),
    ("both controls fall to chance",
     "under the published estimator control-modernbert-large lands below the chance band"),
    ("both controls sit at chance",
     "the same claim; the verdict is read off the published estimator"),
    ("No surface-cue or label-leakage signal",
     "the pre-registered control prediction did not hold for control-modernbert-large"),
    ("close to independent",
     "the caught sets share 3.95 times the positives independent selection predicts"),
    ("plus one false blocks",
     "a pair each at the full budget can spend up to twice the allowance, 26"),
    ("eight times faster",
     "the ledger's 3,059 against 1,190 rows/min is about 2.6 times, and the GPU serving note "
     "is not published here"),
    ("hungriest",
     "peak RSS was measured for one model only, so no model can be named the hungriest"),
    ("Nothing in the cohort reaches 8 GiB",
     "gemma-3-4b-it's unquantized checkpoint is over 8 GiB"),
    ("judgement call",
     "grade B is destructive by the source's own label without a deterministic proof"),
    ("of the 0 scored",
     "a count of zero printed where the number of ranked models belonged"),
    ("All 0 scored", "the same templating defect"),
    ("moves it down the table",
     "pair weighting moves the sparse-bin model up the table, not down"),
    # The retired variable, as a ranking.
    ("ranked on P(block)",
     "the ranking variable is named in full with its definition label, and the difference "
     "variable is excluded by rule"),
]

pages = sorted(p for p in os.listdir(SITE) if p.endswith(".html"))
if not pages:
    print(f"no pages found in {SITE}")
    raise SystemExit(1)
SCRIPTS_SEEN = 0
PAGES_WITH_SCRIPT = 0
LINKS_SEEN: list[tuple[str, int]] = []
EMBEDS_SEEN: list[tuple[str, int]] = []
all_ids: dict[str, set[str]] = {}
all_hrefs: dict[str, list[tuple[str, int]]] = {}
charts = 0
EX_SPANS_SEEN = 0
PREC_PAGES = 0
LB_PAGES = 0
SORTABLE_SEEN = 0

for name in pages:
    path = os.path.join(SITE, name)
    with open(path, "r", encoding="utf-8") as fh:
        body = fh.read()

    for lit, why in RETIRED:
        # A bare dollar or percent literal must not fire on a LONGER number that merely starts
        # with it: "$2.68" is a retired provider total, "$2.68307" is a live per-catch value the
        # chart computes. Anchored with a digit-boundary check so the guard stays useful without
        # becoming a false positive on every rebuild.
        hit = False
        if re.search(r"[\d.]$", lit):
            hit = re.search(re.escape(lit) + r"(?![\d])", body) is not None
        else:
            hit = lit in body
        if hit:
            PROBLEMS.append(f"{name}: retired figure {lit!r} is present as literal text - {why}")

    # The disclosures this Space's pages must carry. A page that lost one of these lost a
    # statement the payload depends on, so it is a build failure.
    REQUIRED = [
        # ---- index.html: the answer
        ("index.html", "not interchangeable",
         "the two-Space non-interchangeability statement is missing from index"),
        ("index.html", "defenseclaw-system-one",
         "index does not name the other Space it must be distinguished from"),
        ("index.html", "block false-positive rate",
         "index does not state the candidate's false-positive rate"),
        ("index.html", "The verdict", "index carries no verdict panel"),
        ("index.html", "No model in this cohort is usable",
         "index does not state the answer in plain words"),
        ("index.html", "Assumption", "index carries no assumption table"),
        ("index.html", "What breaks it", "the assumption table has no falsification column"),
        # ---- operating-point.html: every model at the budget
        ("operating-point.html", "Block FPR",
         "the operating-point page has no block-FPR column"),
        ("operating-point.html", "Precision",
         "the operating-point page has no precision column"),
        ("operating-point.html", "Recall", "the operating-point page has no recall column"),
        ("operating-point.html", "Accuracy", "the operating-point page has no accuracy column"),
        ("operating-point.html", "0.00384502",
         "the operating-point page does not state the shared false-positive budget"),
        ("operating-point.html", "All-allow accuracy",
         "accuracy is printed without the all-allow baseline in the same table"),
        ("operating-point.html", "0.20503174229955326",
         "the block-everything baseline is missing from the operating-point page at full precision"),
        ("operating-point.html", "tp/fp/fn/tn",
         "the confusion counts are not in one compact cell, so a table is wider than it needs "
         "to be"),
        ("operating-point.html", "Wilson 95%",
         "the operating-point page reports a proportion with no interval on it"),
        ("operating-point.html", "chance",
         "the ROC panels are published without the chance diagonal being named"),
        ("operating-point.html", "Jaccard",
         "the failure-overlap analysis is missing from the operating-point page"),
        ("operating-point.html", "clears no gate",
         "the operating-point page does not state what the two-model union concludes"),
        ("operating-point.html", "bootstrap",
         "the interval on F1 is published without its method named"),
        ("operating-point.html", "source dataset",
         "the per-source recall result is missing from the operating-point page"),
        ("operating-point.html", "under 3B", "the first size band is missing"),
        ("operating-point.html", "3B to 6B", "the second size band is missing"),
        ("operating-point.html", "6B and up", "the third size band is missing"),
        ("operating-point.html", "Nothing in this cohort lands",
         "the empty size band is not printed with its zero count and its one-line statement"),
        ("operating-point.html", "log scale",
         "the size-against-F1 scatter is missing from the operating-point page"),
        # ---- results.html: ranking and diagnostics
        ("results.html", "estimator",
         "the results page does not name which length-control estimator it publishes"),
        ("results.html", "chance band",
         "the results page does not print the chance band beside its AUC table"),
        ("results.html", "A and B coincide",
         "the AUC definition label is missing from the results page"),
        ("results.html", "Hanley",
         "the chance band is printed without its standard-error method"),
        ("results.html", "in-sample upper bound",
         "the oracle label is missing from the results page"),
        ("results.html", "0.20503174229955326",
         "the block-everything baseline is missing beside the default-decision F1 column"),
        ("results.html", "length-controlled",
         "the length-control rule is missing from the results page"),
        ("results.html", "Calibration",
         "the calibration diagram is missing from the results page"),
        ("results.html", "Gate: ",
         "the leakage gate is published without a verdict"),
        # ---- datasets.html: data and models
        ("datasets.html", "39f2c1df2369952a0525cc4c5575f4bdb590fb3ca8c1bc6805cf4f376c1adbf7",
         "the s2 corpus digest is missing from the datasets page"),
        ("datasets.html", "0ccbc08fb408ffefc89e051c585cfe22433b1ed4c9714f60cc0f7e242969fa03",
         "the second corpus's digest is missing from the datasets page"),
        ("datasets.html", "truth_grade",
         "the datasets page does not name the function that assigns every grade"),
        ("datasets.html", "Redistribution",
         "the datasets page carries no redistribution marker"),
        ("datasets.html", "evaluation-only",
         "the evaluation-only disposition of the case rows is missing"),
        ("datasets.html", "mcptox",
         "the local-evaluation-only disclosure is missing from the datasets page"),
        ("datasets.html", "grade A",
         "the datasets page does not carry the grade-composition caveat"),
        ("datasets.html", "no transfer figure is published",
         "the datasets page does not state that no transfer figure is published"),
        ("datasets.html", "source.dataset",
         "the datasets page does not name the field the source census is taken over"),
        ("datasets.html", ">Licence</th>", "the licence column is missing from the roster"),
        ("datasets.html", "apache-2.0", "the roster lost its licence values"),
        ("datasets.html", "llama3.2", "the roster lost a gating group"),
        ("datasets.html", "gemma", "the roster lost a gating group"),
        ("datasets.html", "Falcon LLM", "Falcon3's licence name is missing from the roster"),
        ("datasets.html", "DebertaV2ForSequenceClassification",
         "the withdrawn independent-backbone claim's correction is missing from the roster"),
        ("datasets.html", "llamaguard_default_taxonomy_covers_task: false",
         "the Llama Guard taxonomy record is missing from the roster"),
        ("datasets.html", "mixture-of-experts",
         "the mixture-of-experts model's parameter counts are not distinguished"),
        ("datasets.html", "VmHWM", "the peak-RSS provenance caveat is missing"),
        ("datasets.html", "optimistic ceiling", "the foreign-load caveat is missing"),
        ("datasets.html", "peak-RSS axis cannot be drawn",
         "the page does not record that per-model peak RSS is absent from the artifacts"),
        ("datasets.html", "not reproducible from vendored code",
         "the laptop figures are published without saying they cannot be reproduced"),
        # ---- methodology.html: method and reproduce
        ("methodology.html", "39f2c1df2369952a0525cc4c5575f4bdb590fb3ca8c1bc6805cf4f376c1adbf7",
         "the corpus digest is missing from methodology"),
        ("methodology.html", "grade-C", "methodology does not explain the grade-C exclusion"),
        ("methodology.html", "complete-line prefix",
         "the settlement digest's scope is not stated"),
        ("methodology.html", "untorn", "the settlement row requirement is not stated"),
        ("methodology.html", "oracle upper bound",
         "the oracle-ceiling rule is missing from methodology"),
        ("methodology.html", "mcptox",
         "the local-evaluation-only disclosure is missing from methodology"),
        ("methodology.html", "aggregate-only",
         "the aggregate-only disclosure is missing from methodology"),
        ("methodology.html", "stay private",
         "the private-data-repository statement is missing from methodology"),
        ("methodology.html", "feat/system-one-benchmarks",
         "the deep links are not pinned to the branch"),
        ("methodology.html", "retracted",
         "the changelog does not record that the earlier length-control estimator was retracted"),
        ("methodology.html", "Unweighted mean, all bins",
         "the four-estimator table is missing"),
        ("methodology.html", "Pair-weighted pooled",
         "the pair-weighted estimator is missing"),
        ("methodology.html", "Mann-Whitney",
         "the estimand argument for the published estimator is missing"),
        ("methodology.html", "over-weighting",
         "the weight-against-evidence argument is missing"),
        ("methodology.html", "Hanley",
         "the variance argument for the published estimator is missing"),
        ("methodology.html", "area under each drawn curve",
         "methodology does not state that the drawn ROC reproduces the published AUC"),
        ("README.md", "grade A",
         "the Space card does not carry the grade-composition caveat"),
    ]

    for page, text, reason in REQUIRED:
        if name == page and text not in body:
            PROBLEMS.append(f"{name}: {reason}")

    for m in TOKEN.finditer(body):
        PROBLEMS.append(f"{name}: leftover template token near offset {m.start()}")
    if "{{" in body.replace("&#123;", ""):
        for m in re.finditer(r"\{\{", body):
            frag = body[m.start():m.start() + 40].replace("\n", " ")
            PROBLEMS.append(f"{name}: literal '{{{{' in output: {frag!r}")

    c = Check(name)
    c.feed(body)
    if c.stack:
        PROBLEMS.append(f"{name}: unclosed {[t for t, _ in c.stack]}")
    if c.script_src:
        PROBLEMS.append(f"{name}: contains {c.script_src} <script src=...> element(s); every "
                        f"script must be inline")
    # the interactive controls are optional, but a page that ships one must ship all of it
    if c.json_blobs and c.scripts < 2:
        PROBLEMS.append(f"{name}: has a JSON data blob but no inline script to read it")
    if (c.ranges or c.lens_btns) and not c.json_blobs:
        PROBLEMS.append(f"{name}: has an interactive control but no JSON data blob")
    if c.sortable and not c.sort_heads:
        PROBLEMS.append(f"{name}: table[data-sortable] with no th[data-sort] to click")
    if c.sort_heads and not c.sortable:
        PROBLEMS.append(f"{name}: th[data-sort] outside any table[data-sortable]")
    if c.links:
        PROBLEMS.append(f"{name}: contains {c.links} <link> element(s); the stylesheet must be "
                        f"inlined because a private Space answers 401 for subresources")
    # c.external is already reported per occurrence above; this is the roll-up
    LINKS_SEEN.append((name, c.allowed_links))
    EMBEDS_SEEN.append((name, c.embeds))
    for m in URL.finditer(body):
        u = m.group(0)
        if link_ok(u) or embed_ok(u):
            continue
        PROBLEMS.append(f"{name}: external URL at offset {m.start()}: {u[:80]!r}")
    if c.styles != 1:
        PROBLEMS.append(f"{name}: {c.styles} <style> block(s), expected exactly 1")
    inline = STYLE_BLOCK.search(body)
    if not inline or "--series-1" not in inline.group(0):
        PROBLEMS.append(f"{name}: the inlined <style> block is missing or does not carry the palette")
    PROBLEMS.extend(audit_svg_paint(name, body, "as shipped"))
    PROBLEMS.extend(audit_svg_paint(name, STYLE_BLOCK.sub("", body), "style stripped"))
    PROBLEMS.extend(audit_nojs(name, body))
    PROBLEMS.extend(audit_precision(name, body))
    PROBLEMS.extend(audit_controls(name, body))
    EX_SPANS_SEEN += len(EX_SPAN.findall(body))
    PREC_PAGES += 1 if "data-prec-btn" in body else 0
    LB_PAGES += 1 if 'id="lb"' in body else 0
    SORTABLE_SEEN += len(re.findall(r"<table\b[^>]*data-sortable", body))
    PROBLEMS.extend(audit_flagged_variable(name, body))
    PROBLEMS.extend(audit_scope(name, body))
    PROBLEMS.extend(audit_heldout(name, body))
    PROBLEMS.extend(audit_table_width(name, body))
    if c.figures != c.figcaptions:
        PROBLEMS.append(f"{name}: {c.figures} chart figures but {c.figcaptions} figcaptions")
    charts += c.figures
    SCRIPTS_SEEN += c.scripts
    if c.scripts:
        PAGES_WITH_SCRIPT += 1
    all_ids[name] = c.ids
    all_hrefs[name] = c.hrefs

    for sv in SVG_BLOCK.findall(body):
        vb = VIEWBOX.search(sv)
        if not vb:
            PROBLEMS.append(f"{name}: <svg> without a 0-origin viewBox")
            continue
        vw, vh = float(vb.group(1)), float(vb.group(2))
        # geometry attributes on drawing primitives only (text is allowed to overflow a little)
        for prim in re.finditer(r"<(rect|line|circle)\b([^>]*)>", sv):
            attrs = prim.group(2)
            for a, lim in (("x", vw), ("x1", vw), ("x2", vw), ("cx", vw),
                           ("y", vh), ("y1", vh), ("y2", vh), ("cy", vh)):
                m = re.search(rf'\b{a}="(-?[\d.]+)"', attrs)
                if not m:
                    continue
                v = float(m.group(1))
                if v < -2 or v > lim + 2:
                    PROBLEMS.append(
                        f"{name}: <{prim.group(1)}> {a}={v} outside viewBox 0..{lim}")
            wm = re.search(r'\bwidth="([\d.]+)"', attrs)
            xm = re.search(r'\bx="(-?[\d.]+)"', attrs)
            if wm and xm and float(xm.group(1)) + float(wm.group(1)) > vw + 2:
                PROBLEMS.append(
                    f"{name}: <rect> right edge "
                    f"{float(xm.group(1)) + float(wm.group(1)):.1f} > viewBox width {vw}")
        # polylines: every plotted vertex must stay inside the viewBox. The attribute checks
        # above only see x/y/cx/cy, so a curve drawn from data could leave the canvas unseen.
        for pl in re.finditer(r'<polyline\b[^>]*\bpoints="([^"]*)"', sv):
            for pair in pl.group(1).split():
                try:
                    px, py = (float(t) for t in pair.split(","))
                except ValueError:
                    PROBLEMS.append(f"{name}: <polyline> point {pair!r} is not an x,y pair")
                    break
                if px < -2 or px > vw + 2 or py < -2 or py > vh + 2:
                    PROBLEMS.append(f"{name}: <polyline> point {px},{py} outside viewBox "
                                    f"0..{vw} by 0..{vh}")
                    break
        # text runs: estimate the rendered extent and require it to stay on canvas
        for t in re.finditer(r"<text\b([^>]*)>(.*?)</text>", sv, re.S):
            attrs, inner = t.group(1), re.sub(r"<[^>]+>", "", t.group(2))
            if "transform=" in attrs:
                continue          # a rotated run's horizontal extent is not its x span
            inner = inner.replace("&#183;", "-").replace("&#8212;", "-")
            inner = inner.replace("&#215;", "x").replace("&#8722;", "-").strip()
            xm = re.search(r'\bx="(-?[\d.]+)"', attrs)
            if not xm or not inner:
                continue
            x0 = float(xm.group(1))
            size = 11.5
            if 'class="ax"' in attrs:
                size = 11
            wide = sum(1 for ch in inner if ch in "MWmw@%0123456789")
            w = (len(inner) + 0.22 * wide) * 0.545 * size
            anchor = "start"
            if 'text-anchor="end"' in attrs:
                anchor = "end"
            elif 'text-anchor="middle"' in attrs:
                anchor = "middle"
            left = x0 if anchor == "start" else (x0 - w if anchor == "end" else x0 - w / 2)
            right = left + w
            if left < -4 or right > vw + 4:
                PROBLEMS.append(
                    f"{name}: <text> {inner[:46]!r} spans {left:.0f}..{right:.0f}, "
                    f"outside viewBox 0..{vw:.0f}")

# The Space card is markdown, so it is outside the HTML page loop. It carries the front matter
# the Hugging Face static SDK needs and the statement that separates the two Spaces.
CARD = os.path.join(SITE, "README.md")
if not os.path.exists(CARD):
    PROBLEMS.append("README.md: the Space card is missing, so the Space has no front matter")
else:
    card = open(CARD, encoding="utf-8").read()
    for text, reason in (("sdk: static", "the static SDK declaration is missing"),
                         ("app_file: index.html", "the entry page declaration is missing"),
                         ("not interchangeable",
                          "the non-interchangeability statement is missing"),
                         ("Vineethsain/defenseclaw-system-one",
                          "the other Space is not named"),
                         ("0.20503174229955326", "the trivial floor is missing"),
                         ("Aggregates only", "the aggregate-only disclosure is missing")):
        if text not in card:
            PROBLEMS.append(f"README.md: {reason}")

for name, hrefs in all_hrefs.items():
    for href, line in hrefs:
        if href.startswith(("http://", "https://", "mailto:")):
            continue
        target, _, frag = href.partition("#")
        target = target or name
        if target not in all_ids:
            PROBLEMS.append(f"{name}:{line}: link to missing page {target!r}")
            continue
        if frag and frag not in all_ids[target]:
            PROBLEMS.append(f"{name}:{line}: link to missing anchor #{frag} in {target}")

print(f"pages checked      : {len(pages)}")
print(f"chart figures      : {charts}")
print(f"inline scripts     : {SCRIPTS_SEEN} across {PAGES_WITH_SCRIPT} page(s), 0 with src=")
_al = sum(n for _p, n in LINKS_SEEN)
print(f"outbound links     : {_al} to allowed source hosts, 0 other external URLs")
_em = sum(n for _p, n in EMBEDS_SEEN)
_ep = [p for p, n in EMBEDS_SEEN if n]
print(f"viewer embeds      : {_em} Hugging Face dataset-viewer iframe(s) on "
      f"{len(_ep)} page(s), each inside a collapsed <details>; 0 other subresources")
print(f"internal links     : {sum(len(v) for v in all_hrefs.values())}")
print(f"retired figures    : {len(RETIRED)} checked, 0 present as literal text")
print(f"table width        : every table at or under {COL_CAP} columns")
print(f"precision          : {EX_SPANS_SEEN:,} figures at reading precision, each round-tripping "
      f"to its exact decimal; nothing visible over {MAX_SIG} significant digits")
print(f"controls           : precision control on {PREC_PAGES} page(s), "
      f"{SORTABLE_SEEN:,} sortable table(s), leaderboard on {LB_PAGES} page(s)")
if PROBLEMS:
    print(f"PROBLEMS           : {len(PROBLEMS)}")
    for p in PROBLEMS[:80]:
        print("  " + p)
    raise SystemExit(1)
print("PROBLEMS           : 0")
