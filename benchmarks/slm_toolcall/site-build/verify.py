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


def audit_heldout(name: str, body: str) -> list[str]:
    out = []
    for m in HELDOUT.finditer(body):
        window = body[max(0, m.start() - 1400):m.end() + 1400].lower()
        if not any(w in window for w in HELDOUT_NEAR):
            out.append(f"{name}: {m.group(0)!r} at offset {m.start()} appears with no nearby "
                       f"grade-composition caveat, so it could be read as a generalisation "
                       f"result")
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
        ("index.html", "not interchangeable",
         "the two-Space non-interchangeability statement is missing from index"),
        ("index.html", "defenseclaw-system-one",
         "index does not name the other Space it must be distinguished from"),
        ("index.html", "block false-positive rate",
         "index does not state the candidate's false-positive rate"),
        ("results.html", "estimator",
         "the results page does not name which length-control estimator it publishes"),
        ("results.html", "Unweighted mean, all bins",
         "the four-estimator table is missing from the results page"),
        ("results.html", "Pair-weighted pooled",
         "the pair-weighted estimator is missing from the results page"),
        ("index.html", "retracted",
         "index does not record that the earlier length-control estimator was retracted"),
        ("results.html", "Pair-weighted pooled",
         "the pair-weighted estimator is missing from the results page"),
        ("results.html", "Mann-Whitney",
         "the estimand argument for the published estimator is missing"),
        ("results.html", "over-weighting",
         "the weight-against-evidence argument is missing"),
        ("results.html", "Hanley",
         "the variance argument for the published estimator is missing"),
        ("results.html", "grade A",
         "the grade-composition caveat is missing from the results page"),
        ("results.html", "no transfer figure is published",
         "the results page does not state that no transfer figure is published"),
        ("index.html", "grade A",
         "index does not carry the grade-composition caveat"),
        ("README.md", "grade A",
         "the Space card does not carry the grade-composition caveat"),
        ("results.html", "Block FPR",
         "the results page has no block-FPR column"),
        ("results.html", "Precision", "the results page has no precision column"),
        ("results.html", "Recall", "the results page has no recall column"),
        ("methodology.html", "grade-C", "methodology does not explain the grade-C exclusion"),
        ("methodology.html", "complete-line prefix",
         "the settlement digest's scope is not stated"),
        ("methodology.html", "untorn",
         "the settlement row requirement is not stated"),
        ("roster.html", ">Licence</th>", "the licence column is missing from the roster"),
        ("roster.html", "apache-2.0", "the roster lost its licence values"),
        ("roster.html", "llama3.2", "the roster lost a gating group"),
        ("roster.html", "gemma", "the roster lost a gating group"),
        ("roster.html", "DebertaV2ForSequenceClassification",
         "the withdrawn independent-backbone claim's correction is missing from the roster"),
        ("roster.html", "llamaguard_default_taxonomy_covers_task: false",
         "the Llama Guard taxonomy record is missing from the roster"),
        ("roster.html", "Falcon LLM", "Falcon3's licence name is missing from the roster"),
        ("baselines.html", "0.20503174229955326",
         "the trivial floor is missing from the baselines page at full precision"),
        ("baselines.html", "length-controlled",
         "the length-control rule is missing from the baselines page"),
        ("methodology.html", "39f2c1df2369952a0525cc4c5575f4bdb590fb3ca8c1bc6805cf4f376c1adbf7",
         "the corpus digest is missing from methodology"),
        ("methodology.html", "oracle upper bound",
         "the oracle-ceiling rule is missing from methodology"),
        ("methodology.html", "mcptox",
         "the local-evaluation-only disclosure is missing from methodology"),
        ("methodology.html", "augur_unsafe_tool_input_eval",
         "the aggregate-only disclosure is missing from methodology"),
        ("methodology.html", "stay private",
         "the private-data-repository statement is missing from methodology"),
        ("results.html", "in-sample upper bound",
         "the oracle label is missing from the results page"),
        ("footprint.html", "VmHWM", "the peak-RSS provenance caveat is missing from footprint"),
        ("footprint.html", "optimistic ceiling",
         "the foreign-load caveat is missing from footprint"),
        ("reproduce.html", "feat/system-one-benchmarks",
         "the deep links are not pinned to the branch"),
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
    PROBLEMS.extend(audit_flagged_variable(name, body))
    PROBLEMS.extend(audit_scope(name, body))
    PROBLEMS.extend(audit_heldout(name, body))
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
if PROBLEMS:
    print(f"PROBLEMS           : {len(PROBLEMS)}")
    for p in PROBLEMS[:80]:
        print("  " + p)
    raise SystemExit(1)
print("PROBLEMS           : 0")
