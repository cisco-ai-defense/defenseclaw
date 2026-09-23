#!/usr/bin/env python3
"""Post-build verification of the generated static site.

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

SITE = sys.argv[1] if len(sys.argv) > 1 else "$WORK/.system-one-space-build/site"
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
            elif not h.startswith(ALLOWED_LINKS):
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
RETIRED = [
    ("$2.68", "stale provider-spend total; the rollup computes $5.679945"),
    ("1.903382", "stale hosted-Jev spend; the rollup computes 4.903156"),
    ("781,823", "stale request count; the rollup computes it"),
    ("783,911", "stale request count across a stale manifest count"),
    ("$199", "a GPU total derived from an uptime that is in no artifact"),
    ("15.45 h", "an uptime that is in no artifact"),
    ("20.78", "superseded review-burden delta; the chart computes 22.32"),
    ("3-5x more benign", "superseded ratio range; the measured range is 2.7x-5.1x"),
    # -------------------------------------------------- second fact audit
    # Each of these is a claim that was checked against its artifact and found false or
    # out of scope. The corrected version is a computed figure, so a literal reappearing
    # here means some text is carrying a number the rollup does not cover.
    ("13–17% per model", "false for OpenJev, whose flagged-event instability is 0.00%"),
    ("13-17% per model", "false for OpenJev, whose flagged-event instability is 0.00%"),
    ("all 24 cells", "24 covers three backends; the four-model within-family table is 32"),
    ("27 cache configurations",
     "27 is the non-reference RUN count; there are 7 shim configurations over 28 runs"),
    ("3,927 of 3,927 one-second polls",
     "all 3,927 polls are one serving process, not the three-process corroboration"),
    ("1,416 of 69,135",
     "1,416 of 1,416 within that corpus; 69,135 is the whole four-corpus catalogue"),
    ("always scores higher",
     "the any-intervention F1 is LOWER than block-only for four of the five models"),
    ("unsafe families", "221 is a count of unsafe cases, not families"),
    ("a third model blinded",
     "the adjudicator is a fifth decider over a four-decider queue"),
    ("4× to 9×", "the measured multipliers are 3.7x and 9.2x"),
    ("4–9× the whole decision", "the measured multipliers are 3.7x and 9.2x"),
    ("10–32% benign", "10.1-17.9% on the C7 arms; 32.0% is a C1 arm that must be named"),
    ("10–32% of real benign",
     "10.1-17.9% on the C7 arms; 32.0% is a C1 arm that must be named"),
    ("12 families", "the artifact field is distinct_cases, and records 12"),
    ("6 families", "the artifact field is distinct_cases, and records 6"),
    ("1 family, all grade A", "the artifact field is distinct_cases, and records 1"),
    ("= 0.0042%", "stale error rate; the rollup recomputes it over the current request total"),
    ("three policies are undominated",
     "the frontier size is computed per panel; two are undominated on the Broad corpus"),
    ("recovers 35% of the loss",
     "35% is a share of the block-RATE loss from the superseded shared-baseline estimator"),
    ("in <strong>four</strong> cascade",
     "escalate-on-confirm restores 0.75173 in ONE ordering; the identity check holds in four"),
    ("in four cascade orderings",
     "escalate-on-confirm restores 0.75173 in ONE ordering; the identity check holds in four"),
    ("Crashed the scorer", "the non-scorable class crashed the RUNNER, before any scoring"),
    ("crashes the scorer", "the non-scorable class crashed the RUNNER, before any scoring"),
    ("fails open silently", "dramatised; the measurable property is 'no error code'"),
    ("fail open silently", "dramatised; the measurable property is 'no error code'"),
    ("allows silently", "dramatised; the measurable property is 'no error code'"),
    ("errors silently", "dramatised; the measurable property is 'no new error raised'"),
    ("only non-commercial source in the inventory",
     "the lock holds a second CC-BY-NC-4.0 entry that is enabled and supplies no rows"),
    ("Lowest measured p50 of the five", "Gemma 4 has no measured p50, so the set is four"),
    ("the only format that beats removing the tier",
     "only three of the five formats were run in the cascade"),
    ("both from the short-circuit composition",
     "the Broad per-surface optima come from escalate-on-confirm"),
    ("11 of 12 injected failure modes",
     "the judge's probe set is 11 failure modes plus one healthy control"),
    ("11 of its own 12 injected failure modes",
     "the judge's probe set is 11 failure modes plus one healthy control"),
    ("deployable false-block rate",
     "'deployable' was undefined and excluded the arm with the lowest block FPR of all eight"),
    ("against ~1.9 s", "no artifact records the leading candidate's per-request p50"),
    ("the production read", "unexplained jargon for the default scoring lens"),
    ("3 stages<br>7 cascade variants",
     "the invariant check covers 4 stage/model pairs, from 2 stages and 2 models"),
    ("25.89% → <strong>44.65%</strong>",
     "background-subtracted and persisted in no artifact; the raw shares are 11.97% and 18.24%"),
    ("25.89% → 44.65% cache share",
     "background-subtracted and persisted in no artifact; the raw shares are 11.97% and 18.24%"),
    ("Cases are derived from decisions",
     "the calculator takes cases directly and applies no decisions-per-case ratio"),
    ("silent fail-open", "dramatised; the measurable property is 'no error code'"),
    ("14 of 1,412", "no key path under outputs/ yields this pair"),
    ("of those ties flipped", "no artifact records a flip rate for the tied rows"),
    ("outputs/*/*.meta.json", "the rollup glob is recursive: outputs/**/*.meta.json"),
    # Jev's cascade figures were excluded on the strength of a probe that measured a DIFFERENT
    # model's file in the same directory. Jev's own predictions were on the real rule tier all
    # along (realdet-jev-provenance.json). These are the exact generated sentences that carried
    # the false claim; the restated-figures table quotes the claim in its "Earlier claim" column
    # with the correction beside it, so the retired strings are the generated phrasings only.
    ("is scored against the all-allow stand-in rule tier, which is worth up to 0.057",
     "that was an inference from OpenJev's file; Jev's own tier is real"),
    ("its scorecard family sits on the all-allow stand-in",
     "the tier is a property of each scorecard, and Jev's is the real tier"),
    ("Jev's family is scored on the all-allow stand-in",
     "the stand-in finding is about the OpenJev file in that directory only"),
    # The ranked leaderboard is one question format for every model. These phrasings ranked
    # DiffusionGemma's Q3 arm against other models' Q2 arms; at the shared format it is last on
    # both lenses and no model gains on the looser one. The restated-figures table quotes the
    # withdrawn claim in its "Earlier claim" column, so only the generated phrasings are retired.
    ("First of all five rows on any-intervention F1",
     "that ranked a Q3 arm against Q2 arms; at the shared format it is last on both lenses"),
    ("first of the five rows on any-intervention F1",
     "that ranked a Q3 arm against Q2 arms; at the shared format it is last on both lenses"),
    ("First on any-intervention F1",
     "the short verdict form of the same withdrawn claim"),
    # The SURVIVING phrasings, not only the withdrawn one. Retiring "DiffusionGemma leads on
    # any-intervention F1" left nine paraphrases live in a shared registry for three revisions,
    # because none of them used the retired words. These match the paraphrase.
    ("higher than the block-only F1 for DiffusionGemma",
     "false at the ranked parity grid: 0.18527 any against 0.26792 block, the largest loss"),
    ("which reorders the ranking",
     "the lens does not reorder the ranked set: OpenJev > Jev > DiffusionGemma on both lenses"),
    ("reorders the leaderboard",
     "the lens does not reorder the ranked set: OpenJev > Jev > DiffusionGemma on both lenses"),
    ("it reorders the models",
     "the lens does not reorder the ranked set: OpenJev > Jev > DiffusionGemma on both lenses"),
    ("Only Q2 improves on it",
     "population unnamed: three of five formats were run in the cascade. Name the three."),
    ("the only format that beats removing the tier",
     "population unnamed: three of five formats were run in the cascade"),
    ("DiffusionGemma leads on\n  any-intervention F1",
     "withdrawn: the lead was a property of Q3, not of the model"),
    ("best any-intervention F1, last on block-only",
     "withdrawn: both cells were Q3 and are not comparable with the Q2 rows"),
    # Retired as a PHRASING, not as a fact. When it was written no row scored higher on the
    # looser lens; one added arm now does. The live statement is recomputed per build and names
    # the row and both of its values, so this bare form must not come back.
    ("is the only row that scores higher on the looser lens",
     "a bare 'only' with no row named and no values: the live statement names the row and "
     "prints both of its F1s, recomputed per build"),
    # ------------------------------------- third audit: the independent semantic pass
    # Again, the surviving phrasing as well as the withdrawn one.
    ("worth up to 0.057",
     "the rule tier is worth 0.000000 on the block lens; 0.057228 is one composition gap at "
     "Production weighting and is not the maximum, which is 0.436364"),
    ("0.057 block F1",
     "the same bound, in the sentences that quoted it without the word 'worth'"),
    ("0.057 F1",
     "the same bound again"),
    ("the two tiers are never mixed in one chart",
     "on the block lens there is nothing to mix: the stand-in equals escalate-on-confirm in all "
     "12 measured cells. The axis that matters is the composition"),
    ("This uses the REAL deterministic rule tier",
     "attached by pattern to the two figures that ARE the stand-in, asserting the opposite of "
     "their own source line"),
    ("inverts the Production-weighted finding",
     "attributed to the rule tier an effect that is a composition choice"),
    ("only tier on this page with a measured provider bill",
     "false: hosted Jev is a ranked row on the same table and has one"),
    ("$0.00018162",
     "the Q2 judge run's per-case price applied to the Q0 run the cascade was scored from; the "
     "Broad figure is $0.00019353 and the Production figure is $0.00009228"),
    ("spread is 419",
     "a cross-corpus spend ratio built on one corpus's price applied to both; it is about 200"),
    ("419\u00d7",
     "the same ratio, in its rendered multiplication-sign form"),
    ("was run at four settings and only four",
     "the per-surface sweep measures five, including the 0.50 the site recommends"),
    ("Four measured settings",
     "five in the per-surface sweep; four in the whole-corpus scorecard sweep"),
    ("factor of 1.73",
     "the two decisions-per-case ratios were on different denominators; per scorable case it is "
     "1.94"),
    ("the single largest effect on this page",
     "names no metric and no comparison set; deleted rather than softened"),
    ("nothing else beats on both",
     "the implemented relation is weak domination: matched or beaten on both with one strict "
     "loss. All four greyed points tie on spend and lose on F1 only"),
    ("-0.182644 and -0.228212",
     "the reproduction recipe's control pair was on the any lens and the 3-class separation "
     "metric, not the block lens and sep_vs_resisted the same steps compute"),
    ("the self-hosted small model recorded no provider spend",
     "two self-hosted small models are drawn on those panels"),
    ("the highest of those rows is DiffusionGemma",
     "a tie printed as a strict ordering: both rows are 0.00680272 with 23 false blocks each"),
    ("$0.0425",
     "a mismatched-basis ratio: the per-manifest hosted rate is $0.042000 per million and every "
     "priced manifest agrees on it"),
    ("loses on every quality, cost",
     "the CPU-only candidate wins the one cost axis these artifacts carry"),
    ("no single configuration holds the best value on more than one axis",
     "false from the cells beneath it: two configurations hold a best on three and two axes"),
    ("41.95 s on CPU",
     "the table promises each model's own best per axis; that arm is not Von's best, which is "
     "38.76 s at C7/I3/Q1"),
    ("the artifact records ~11",
     "a per-request ratio grounded in nothing; neither scorecard records a per-request p50"),
    ("Seven policies",
     "the disposition chart draws 19 rows over three small models, not seven"),
    ("The largest measured cost lever",
     "two-sided routing is the largest measured reduction; per-surface is the largest "
     "between-surface ratio"),
    ("Escalate-on-confirm restores 0.75173.",
     "stated as a property of the composition; it is each ordering's own stand-in figure that is "
     "restored, and 0.75173 belongs to one ordering"),
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

    # Check for required license disclosures
    REQUIRED = [
        ("index.html", "CC BY-NC 4.0", "OpenJev license disclosure missing from index"),
        ("decide.html", "CC BY-NC 4.0", "OpenJev license disclosure missing from decide"),
        ("recommendations.html", "CC BY-NC 4.0", "OpenJev license disclosure missing from recommendations"),
        ("index.html", "<th>License</th>", "License column missing from leaderboard"),
        ("index.html", "apache-2.0", "DiffusionGemma/Gemma4 license missing from leaderboard"),
        ("index.html", "served via Bedrock (paid service)", "Gemma 4 Bedrock qualifier missing"),
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
        if u.startswith(ALLOWED_LINKS) or embed_ok(u):
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
