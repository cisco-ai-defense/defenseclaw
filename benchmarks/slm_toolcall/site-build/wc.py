#!/usr/bin/env python3
"""Visible-word counter, split by where the words live.

Buckets, in priority order so nothing is counted twice:
  chart  - inside an <svg> (axis ticks, in-chart labels: per-datum evidence)
  table  - inside a <table> (cells and captions)
  card   - inside a <div> whose class names a card or tile
  other  - everything else a reader sees

<head> and <style> are excluded throughout.
"""
import json
import os
import re
import sys

TAG = re.compile(r"<[^>]+>")
HEAD = re.compile(r"<head\b.*?</head>", re.S | re.I)
STYLE = re.compile(r"<style\b.*?</style>", re.S | re.I)
SCRIPT = re.compile(r"<script\b.*?</script>", re.S | re.I)
SVG = re.compile(r"<svg\b.*?</svg>", re.S | re.I)
TABLE = re.compile(r"<table\b.*?</table>", re.S | re.I)
WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9''’.,%$/+()−-]*")
CARD_OPEN = re.compile(r'<div\b[^>]*class="[^"]*\b(?:card|fcard|mcard|tile)\b[^"]*"[^>]*>', re.I)
DIV = re.compile(r"</?div\b", re.I)


def words(fragment: str) -> int:
    t = TAG.sub(" ", fragment)
    t = t.replace("&nbsp;", " ").replace("&#183;", " ").replace("&#8212;", " ")
    return len(WORD.findall(t))


def card_spans(body: str):
    """Spans of every div whose class names a card, matched by balanced <div> depth."""
    out = []
    for m in CARD_OPEN.finditer(body):
        depth, pos = 1, m.end()
        while depth and pos < len(body):
            d = DIV.search(body, pos)
            if not d:
                break
            depth += -1 if d.group(0).startswith("</") else 1
            pos = d.end()
        out.append((m.start(), pos))
    # merge nested/overlapping spans so a card inside a card is counted once
    merged = []
    for a, b in sorted(out):
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return merged


def split(body: str) -> dict[str, int]:
    body = SCRIPT.sub(" ", STYLE.sub(" ", HEAD.sub(" ", body)))
    out = {"chart": 0, "table": 0, "card": 0, "other": 0}
    # blank out each bucket as it is counted, so the remainder is "other"
    def take(pattern, key, text):
        pieces = []
        for m in pattern.finditer(text):
            out[key] += words(m.group(0))
            pieces.append((m.start(), m.end()))
        for a, b in reversed(pieces):
            text = text[:a] + " " * (b - a) + text[b:]
        return text

    body = take(SVG, "chart", body)
    body = take(TABLE, "table", body)
    for a, b in reversed(card_spans(body)):
        out["card"] += words(body[a:b])
        body = body[:a] + " " * (b - a) + body[b:]
    out["other"] = words(body)
    out["prose"] = out["table"] + out["card"] + out["other"]
    out["all"] = out["prose"] + out["chart"]
    return out


d = sys.argv[1]
rows = {}
for n in sorted(os.listdir(d)):
    if not n.endswith(".html"):
        continue
    with open(os.path.join(d, n), encoding="utf-8") as fh:
        rows[n] = split(fh.read())

cols = ("table", "card", "other", "prose", "chart", "all")
print(f"{'page':30s}" + "".join(f"{c:>9s}" for c in cols))
for n, v in rows.items():
    print(f"{n:30s}" + "".join(f"{v[c]:>9,}" for c in cols))
tot = {c: sum(v[c] for v in rows.values()) for c in cols}
print(f"{'TOTAL':30s}" + "".join(f"{tot[c]:>9,}" for c in cols))
if len(sys.argv) > 2:
    with open(sys.argv[2], "w") as fh:
        json.dump({"pages": rows, "total": tot}, fh, indent=1, sort_keys=True)
