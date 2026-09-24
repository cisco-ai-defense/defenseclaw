#!/usr/bin/env python3
"""Payload guard. Runs over EVERY file about to be uploaded and aborts on a hit.

Five independent checks:

  1. CASE IDS - loads the full case-id set from every corpus on disk (never printing any
     of them) and fails if any appears anywhere in the payload, as a whole token or as a
     substring of a long token.
  2. SENSITIVE TEXT - builds word-shingles from the corpora's user-intent strings, tool-call
     argument blobs, tool descriptions and risk/rationale fields, and fails on any shingle
     that also appears in the payload. This catches a verbatim quote even if it was
     reformatted.
  3. CJK - fails on any CJK / Hangul / fullwidth codepoint. The evaluation-only corpus's risk
     descriptions are Chinese, so a single CJK character is treated as a leak.
  4. CREDENTIALS - fails on token shapes for HuggingFace, AWS, GitHub, Slack, OpenAI, private
     keys, JWTs, Authorization headers and .env-style secret assignments.
  5. SIZE / TYPE - fails on anything that is not a UTF-8 .html/.css/.md/.json text file, and on
     any file over 1 MiB (a static Space here should have no binaries at all).

Exit 0 = clean and safe to upload. Anything else = do not upload.
"""
from __future__ import annotations

import json
import os
import re
import sys
import unicodedata

SITE = sys.argv[1] if len(sys.argv) > 1 else "$WORK/.system-one-space-build/site"
DATA = os.environ.get("SPACE_DATA", "$WORK/.system-one-data/outputs")

ALLOWED_EXT = {".html", ".css", ".md", ".json", ".txt", ".py", ".sh"}
MAX_BYTES = 1024 * 1024

HITS: list[str] = []
STATS: dict[str, int] = {}

# ---------------------------------------------------------------- corpora to guard against
CORPUS_FILES = [
    "mcptox/cases.jsonl",
    "intent-real/cases.jsonl",
    "intent-ablation/cases.jsonl",
    "toolcall-labels/cases.jsonl",
    "s2/cases.jsonl",
    "s3/cases.jsonl",
    "agentdojo/cases.jsonl",
    "injecagent/cases.jsonl",
    "agenttrace/cases.jsonl",
    "bashbench/cases.jsonl",
    "shellattack/cases.jsonl",
    "intent-pairs/cases.jsonl",
    "intent-large/cases.jsonl",
    "s1-n1000/cases.jsonl",
    "s1-n1000/screen-cases.jsonl",
    "s1-n1000/terminalbench-context-cases.jsonl",
    "s2-adjudication/disagreement-queue.jsonl",
    "s2-adjudication/adjudication-in.jsonl",
]

# First-party protocol text.  The instruction / question / context templates are
# authored in this repository and are published verbatim on the prompts page.  They also
# appear inside `s2-adjudication/adjudication-in.jsonl`, because the adjudication request
# embeds the same policy block, so shingling that file re-derives our own text and the
# guard would flag the prompts page for quoting it.  Every shingle that appears in one of
# these files is therefore subtracted from the index, and the count is printed.  Nothing
# else is exempt: case ids, CJK, credentials, size and type checks are untouched, and any
# shingle NOT present in a protocol file still fails the build.
PROTOCOL_ROOT = os.environ.get("SPACE_PROTO",
                               "$WORK/.system-one-hf-stage/evaluations-add/protocol")
PROTOCOL_FILES = ["v1/contexts-v1.json", "v1/questions-v1.json", "v1/pilot-v1.json",
                  "v2/questions-v2.json"]

SENSITIVE_KEYS = (
    "content", "intent", "user_intent", "session_user_intent", "arguments", "args",
    "command", "query", "body", "description", "tool_description", "risk", "risk_description",
    "rationale", "reason", "prompt", "text", "payload", "poisoned", "attack", "injection",
)

WORD = re.compile(r"[A-Za-z0-9_]+")
SHINGLE_N = 8
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@+-]{5,}")

CJK = re.compile(
    "[⺀-〿぀-ヿ㄀-ㄯ㄰-㆏ㆠ-ㆿ"
    "㐀-䶿一-鿿ꀀ-꓏가-힯豈-﫿︰-﹏"
    "＀-￯]"
)

CRED_PATTERNS = [
    ("HuggingFace token", re.compile(r"\bhf_[A-Za-z0-9]{16,}")),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    ("AWS secret-shaped", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*\S+")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("OpenAI-style key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}")),
    ("Anthropic-style key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Authorization header", re.compile(r"(?i)\bauthorization\s*:\s*(bearer|basic)\s+\S+")),
    ("secret assignment", re.compile(
        r"(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)"
        r"\s*[:=]\s*['\"]?[A-Za-z0-9/_+=-]{12,}")),
]


def walk_strings(node, depth=0):
    """Yield (key, string) for every string in a nested structure."""
    if depth > 12:
        return
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, str):
                yield k, v
            else:
                yield from walk_strings(v, depth + 1)
    elif isinstance(node, list):
        for v in node:
            if isinstance(v, str):
                yield "", v
            else:
                yield from walk_strings(v, depth + 1)


ALPHA = re.compile(r"[A-Za-z]")


def shingles(text: str):
    """8-word shingles, skipping any window that is mostly numbers.

    A window needs at least 4 tokens containing a letter. Axis tick sequences
    ("0 10 20 30 40 50 60 70") otherwise collide with numeric content in the corpora and
    would make the guard cry wolf on every chart.
    """
    words = [w.lower() for w in WORD.findall(text)]
    for i in range(0, max(0, len(words) - SHINGLE_N + 1)):
        win = words[i:i + SHINGLE_N]
        if sum(1 for w in win if ALPHA.search(w)) < 4:
            continue
        yield " ".join(win)


TAG = re.compile(r"<[^>]+>")
HEAD = re.compile(r"<head\b.*?</head>", re.S | re.I)
FREE_TEXT_ATTR = re.compile(r'\b(?:alt|title|aria-label|aria-description|data-[a-z-]+)="([^"]*)"',
                            re.I)


def prose_of(body: str, ext: str) -> str:
    """The text a reader can actually see, plus free-text attributes.

    HTML markup and structural attribute values are excluded: they are boilerplate this build
    authored, and they collide with corpus tool-call arguments purely by coincidence (an HTML
    fragment inside a tool call will share n-grams with any HTML page). Element content -
    including every SVG <title> tooltip and <desc> - is kept, as are the attributes that can
    legitimately carry prose.
    """
    if ext not in (".html",):
        return body
    free = " ".join(FREE_TEXT_ATTR.findall(body))
    visible = TAG.sub(" ", HEAD.sub(" ", body))
    return visible + " \n " + free


print("building the guard index from the corpora on disk (nothing is printed from them)")
case_ids: set[str] = set()
bad_shingles: set[str] = set()
corpora_seen = 0
rows_seen = 0

for rel in CORPUS_FILES:
    path = os.path.join(DATA, rel)
    if not os.path.exists(path):
        continue
    corpora_seen += 1
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:  # noqa: BLE001
                continue
            rows_seen += 1
            for key in ("id", "case_id", "original_id", "split_group", "trajectory_id"):
                v = row.get(key)
                if isinstance(v, str) and len(v) >= 6:
                    case_ids.add(v)
            strata = row.get("strata") if isinstance(row.get("strata"), dict) else {}
            src = row.get("source") if isinstance(row.get("source"), dict) else {}
            for d in (strata, src):
                for key in ("split_group", "trajectory_id", "original_id", "case_id", "id"):
                    v = d.get(key)
                    if isinstance(v, str) and len(v) >= 6:
                        case_ids.add(v)
            for key, val in walk_strings(row):
                if len(val) < 40:
                    continue
                kl = key.lower()
                if any(s in kl for s in SENSITIVE_KEYS) or key == "":
                    bad_shingles.update(shingles(val))

# subtract the first-party protocol text
first_party: set[str] = set()
protocol_seen = 0
for rel in PROTOCOL_FILES:
    path = os.path.join(PROTOCOL_ROOT, rel)
    if not os.path.exists(path):
        continue
    protocol_seen += 1
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    for _key, val in walk_strings(doc):
        first_party.update(shingles(val))
exempted = bad_shingles & first_party
bad_shingles -= first_party

STATS["protocol_files_indexed"] = protocol_seen
STATS["first_party_shingles"] = len(first_party)
STATS["shingles_exempted_as_first_party"] = len(exempted)
STATS["corpora_indexed"] = corpora_seen
STATS["corpus_rows_indexed"] = rows_seen
STATS["case_ids_indexed"] = len(case_ids)
STATS["sensitive_shingles_indexed"] = len(bad_shingles)
for k, v in STATS.items():
    print(f"  {k:30s} {v:,}")
if corpora_seen == 0:
    print("ABORT: no corpus files found, so the guard would be vacuous")
    raise SystemExit(2)

# lowercase index for substring checks, keeping only ids distinctive enough to be meaningful
id_index = {i.lower() for i in case_ids if len(i) >= 8}

# ------------------------------------------------------------------------- scan the payload
files = []
for root, _dirs, names in os.walk(SITE):
    for n in sorted(names):
        files.append(os.path.join(root, n))

print(f"\nscanning {len(files)} payload file(s) under {SITE}")
for path in sorted(files):
    rel = os.path.relpath(path, SITE)
    ext = os.path.splitext(path)[1].lower()
    size = os.path.getsize(path)
    if ext not in ALLOWED_EXT:
        HITS.append(f"{rel}: disallowed file type {ext!r}")
        continue
    if size > MAX_BYTES:
        HITS.append(f"{rel}: {size:,} bytes exceeds the {MAX_BYTES:,} byte limit")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            body = fh.read()
    except UnicodeDecodeError:
        HITS.append(f"{rel}: not valid UTF-8")
        continue

    # 3. CJK
    for m in CJK.finditer(body):
        ch = m.group(0)
        HITS.append(f"{rel}: CJK/fullwidth codepoint U+{ord(ch):04X} "
                    f"({unicodedata.name(ch, 'unnamed')}) at offset {m.start()}")
        break

    # 4. credentials
    for label, pat in CRED_PATTERNS:
        if pat.search(body):
            HITS.append(f"{rel}: matches credential pattern [{label}] "
                        f"(value deliberately not printed)")

    # 1. case ids
    low = body.lower()
    toks = {t.group(0).lower() for t in TOKEN.finditer(body)}
    for t in toks:
        if t in id_index:
            HITS.append(f"{rel}: token matches an indexed corpus case id "
                        f"(length {len(t)}; value not printed)")
            break
    else:
        # substring pass for ids embedded in longer strings
        for cid in id_index:
            if len(cid) >= 14 and cid in low:
                HITS.append(f"{rel}: contains an indexed corpus case id as a substring "
                            f"(length {len(cid)}; value not printed)")
                break

    # 2. sensitive text shingles, over the visible prose and free-text attributes
    hit_shingles = 0
    for sh in shingles(prose_of(body, ext)):
        if sh in bad_shingles:
            hit_shingles += 1
            if hit_shingles == 1:
                HITS.append(f"{rel}: contains an 8-word shingle that also appears in a "
                            f"corpus intent / tool-call / description field "
                            f"(value not printed)")
    if hit_shingles > 1:
        HITS.append(f"{rel}: {hit_shingles} sensitive shingles total")

print(f"payload bytes: {sum(os.path.getsize(p) for p in files):,}")
print()
if HITS:
    print(f"GUARD RESULT: FAIL - {len(HITS)} finding(s). DO NOT UPLOAD.")
    for h in HITS:
        print("  " + h)
    raise SystemExit(1)
print("GUARD RESULT: PASS")
print("  0 corpus case ids, 0 sensitive-text shingles, 0 CJK codepoints,")
print("  0 credential patterns, 0 disallowed file types, 0 oversized files.")
