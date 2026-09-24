#!/usr/bin/env python3
"""Credential scan for anything staged for publication (git or HuggingFace).

The hard part is not finding credentials. It is *not* firing on the things that
legitimately look like credentials in this programme's artifacts:

  - sha256 digests everywhere (`prediction_sha256`, `context_sha256`,
    `request_sha256`, `cases_sha256`) - 64 hex chars, maximal entropy
  - git/HF revisions - 40 hex chars
  - case ids, run ids, base64-ish model revision strings
  - an adversarial security corpus that contains secret-SHAPED strings on
    purpose, because detecting them is the benchmark

So every rule here is anchored on a credential-specific *prefix or context*
(`hf_`, `AKIA`, `-----BEGIN ... PRIVATE KEY-----`, an `Authorization:` header,
an assignment to a password/secret/token name). Bare high-entropy strings are
deliberately NOT a rule - that is what makes the negative control pass.

Usage:
    scan_credentials.py PATH [PATH ...]      # scan
    scan_credentials.py --selftest           # run both controls, exit 1 on failure

Exit codes: 0 clean, 1 findings (or selftest failure), 2 usage error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Fields whose values are digests/ids by construction. Values under these keys
# are never treated as secrets, which is what keeps sha256 digests quiet.
DIGEST_KEYS = {
    "prediction_sha256", "context_sha256", "request_sha256", "cases_sha256",
    "run_plan_sha256", "sha256", "revision", "model_revision", "repo_revision",
    "case_id", "run_id", "id", "commit", "sha", "digest", "checksum",
}

RULES: list[tuple[str, re.Pattern[str]]] = [
    # HuggingFace user access tokens.
    ("hf_token", re.compile(r"\bhf_[A-Za-z0-9]{32,}\b")),
    # HuggingFace fine-grained / org tokens.
    ("hf_token_finegrained", re.compile(r"\bhf_oauth_[A-Za-z0-9_\-]{20,}\b")),
    # AWS access key id + secret in context.
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws_secret_access_key", re.compile(
        r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?")),
    # PEM private keys of any flavour.
    ("private_key_pem", re.compile(
        r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----")),
    # Authorization headers carrying a real-looking credential.
    ("authorization_header", re.compile(
        r"(?i)\bauthorization\s*[:=]\s*['\"]?(?:bearer|basic|token)\s+[A-Za-z0-9._\-/+=]{16,}")),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{24,}\b")),
    # Common provider key shapes.
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{32,}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{22,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b")),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    # JWTs (three base64url segments).
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    # Secret-ish assignment. The value is captured in group 1 and then checked
    # against PLACEHOLDER_VALUES in code - doing the exclusion as a regex
    # lookahead is how this rule silently broke once (a zero-width `\s*` branch
    # made the negative lookahead always succeed, so the rule never fired).
    ("secret_assignment", re.compile(
        r"(?i)\b(?:password|passwd|secret|api_key|apikey|access_token|auth_token|"
        r"client_secret|private_token)\b\s*[:=]\s*"
        r"['\"]([^'\"\s]{8,})['\"]")),
    # Raw provider rationale leakage guard: a private reasoning field with prose.
    ("provider_rationale", re.compile(
        r"(?i)\"(?:reasoning_content|thinking|rationale_raw|raw_rationale|"
        r"provider_rationale|chain_of_thought)\"\s*:\s*\"[^\"]{40,}")),
]

SKIP_SUFFIXES = {".pt", ".bin", ".safetensors", ".gguf", ".onnx", ".pyc", ".so",
                 ".tgz", ".tar", ".gz", ".zip", ".png", ".jpg", ".jpeg", ".pdf"}

# Values that mean "no secret here". An adversarial corpus is full of these:
# prompts and tool arguments that reference credentials without carrying one.
PLACEHOLDER_RX = re.compile(
    r"(?i)\A(?:x{3,}|\*{3,}|\.{3,}|-{3,}|<[^>]*>|\$\{[^}]*\}|\$[A-Z_]+|"
    r"\{\{[^}]*\}\}|%[A-Za-z_]+%|None|null|nil|true|false|empty|"
    r"REDACTED|SCRUBBED|MASKED|OMITTED|CHANGEME|placeholder|example|"
    r"examplekey|test|testing|dummy|fake|sample|secret|password|"
    r"your[_-]?(?:api[_-]?)?key(?:[_-]?here)?|insert[_-].*|todo)\Z")


def is_placeholder(value: str) -> bool:
    return bool(PLACEHOLDER_RX.match(value.strip()))


def redact(s: str) -> str:
    """Never echo a live secret; show only shape."""
    if len(s) <= 10:
        return s[:2] + "*" * (len(s) - 2)
    return f"{s[:6]}...{s[-2:]} (len {len(s)})"


def digest_valued_spans(line: str) -> list[tuple[int, int]]:
    """Spans of `"key": "value"` where key is a known digest/id field."""
    spans = []
    for m in re.finditer(r'"([A-Za-z0-9_]+)"\s*:\s*"([^"]*)"', line):
        if m.group(1) in DIGEST_KEYS:
            spans.append(m.span(2))
    return spans


def scan_text(text: str, path: str) -> list[dict]:
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 200_000:
            line = line[:200_000]
        safe = digest_valued_spans(line)
        for name, rx in RULES:
            for m in rx.finditer(line):
                s, e = m.span()
                if any(s >= a and e <= b for a, b in safe):
                    continue  # inside a declared digest/id field
                if name == "secret_assignment" and is_placeholder(m.group(1)):
                    continue  # templated/redacted value, not a live credential
                findings.append({
                    "path": path, "line": lineno, "rule": name,
                    "match": redact(m.group(0)),
                })
    return findings


def scan_path(p: Path) -> list[dict]:
    if p.suffix.lower() in SKIP_SUFFIXES:
        return []
    try:
        text = p.read_text(errors="replace")
    except (OSError, UnicodeError):
        return []
    return scan_text(text, str(p))


# The HF-token fixture is assembled at runtime rather than written as a literal.
# A real-shaped token literal in a tracked file trips GitHub push protection, and
# the control needs the SHAPE, not a specific value. Prefix plus 34 chars matches
# the pattern the scanner keys on.
_HF_SHAPE = "hf_" + ("Zq7" * 12)[:34]

POSITIVE_CONTROL = """
# POSITIVE CONTROL - every line below must be caught.
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
Authorization: Bearer ya29.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789
-----BEGIN RSA PRIVATE KEY-----
openai = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
gh = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz01234"
jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
password = "hunter2correcthorse"
{"reasoning_content": "The user is asking me to exfiltrate the database, so I should consider whether"}
""" + 'hf_token = "' + _HF_SHAPE + '"\n'

# Things that legitimately appear in this programme's artifacts and in an
# adversarial security corpus. None of these may fire.
NEGATIVE_CONTROL = """
# NEGATIVE CONTROL - none of these may be flagged.
{"prediction_sha256": "c3f8a277bdbd3865eaa4a44f8d8667af1b8b7b9b85642669f32ab9e08a392ff5"}
{"context_sha256": "ff729f284dd7542690e78c0e169c346bd25e8cc1f24d81e164cfedc25307401f"}
{"request_sha256": "bedd79fa0cebf4e134dcbafcc9caef89aac755b1057b598332bc29a8417ab94e"}
{"cases_sha256": "39f2c1df2369952a0525cc4c5575f4bdb590fb3ca8c1bc6805cf4f376c1adbf7"}
{"model_revision": "93ec5d6ff1a9cd31d6cc0e0c58d312465d36de7c"}
{"revision": "8949b909ec900327062f0ebf497f51aef5e6f0c8"}
{"case_id": "dtap-agent-trajectories/2d5a97f46d9e11e01c7834f6"}
{"run_id": "s2-kev-9b-h200", "route": "system_one", "action": "allow"}
# Adversarial corpus content: secret-SHAPED strings that are the benchmark itself.
# Redacted / templated credentials in prompts and tool arguments:
token = "REDACTED"
api_key = "<YOUR_API_KEY>"
password = "${DB_PASSWORD}"
secret = "xxxxxxxxxxxx"
AWS_SECRET = "***"
# High-entropy but non-credential identifiers:
case = "mcphunt/9f2e1a7c4b8d3e6f0a1b2c3d4e5f6a7b"
nonce = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
uuid = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
"""


def selftest() -> int:
    ok = True
    pos = scan_text(POSITIVE_CONTROL, "<positive-control>")
    pos_rules = sorted({f["rule"] for f in pos})
    expected = {
        "hf_token", "aws_access_key_id", "aws_secret_access_key",
        "authorization_header", "private_key_pem", "openai_key",
        "github_token", "jwt", "secret_assignment", "provider_rationale",
    }
    missing = sorted(expected - set(pos_rules))
    print(f"positive control: {len(pos)} findings, rules fired = {pos_rules}")
    if missing:
        print(f"  FAIL - these rules did not fire: {missing}")
        ok = False
    else:
        print("  PASS - scanner fires on every seeded credential class")

    neg = scan_text(NEGATIVE_CONTROL, "<negative-control>")
    print(f"negative control: {len(neg)} findings")
    if neg:
        print("  FAIL - flagged legitimate digest/adversarial-corpus strings:")
        for f in neg:
            print(f"    line {f['line']} rule={f['rule']} match={f['match']}")
        ok = False
    else:
        print("  PASS - no false positive on sha256 digests, revisions, case ids,")
        print("         or the redacted/templated secret-shaped strings that")
        print("         legitimately appear in an adversarial corpus")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--json", dest="as_json", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        return selftest()
    if not a.paths:
        ap.error("need at least one PATH or --selftest")

    findings, nfiles = [], 0
    for root in a.paths:
        rp = Path(root)
        files = [rp] if rp.is_file() else [q for q in rp.rglob("*") if q.is_file()]
        for q in files:
            if "/.git/" in str(q) or "__pycache__" in str(q):
                continue
            nfiles += 1
            findings.extend(scan_path(q))

    if a.as_json:
        print(json.dumps({"files_scanned": nfiles, "findings": findings}, indent=2))
    else:
        print(f"scanned {nfiles} files")
        if not findings:
            print("CLEAN - 0 findings")
        else:
            print(f"{len(findings)} FINDINGS:")
            for f in findings:
                print(f"  {f['path']}:{f['line']} rule={f['rule']} match={f['match']}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
