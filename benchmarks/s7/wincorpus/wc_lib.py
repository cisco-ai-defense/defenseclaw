# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0
"""Shared helpers for the Windows shell corpus builder (case-v1 rows, redaction, wrappers, validation). Stdlib only (jsonschema optional)."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re

REVISION = "rel-1-0-10-2026-11-13"
DATASET_BY_SRC = {
    "real-owner": ("Vineethsain/agent-transcripts", "internal", "manual"),
    "real-traces": ("trace-commons/agent-traces", "public-dataset", "download-only"),
    "real-stateful": ("Vineethsain/agent-transcripts", "internal", "manual"),
    "capture": ("defenseclaw-ledgers", "internal", "manual"),
    "gapreg": ("defenseclaw-ledgers", "internal", "manual"),
    "protwrite": ("defenseclaw-ledgers", "internal", "manual"),
    "fixture": ("defenseclaw-security-suite", "Apache-2.0", "vendored"),
    "variant": ("defenseclaw-security-suite", "Apache-2.0", "vendored"),
    "atomic": ("redcanaryco/atomic-red-team", "MIT", "download-only"),
    "authored": ("defenseclaw-wincorpus-authored", "internal", "manual"),
    "credpaths": ("defenseclaw-ledgers", "internal", "manual"),
}

# --- redaction -----------------------------------------------------------------------------------------------
_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_EMAIL = re.compile(r"\b[\w.+-]+@(?!example\.com)[\w-]+(?:\.[\w-]+)+\b")
_ACCT = re.compile(r"(?<![\w.:/-])\d{12}(?![\w.-])")
_SECRETS = [
    re.compile(r"\bhf_[A-Za-z0-9]{20,}\b"), re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}"), re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{32,}"), re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/\-]{24,}=*"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.S),
]
_ASSIGN = re.compile(r"(?i)\b((?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|refresh[_-]?token|session[_-]?token|token)\s*[=:]\s*['\"]?)([A-Za-z0-9_\-+/=.]{16,})")
_UPN = re.compile(r"\b[\w.-]+@[\w-]+\.(?:onmicrosoft|local|corp|internal|lan)(?:\.[\w-]+)*\b", re.I)
# lab identities: test-host aliases, test accounts under C:\Users, domain\user pairs, personal account names
_HOST = re.compile(r"\bdc-(?:[a-z0-9]+-)*?(?:win|ewin|rhel|mac|ubuntu|ent|float)[a-z0-9-]*\b", re.I)
_USERDIR = re.compile(r"(?i)([A-Za-z]:[\\/]+Users[\\/]+)(?!alice\b|Public\b|Default\b|All Users\b)([^\\/\s\"';:*?<>|]+)")
_DOMUSER = re.compile(r"\b(?!NT\b|BUILTIN\b|WORKGROUP\b)[A-Z][A-Z0-9-]{2,14}\\(?!Users\b|Windows\b|Program\b|ProgramData\b|Public\b)[a-z][a-z0-9._-]{2,20}\b")
_INSTID = re.compile(r"\bi-[0-9a-f]{17}\b")
_PERSON = re.compile(r"(?i)\b(?:vnarajal|vineethsai|vineeth)\b")
_ipmap: dict[str, str] = {}


def _ip(m: re.Match) -> str:
    s = m.group(0)
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return s
    if a.is_loopback or s.startswith("0.") or s == "255.255.255.255" or s.startswith("192.0.2.") or s.startswith("198.51.100."):
        return s
    if s not in _ipmap:
        _ipmap[s] = "198.51.100.%d" % (len(_ipmap) % 250 + 1)
    return _ipmap[s]


def redact(t: str) -> str:
    if not t:
        return t
    for rx in _SECRETS:
        t = rx.sub("REDACTED_SECRET", t)
    t = _ASSIGN.sub(lambda m: m.group(1) + "REDACTED_SECRET", t)
    t = _UPN.sub("user@example.com", t)
    t = _EMAIL.sub("user@example.com", t)
    t = _ACCT.sub("000000000000", t)
    t = _HOST.sub("labhost", t)
    t = _USERDIR.sub(lambda m: m.group(1) + "alice", t)
    t = _PERSON.sub("alice", t)
    t = _INSTID.sub("i-0123456789abcdef0", t)
    return _IP.sub(_ip, t)


def redact_obj(o):
    if isinstance(o, str):
        return redact(o)
    if isinstance(o, list):
        return [redact_obj(x) for x in o]
    if isinstance(o, dict):
        return {k: redact_obj(v) for k, v in o.items()}
    return o


LEAK_PATTERNS = {
    "ip": _IP, "email": re.compile(r"\b(?!git@)[\w.+-]+@(?!example\.com)[\w-]+(?:\.[\w-]+)+\b"), "labhost": re.compile(r"\bdc-(?:[a-z0-9]+-)*?(?:win|ewin|rhel|mac|ubuntu|ent|float)[a-z0-9-]*\b", re.I),
    "userdir": _USERDIR, "person": _PERSON, "secret": re.compile("|".join(r.pattern for r in _SECRETS[:9])),
}


def leak_scan(text: str) -> list[str]:
    hits = []
    for name, rx in LEAK_PATTERNS.items():
        for m in rx.finditer(text):
            s = m.group(0)
            if name == "ip":
                try:
                    a = ipaddress.ip_address(s)
                except ValueError:
                    continue
                if a.is_loopback or s.startswith(("0.", "192.0.2.", "198.51.100.")) or s == "255.255.255.255":
                    continue
            hits.append(name)
            break
    return hits


def sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()


# --- case-v1 rows --------------------------------------------------------------------------------------------
# provider -> (tool name for a PowerShell shell call, dialect). The harness (-connector auto) maps the provider to its hook handler and
# builds that connector's native shell payload from tool_name/dialect.
# The harness (-connector auto) turns the generic tool name (Bash / PowerShell) into the connector's native shell tool (Kiro: execute_bash / execute_pwsh); a corpus
# row that already carries execute_pwsh is not recognised as a shell tool by the harness and reaches the hook as an unknown MCP call.
SHELL_TOOL = {"claudecode": "PowerShell", "codex": "Bash", "cursor": "Shell", "opencode": "bash", "kiro": "PowerShell"}
PROVIDERS = ["claudecode", "codex", "cursor", "opencode", "kiro"]


def mkcase(cid: str, src: str, original_id: str, tool: str, args: dict, command: str | None, dialect: str, provider: str, *, truth: str,
           cats: list[str], label_source: str, conf: str = "high", disp: str | None = None, actions: dict | None = None,
           rule_ids: list[str] | None = None, cwd: str = "C:\\Users\\alice\\proj", campaign: str = "windows-shell", hard_neg: bool = False,
           applicability: str = "in_scope", exclusion: str = "", platform: str = "windows", domain: str = "windows-shell") -> dict:
    ds, lic, red = DATASET_BY_SRC[src]
    payload: dict = {"tool_name": tool, "args": args, "dialect": dialect, "direction": "tool_call", "cwd": cwd}
    if command is not None:
        payload["command"] = command
    benign = truth in ("benign", "unknown")
    t: dict = {"applicability": applicability, "categories": sorted(set(cats)), "label_confidence": conf, "label_source": label_source, "source_truth": truth}
    if truth == "benign":
        t.update(deterministic_truth="benign", expected_disposition="allow")
    elif truth == "malicious":
        t.update(deterministic_truth="deterministic_malicious", expected_disposition=disp or "block")
    else:
        t.update(expected_disposition="allow")
    if applicability == "out_of_scope":
        t["exclusion_reason"] = exclusion or "excluded"
    if actions:
        t["expected_profile_actions"] = actions
    if rule_ids:
        t["rule_ids"] = sorted(set(rule_ids))
    del benign
    h = sha(cid)
    return {
        "id": cid, "payload": payload, "schema_version": "1",
        "source": {"dataset": ds, "license": lic, "original_id": original_id[:240], "redistribution": red, "revision": REVISION},
        "split": "test",
        "strata": {"call_index": 0, "campaign": campaign, "dialect": dialect, "domain": domain, "ecosystem": "coding_agent", "hard_negative": hard_neg,
                   "platform": platform, "provider": provider, "sequence_index": 0, "split_group": h[:24], "trajectory_id": h[:32]},
        "surface": "action", "truth": t,
    }


def shell_case(cid, src, original_id, cmd, *, provider="claudecode", dialect="powershell", **kw) -> dict:
    """A shell call in the connector's native Windows shell tool. dialect posix = Git Bash (tool Bash)."""
    if dialect == "posix":
        tool = {"claudecode": "Bash", "codex": "Bash", "cursor": "Shell", "opencode": "bash", "kiro": "Bash"}[provider]
    elif dialect == "cmd":
        tool = {"claudecode": "Bash", "codex": "Bash", "cursor": "Shell", "opencode": "bash", "kiro": "Bash"}[provider]
    else:
        tool = SHELL_TOOL[provider]
    args = {"cmd": cmd} if provider == "amp" else {"command": cmd}
    return mkcase(cid, src, original_id, tool, args, cmd, dialect, provider, **kw)


def profile_actions(sev: str, strict_only: bool = False) -> dict:
    """Expected action per pack from the documented severity posture (strict blocks MEDIUM+, default blocks CRITICAL and alerts MEDIUM+,
    permissive blocks CRITICAL and alerts HIGH+). strict_only rules (CMD-WIN-RM-FORCE...) are expected silent in default and permissive."""
    s = sev.upper()
    if s == "CRITICAL":
        return {"default": "block", "permissive": "block", "strict": "block"}
    if strict_only:
        return {"default": "allow", "permissive": "allow", "strict": "block" if s in ("HIGH", "MEDIUM") else "alert"}
    if s == "HIGH":
        return {"default": "alert", "permissive": "alert", "strict": "block"}
    if s == "MEDIUM":
        return {"default": "alert", "permissive": "allow", "strict": "block"}
    return {"default": "alert", "permissive": "allow", "strict": "alert"}


# --- equivalence-preserving wrappers (the labels carry over: same action, other spelling) ---------------------
def w_ps_command(cmd: str) -> str:
    return 'powershell -NoProfile -Command "' + cmd.replace('"', '\\"') + '"'


def w_pwsh_c(cmd: str) -> str:
    return "pwsh -NoProfile -c '" + cmd.replace("'", "''") + "'"


def w_cmd_c(cmd: str) -> str:
    return 'cmd /c "' + cmd.replace('"', "'") + '"' if '"' in cmd else "cmd /c " + cmd


def w_cd(cmd: str) -> str:
    return "Set-Location C:\\Users\\alice\\proj; " + cmd


def w_call(cmd: str) -> str:
    return "& { " + cmd + " }"


def w_tail(cmd: str) -> str:
    return cmd + " ; Write-Output done"


def w_gitbash_ps(cmd: str) -> str:
    return "powershell.exe -NoProfile -Command '" + cmd.replace("'", "'\\''") + "'"


def looks_posh(cmd: str) -> bool:
    return bool(re.search(r"\$|\b[A-Za-z]+-[A-Za-z]+\b|\|", cmd))


# --- validation ------------------------------------------------------------------------------------------------
def load_validator(schema_path: str):
    try:
        import jsonschema
    except ImportError:
        return None
    with open(schema_path) as f:
        sch = json.load(f)
    return jsonschema.Draft202012Validator(sch)


def validate_rows(rows, schema_path: str) -> list[str]:
    v = load_validator(schema_path)
    errs: list[str] = []
    seen: set[str] = set()
    for r in rows:
        if r["id"] in seen:
            errs.append("duplicate id " + r["id"])
        seen.add(r["id"])
        if v is not None:
            for e in v.iter_errors(r):
                errs.append(f"{r['id']}: {e.message[:120]}")
    return errs
