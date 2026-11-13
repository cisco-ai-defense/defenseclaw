# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E501  (regex and data tables read better on one line; the checked-in corpus tooling has always been long-line)
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
# Redaction is by CATEGORY, with stable numbered placeholders (first seen = 1, the same real value always gets the same placeholder within a build):
#   Windows computer names (EC2AMAZ-*, WIN-*, UNC / -ComputerName / machine-account NetBIOS names) -> LABPC<n>
#   other host names (dc-* test aliases, ip-* and ec2-* EC2 names, private-TLD hosts)             -> labhost<n>
#   AD / DNS domain (private-TLD suffix of a host, UPN suffix) -> labdomain<n>.example.com;  NetBIOS domain -> LABDOM<n>
#   user names (DOMAIN\user, UPN, /user: and -User flags, the owner's names) -> labuser<n>; home-path users -> alice
#   SIDs (S-1-5-21-a-b-c[-rid]) -> S-1-5-21-<fixed>-<fixed>-<n>[-rid];  IPv4 -> 198.51.100.<n>;  IPv6 -> 2001:db8::<n>;  MAC -> 00:00:5E:00:53:<n>
#   AWS instance and resource ids, 12-digit account ids, secrets, emails.
# Placeholders are bare tokens (no angle brackets): < and > are shell redirection operators and would change how a command parses.
# Real lab values (an arbitrary NetBIOS name, the owner's names, host aliases) are NEVER written in this repo: they come from a denylist file kept
# outside git (load_denylist, mkdenylist.py). The build requires it; tests use synthetic values only.
_IP = re.compile(r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\w|\.\d)")
_IP6 = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:%[\w.]+)?(?![\w:])")
_MAC = re.compile(r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}([:-])){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])")
_EMAIL = re.compile(r"\b[\w.+-]+@(?!(?:[\w-]+\.)*example\.com\b)[\w-]+(?:\.[\w-]+)+\b")
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
# computer names
_EC2WIN = re.compile(r"\b(?:(?i:EC2AMAZ-[a-z0-9]+)|WIN-[A-Z0-9]{11})\b(?P<sfx>(?:\.[A-Za-z0-9-]+)+)?")
_EC2DNS = re.compile(r"\b(?:ip-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}|ec2-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3})(?:\.[a-z0-9-]+)*(?:\.compute[a-z0-9-]*\.(?:internal|amazonaws\.com)|\.ec2\.internal|\.internal)\b", re.I)
_UNC = re.compile(r"(?<![\w$\\:])(\\\\)(?!\.[\\/]|\?[\\/]|wsl\$|wsl\.localhost|localhost\b|[*$]|(?i:users|windows|program|programdata|temp|tmp|system32|device|globalroot|pipe)\b|\d+\.\d+\.\d+\.\d+\\)([A-Za-z0-9][A-Za-z0-9_-]{1,62})(?=\\)")
_COMPFLAG = re.compile(r"(?i)((?:-(?:ComputerName|Computer|CN|Server|DomainController|PSComputerName)(?:\s+|:|=)|\b(?:schtasks|tasklist|taskkill|systeminfo|shutdown|wmic)\b[^\n|;&]{0,80}?\s/(?:s\s+|node:))['\"]?)([A-Za-z][A-Za-z0-9_-]{1,14})(?![\w.$\\(-])")
# domains
_PRIVFQDN = re.compile(r"(?<![\w.@-])(?:(?<!/)|(?<=//))((?:[a-z0-9][a-z0-9-]*\.)+(?:local|corp|internal|lan|intranet|localdomain|home\.arpa))(?![\w-])(?!\()(?!\.(?:json|ya?ml|toml|env|js|ts|py|md|txt|cfg|conf|ini|log|bak|example)\b)", re.I)
_PRIVSKIP = re.compile(r"(?i)^(?:settings|appsettings|env|config|secrets|application|docker-compose|compose|launchSettings|\.env)\.local$")
_UPN = re.compile(r"\b([\w.-]+)@((?:[\w-]+\.)*[\w-]+\.(?:onmicrosoft\.com|local|corp|internal|lan|intranet|localdomain))\b", re.I)
# users
_IDCTX = re.compile(r"(?i)((?:/user:|/ru\s+|/u\s+|-user(?:name)?(?:\s+|:|=)|-credential\s+|-samaccountname\s+|-runasuser\s+|-owner\s+|-principal\s+|/(?:grant|deny|remove|setowner)(?::r)?\s+)['\"]?)([A-Za-z][\w.-]{1,30})\\{1,2}([A-Za-z0-9][\w.$-]{0,40})")
_SYSDOM = {"NT", "BUILTIN", "WORKGROUP", "NTAUTHORITY", "NTSERVICE", "NTVIRTUALMACHINE", "WINDOWSMANAGER", "FONTDRIVER", "FONT", "IIS", "APPPOOL", "MICROSOFT",
           "HKLM", "HKCU", "HKCR", "HKU", "HKCC", "HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER", "HKEY_CLASSES_ROOT", "HKEY_USERS", "SOFTWARE", "SYSTEM", "SAM", "SECURITY", "HARDWARE",
           "TEMP", "TMP", "APPDATA", "LOCALAPPDATA", "PROGRAMFILES", "PROGRAMDATA", "SYSTEMROOT", "WINDIR", "USERPROFILE", "HOMEPATH", "PUBLIC", "ALLUSERSPROFILE", "CURRENTCONTROLSET",
           "CONTROLSET001", "MACHINE", "USER", "USERS", "SERVICES", "WINDOWS", "DRIVERS", "CONFIG", "SYSTEM32", "SYSWOW64", "ROOT", "ACL", "ACE", "NTUSER", "CLASSES", "POLICIES",
           "ENV", "APP", "SYS", "LOCAL", "DOS", "DEVICE", "GLOBALROOT", "STORAGE", "SHARE", "VOLUME", "HOME", "DATA", "BIN", "LIB", "SRC", "TESTS", "TEST", "BUILD", "SCRIPTS", "PROFILE", "AUTHORITY", "SERVICE"}
_DOMUSER = re.compile(r"(?<![\w\\./$:-])([A-Z][A-Z0-9-]{2,14})(\\{1,2})([a-z][a-z0-9._-]{2,20})\b(?![\\/:(])")
_USERDIR = re.compile(r"(?i)((?:[A-Za-z]:|/[a-z]|/mnt/[a-z])?[\\/]+Users[\\/]+)(?!alice\b|Public\b|Default\b|All Users\b)([^\\/\s\"';:*?<>|]+)")
_USERDIR_BARE = re.compile(r"(?i)(?<![\w\\/.:-])(Users[\\/]+)(?!alice\b|Public\b|Default\b|All Users\b)([^\\/\s\"';:*?<>|]+)")
_HOMEDIR = re.compile(r"(?<![\w.-])(/(?:home|usr/home)/)(?!alice\b|user\b|username\b|runner\b|[%$*{(\[<~.])([A-Za-z0-9._-]+)")
# hosts / ids
_HOST = re.compile(r"\bdc-(?:[a-z0-9]+-)*?(?:win|ewin|rhel|mac|ubuntu|ent|float)[a-z0-9-]*\b", re.I)
_INSTID = re.compile(r"\bi-[0-9a-f]{8}(?:[0-9a-f]{9})?\b")
_AWSRES = re.compile(r"\b(sg|vpc|subnet|eni|vol|ami|snap|eipalloc)-(?=[0-9a-f]*\d)([0-9a-f]{8}(?:[0-9a-f]{9})?)\b")
_SID = re.compile(r"\bS-1-5-21-(\d+)-(\d+)-(\d+)((?:-\d+)?)")

_KEEP_V4 = ("0.", "127.", "192.0.2.", "198.51.100.", "203.0.113.", "255.")
# Keep-list: cloud metadata endpoints and cluster-internal names are the TARGET of real attacks (credential theft from IMDS, SSRF to the Kubernetes API) and are public,
# fixed values. Rewriting them would erase the attack text, so redact() and the leak scan leave them alone.
_KEEP_NETS = tuple(ipaddress.ip_network(n) for n in ("169.254.0.0/16", "100.100.100.200/32", "168.63.129.16/32", "fd00:ec2::/32", "fd00:ec2::254/128"))
_KEEP_NAME = re.compile(r"(?i)^(?:metadata(?:\.google\.internal)?|instance-data(?:\.ec2\.internal)?|metadata\.goog|kubernetes\.default(?:\.svc)?(?:\.cluster\.local)?|"
                        r"(?:[a-z0-9-]+\.)*(?:cluster\.local|docker\.internal))$")


def _keep_ip(a) -> bool:
    return any(a in n for n in _KEEP_NETS if n.version == a.version)
_maps: dict[str, dict] = {}
_deny: list = []   # [(compiled regex, {lowercased value -> category})]


def reset() -> None:
    """Forget every placeholder assignment (tests, or a fresh build)."""
    _maps.clear()


def _n(kind: str, key: str) -> int:
    m = _maps.setdefault(kind, {})
    k = key.lower()
    if k not in m:
        m[k] = len(m) + 1
    return m[k]


def _is_ph(s: str, rx: str) -> bool:
    return re.fullmatch(rx, s, re.I) is not None


def _pc(v: str) -> str:
    return v if _is_ph(v, r"labpc\d+") else f"LABPC{_n('pc', v)}"


def _host(v: str) -> str:
    return v if _is_ph(v, r"labhost\d+") else f"labhost{_n('host', v)}"


def _domlabel(v: str) -> str:
    return v.split(".")[0]


def _dns(v: str) -> str:
    if _is_ph(v, r"labdomain\d+\.example\.com"):
        return v
    return f"labdomain{_n('dom', _domlabel(v))}.example.com"


def _nb(v: str) -> str:
    return v if _is_ph(v, r"labdom\d+") else f"LABDOM{_n('dom', v)}"


_KEEPUSER = {"administrator", "administrators", "guest", "system", "krbtgt", "defaultaccount", "wdagutilityaccount", "admin", "root", "everyone", "users", "domain admins", "domain users"}


def _user(v: str) -> str:
    if v.lower() in _KEEPUSER:
        return v
    return v if _is_ph(v, r"labuser\d+|alice") else f"labuser{_n('user', v)}"


def _sid(m: re.Match) -> str:
    key = "-".join(m.group(i) for i in (1, 2, 3))
    if (m.group(1), m.group(2)) == ("1000000000", "2000000000"):
        return m.group(0)
    return f"S-1-5-21-1000000000-2000000000-{3000000000 + _n('sid', key)}{m.group(4)}"


def _ip(m: re.Match) -> str:
    s = m.group(0)
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return s
    if a.is_loopback or s.startswith(_KEEP_V4) or _keep_ip(a):
        return s
    return f"198.51.100.{_n('ip4', s) % 250 + 1}"


def _ip6(m: re.Match) -> str:
    s = m.group(0)
    try:
        a = ipaddress.ip_address(s.split("%")[0])
    except ValueError:
        return s
    if a.version != 6 or a.is_loopback or a.is_unspecified or a in ipaddress.ip_network("2001:db8::/32") or _keep_ip(a):
        return s
    return f"2001:db8::{_n('ip6', s):x}"


def _mac(m: re.Match) -> str:
    s = m.group(0)
    sep = m.group(1)
    low = s.lower().replace("-", ":")
    if low in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") or low.startswith("00:00:5e:00:53:"):
        return s
    out = f"00:00:5E:00:53:{_n('mac', low) % 256:02X}"
    return out.replace(":", sep)


def _awsres(m: re.Match) -> str:
    return m.group(1) + ("-0123456789abcdef0" if len(m.group(2)) == 17 else "-01234567")


def _ec2win(m: re.Match) -> str:
    sfx = m.group("sfx")
    name = _pc(m.group(0)[: m.end() - m.start() - len(sfx or "")])
    if sfx:
        return name + "." + _dns(sfx[1:])
    return name


def _privfqdn(m: re.Match) -> str:
    v = m.group(1)
    if _PRIVSKIP.match(v) or _KEEP_NAME.match(v) or v.lower().endswith(".example.com"):
        return m.group(0)
    # a short host label in front of the domain is a host: name.domain.tld
    parts = v.split(".")
    if len(parts) >= 3:
        return _host(parts[0]) + "." + _dns(".".join(parts[1:]))
    return _dns(v)


def _upn(m: re.Match) -> str:
    return _user(m.group(1)) + "@" + _dns(m.group(2))


def _unc(m: re.Match) -> str:
    return m.group(1) + _pc(m.group(2))


def _compflag(m: re.Match) -> str:
    v = m.group(2)
    if v.lower() in ("localhost", "local", "none", "null") or v.startswith("$"):
        return m.group(0)
    return m.group(1) + _pc(v)


def _idctx(m: re.Match) -> str:
    dom, user = m.group(2), m.group(3)
    if dom.upper().replace(" ", "") in _SYSDOM or _is_ph(dom, r"labdom\d+|labpc\d+"):
        return m.group(0)
    sep = "\\\\" if "\\\\" in m.group(0)[len(m.group(1)):] else "\\"
    return m.group(1) + _nb(dom.upper() if dom.isupper() else dom) + sep + _user(user)


def _domuser(m: re.Match) -> str:
    if m.group(1) in _SYSDOM or _is_ph(m.group(1), r"labdom\d+|labpc\d+"):
        return m.group(0)
    return _nb(m.group(1)) + m.group(2) + _user(m.group(3))


def load_denylist(path: str) -> int:
    """Load the real-values denylist (jsonl {cat, v}); kept outside git. Replaces each value, case-insensitively, whatever the escaping of backslashes."""
    global _deny
    ents: dict[str, str] = {}
    with open(path) as f:
        for line in f:
            if line.strip():
                r = json.loads(line)
                ents[r["v"].lower()] = r["cat"]
    _deny = []
    if ents:
        vals = sorted(ents, key=len, reverse=True)
        rx = re.compile(r"(?<![A-Za-z0-9])(?:" + "|".join(re.escape(v).replace("\\\\", r"\\+") for v in vals) + r")(?![A-Za-z0-9])", re.I)
        _deny.append((rx, ents))
    return len(ents)


def _deny_sub(m: re.Match, ents: dict) -> str:
    raw = m.group(0)
    v = re.sub(r"\\+", r"\\", raw).lower()
    cat = ents.get(v) or ents.get(raw.lower(), "host")
    if cat == "computername":
        return _pc(raw)
    if cat in ("hostalias", "sshalias", "sshhost", "labfqdn", "host"):
        return _host(raw)
    if cat == "labdomain":
        return _dns(raw)
    if cat == "netbios":
        return _nb(raw)
    if cat == "domuser":
        d, _, u = raw.replace("\\\\", "\\").partition("\\")
        return _nb(d) + "\\" + _user(u)
    if cat == "upn":
        u, _, d = raw.partition("@")
        return _user(u) + "@" + _dns(d)
    if cat == "labuser":
        return _user(raw)
    if cat == "person":
        return "alice"
    if cat == "ip":
        return f"198.51.100.{_n('ip4', raw) % 250 + 1}"
    if cat == "account":
        return "000000000000"
    if cat == "instance":
        return "i-0123456789abcdef0"
    if cat == "sid":
        mm = _SID.match(raw)
        return _sid(mm) if mm else raw
    return _host(raw)


def redact(t: str) -> str:
    if not t:
        return t
    for rx in _SECRETS:
        t = rx.sub("REDACTED_SECRET", t)
    t = _ASSIGN.sub(lambda m: m.group(1) + "REDACTED_SECRET", t)
    for rx, ents in _deny:
        t = rx.sub(lambda m, e=ents: _deny_sub(m, e), t)
    t = _SID.sub(_sid, t)
    t = _EC2WIN.sub(_ec2win, t)
    t = _EC2DNS.sub(lambda m: _host(m.group(0)), t)
    t = _UPN.sub(_upn, t)
    t = _EMAIL.sub("user@example.com", t)
    t = _IDCTX.sub(_idctx, t)
    t = _DOMUSER.sub(_domuser, t)
    t = _UNC.sub(_unc, t)
    t = _COMPFLAG.sub(_compflag, t)
    t = _PRIVFQDN.sub(_privfqdn, t)
    t = _HOST.sub(lambda m: _host(m.group(0)), t)
    t = _USERDIR.sub(lambda m: m.group(1) + "alice", t)
    t = _USERDIR_BARE.sub(lambda m: m.group(1) + "alice", t)
    t = _HOMEDIR.sub(lambda m: m.group(1) + "alice", t)
    t = _INSTID.sub("i-0123456789abcdef0", t)
    t = _AWSRES.sub(_awsres, t)
    t = _ACCT.sub("000000000000", t)
    t = _MAC.sub(_mac, t)
    t = _IP6.sub(_ip6, t)
    return _IP.sub(_ip, t)


def redact_obj(o):
    if isinstance(o, str):
        return redact(o)
    if isinstance(o, list):
        return [redact_obj(x) for x in o]
    if isinstance(o, dict):
        return {k: redact_obj(v) for k, v in o.items()}
    return o


# Leak scan: pattern categories (no real values), plus the real-values denylist. Run on every string of every row.
LEAK_PATTERNS = {
    "ipv4": _IP, "ipv6": _IP6, "mac": _MAC, "sid": _SID, "computername": _EC2WIN, "ec2dns": _EC2DNS, "unc": _UNC, "compflag": _COMPFLAG,
    "email": re.compile(r"\b(?!git@)[\w.+-]+@(?!(?:[\w-]+\.)*example\.com\b)[\w-]+(?:\.[\w-]+)+\b"), "upn": _UPN, "idctx": _IDCTX,
    "domuser": _DOMUSER, "privfqdn": _PRIVFQDN, "labhost": _HOST,
    "userdir": _USERDIR, "userdir_bare": _USERDIR_BARE, "homedir": _HOMEDIR, "instance": _INSTID, "awsres": _AWSRES,
    "account": _ACCT, "secret": re.compile("|".join(r.pattern for r in _SECRETS[:9])),
}


def _hit_ok(name: str, m: re.Match) -> bool:
    s = m.group(0)
    if name in ("ipv4",):
        try:
            a = ipaddress.ip_address(s)
        except ValueError:
            return True
        return a.is_loopback or s.startswith(_KEEP_V4) or _keep_ip(a)
    if name == "ipv6":
        try:
            a = ipaddress.ip_address(s.split("%")[0])
        except ValueError:
            return True
        return a.version != 6 or a.is_loopback or a.is_unspecified or a in ipaddress.ip_network("2001:db8::/32") or _keep_ip(a)
    if name == "mac":
        low = s.lower().replace("-", ":")
        return low in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") or low.startswith("00:00:5e:00:53:")
    if name == "sid":
        return (m.group(1), m.group(2)) == ("1000000000", "2000000000")
    if name == "computername":
        return False
    if name == "unc":
        return _is_ph(m.group(2), r"labpc\d+")
    if name == "compflag":
        return _is_ph(m.group(2), r"labpc\d+") or m.group(2).lower() in ("localhost", "local", "none", "null")
    if name == "idctx":
        return m.group(2).upper().replace(" ", "") in _SYSDOM or _is_ph(m.group(2), r"labdom\d+|labpc\d+")
    if name == "domuser":
        return m.group(1) in _SYSDOM or _is_ph(m.group(1), r"labdom\d+|labpc\d+")
    if name == "privfqdn":
        v = m.group(1)
        return bool(_PRIVSKIP.match(v) or _KEEP_NAME.match(v)) or v.lower().endswith(".example.com")
    if name == "upn":
        return _is_ph(m.group(1), r"labuser\d+") and _is_ph(m.group(2), r"labdomain\d+\.example\.com")
    if name == "labhost":
        return _is_ph(s, r"labhost\d+")
    if name == "instance":
        return s == "i-0123456789abcdef0"
    if name == "awsres":
        return s.endswith("-0123456789abcdef0") or s.endswith("-01234567")
    if name == "account":
        return s == "000000000000"
    return False


# Public dataset handles named in DATASET_BY_SRC are provenance, not identities: the repo scan ignores them.
PUBLIC_DATASET_HANDLES = tuple(sorted({ds for ds, _, _ in DATASET_BY_SRC.values()}))


def deny_hits(text: str) -> list[str]:
    """Denylist categories whose real value occurs in `text` (one entry per occurrence; the value itself is never returned)."""
    flat = re.sub(r"\\+", r"\\", text)
    return [ents.get(m.group(0).lower(), "host") for rx, ents in _deny for m in rx.finditer(flat)]


_ALT = re.compile(r"\(\?:([^()]*\|[^()]*)\)|\(([^()?][^()]*\|[^()]*)\)")
_SPLIT = re.compile(r"[\"'`]\s*\+?\s*[\"'`]")


def _expand_alternations(s: str, cap: int = 64) -> list[str]:
    """Spell out simple regex alternations: `ab-(?:c|d)` -> `ab-c`, `ab-d` (nested groups one level at a time, at most `cap` results)."""
    out, todo = [], [s]
    while todo and len(out) < cap:
        cur = todo.pop()
        m = _ALT.search(cur)
        if not m:
            out.append(cur)
            continue
        for alt in (m.group(1) or m.group(2)).split("|"):
            todo.append(cur[: m.start()] + alt + cur[m.end():])
    return out


def _scan_forms(line: str, nxt: str = "") -> list[str]:
    """The spellings of a source line a literal match would miss: as is, split-string halves joined ("ab" + "cd", "ab" "cd", across a line break),
    regex alternations spelled out, regex escapes dropped, doubled backslashes folded. All lower case."""
    forms = {line}
    for base in (line, line.rstrip() + nxt.lstrip()):
        j = _SPLIT.sub("", base)
        forms.add(j)
        for alt in _expand_alternations(j):
            forms.add(alt)
            forms.add(re.sub(r"\\([.\-_/])", r"\1", re.sub(r"\\b", "", alt)))
    return [re.sub(r"\\+", r"\\", f).lower() for f in forms]


def deny_substring_hits(line: str, nxt: str = "") -> list[str]:
    """Denylist categories whose real value occurs in a source line as a SUBSTRING (inside an identifier, a regex alternation, a split string), case-insensitively.
    Values shorter than 6 characters must stand alone (a 3-letter NetBIOS name would otherwise match every word)."""
    forms = _scan_forms(line, nxt)
    hits = []
    for rx, ents in _deny:
        for v, cat in ents.items():
            vv = re.sub(r"\\+", r"\\", v)
            if len(vv) >= 6:
                if any(vv in f for f in forms):
                    hits.append(cat)
            elif any(re.search(r"(?<![a-z0-9])" + re.escape(vv) + r"(?![a-z0-9])", f) for f in forms):
                hits.append(cat)
    return hits


def leak_scan(text: str) -> list[str]:
    """Pattern categories that still hit `text` after redaction (one entry per category), plus 'denylist' when a real lab value survives."""
    hits = []
    for name, rx in LEAK_PATTERNS.items():
        for m in rx.finditer(text):
            if not _hit_ok(name, m):
                hits.append(name)
                break
    for cat in sorted(set(deny_hits(text))):
        hits.append("denylist:" + cat)
    return hits


def iter_strings(o):
    """Every string value of a row (keys too), decoded."""
    if isinstance(o, str):
        yield o
    elif isinstance(o, list):
        for x in o:
            yield from iter_strings(x)
    elif isinstance(o, dict):
        for k, v in o.items():
            yield k
            yield from iter_strings(v)


_ROW_SKIP_SOURCE = ("dataset", "license", "redistribution", "revision")


def redact_row(r: dict) -> dict:
    """Final redaction pass over a finished case row: payload, truth and source.original_id (ids, strata and fixed provenance fields are kept)."""
    out = dict(r)
    out["payload"] = redact_obj(r["payload"])
    out["truth"] = redact_obj(r["truth"])
    out["source"] = {k: (v if k in _ROW_SKIP_SOURCE else redact_obj(v)) for k, v in r["source"].items()}
    return out


def scan_row(r: dict) -> list[str]:
    """Leak categories left in any string of a row (source.dataset, the owner's public dataset handle, is provenance and not scanned)."""
    body = {k: v for k, v in r.items() if k != "source"}
    body["source"] = {k: v for k, v in r["source"].items() if k != "dataset"}
    hits: list[str] = []
    for s in iter_strings(body):
        for h in leak_scan(s):
            if h not in hits:
                hits.append(h)
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
    args = {"command": cmd}
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
