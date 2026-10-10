#!/usr/bin/env python3
"""
Edge Connector Policy Compiler

Compiles YAML policy files into:
  1. C header (policy_tables.h) — compile-time embed for device firmware
  2. Signed binary blob (policy.bin) — OTA delivery to devices

Usage:
  dclaw-compile --input policies/strict.yaml --profile standard \
    --output-header generated/policy_tables.h \
    --output-binary dist/policy.bin \
    --signing-key keys/ota-ca.key \
    --target-partition-size 4096

Implements REQ-41 through REQ-44.
"""

import argparse
import hashlib
import re
import struct
import sys
import os
from collections import deque
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML required. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


# Profile partition size limits (must match HAL_FLASH_POLICY_*_SIZE in platform.h)
PROFILE_LIMITS = {
    "minimal": 2048,
    "standard": 4096,
    "edge": 4096,
}

# Capability name → bitmask mapping
CAP_MAP = {
    "read_fs": 0x01,
    "write_fs": 0x02,
    "exec_shell": 0x04,
    "net_fetch": 0x08,
    "send_msg": 0x10,
    "actuate": 0x20,
    "sensor_read": 0x40,
}

# Action name → enum value
ACTION_MAP = {
    "allow": 0,
    "block": 1,
    "warn": 2,
    "escalate": 3,
}

# Severity name → enum value
SEVERITY_MAP = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# Escalation mode name → value
ESCALATION_MAP = {
    "sync_block": 0,
    "speculative": 1,
}

# Content category name → enum value
CONTENT_CATEGORY_MAP = {
    "secret": 1,
    "pii": 2,
    "credential": 3,
    "exfil": 4,
    "injection": 5,
    "command": 6,
}

# CRT-2 fix: Hostname-safe pattern for destination allowlist entries.
# Only alphanumeric, dot, hyphen, and wildcard star are allowed.
HOSTNAME_SAFE_RE = re.compile(r'^[a-zA-Z0-9.*\-]+$')


def validate_destination(dest: str) -> str:
    """CRT-2 fix: Validate destination string against hostname-safe pattern.
    Raises ValueError if the destination contains unsafe characters."""
    if not HOSTNAME_SAFE_RE.match(dest):
        raise ValueError(
            f"Destination '{dest}' contains unsafe characters. "
            f"Only [a-zA-Z0-9.*-] are allowed.")
    return dest


def escape_c_string(s: str) -> str:
    """CRT-2 fix: Escape quotes and backslashes in C string literals."""
    return s.replace('\\', '\\\\').replace('"', '\\"')


# ── Aho-Corasick DFA builder ──────────────────────────────────────────────

# All patterns for each content category.
# Each entry: (lowercase_pattern_string, category_int, severity_int, flags)
# flags: 0 = normal word-boundary match, 1 = substring (no boundary), 2 = needs_suffix
CONTENT_DFA_PATTERNS = [
    # SECRET category (category=1, severity=HIGH=3)
    ("api_key",                          1, 3, 0),
    ("apikey",                           1, 3, 0),
    ("api-key",                          1, 3, 0),
    ("secret_key",                       1, 3, 0),
    ("secretkey",                        1, 3, 0),
    ("secret-key",                       1, 3, 0),
    ("private_key",                      1, 3, 0),
    ("privatekey",                       1, 3, 0),
    ("private-key",                      1, 3, 0),
    ("access_token",                     1, 3, 0),
    ("accesstoken",                      1, 3, 0),
    ("access-token",                     1, 3, 0),
    ("bearer_token",                     1, 3, 0),
    ("bearertoken",                      1, 3, 0),
    ("bearer-token",                     1, 3, 0),
    ("password",                         1, 3, 0),
    ("passwd",                           1, 3, 0),
    ("-----begin private key-----",      1, 3, 1),
    ("-----begin rsa private key-----",  1, 3, 1),

    # CREDENTIAL category (category=3, severity=HIGH=3)
    ("authorization:",                   3, 3, 1),
    ("basic ",                           3, 3, 1),
    ("bearer ",                          3, 3, 1),
    ("token ",                           3, 3, 1),
    # "username" and "login" require = or : after (suffix flag=2)
    ("username=",                         3, 3, 1),
    ("username:",                         3, 3, 1),
    ("login=",                            3, 3, 1),
    ("login:",                            3, 3, 1),

    # INJECTION category (category=5, severity=HIGH=3)
    # SQL keywords with trailing space (word-boundary enforced via pattern shape)
    ("select ",                          5, 3, 0),
    ("insert ",                          5, 3, 0),
    ("update ",                          5, 3, 0),
    ("delete ",                          5, 3, 0),
    ("drop ",                            5, 3, 0),
    ("union ",                           5, 3, 0),
    # XSS / template injection (substring match)
    ("<script",                          5, 3, 1),
    ("javascript:",                      5, 3, 1),
    ("onerror=",                         5, 3, 1),
    # Path traversal
    ("../",                              5, 3, 1),
    ("..\\",                             5, 3, 1),
    # Code injection
    ("${",                               5, 3, 1),
    ("eval(",                            5, 3, 1),
    ("exec(",                            5, 3, 1),

    # COMMAND category (category=6, severity=HIGH=3)
    ("rm ",                              6, 3, 0),
    ("chmod ",                           6, 3, 0),
    ("chown ",                           6, 3, 0),
    ("kill ",                            6, 3, 0),
    ("sudo ",                            6, 3, 0),
    ("su ",                              6, 3, 0),
    ("system(",                          6, 3, 1),
    ("/bin/",                            6, 3, 1),
    ("/usr/bin/",                        6, 3, 1),
    ("cmd.exe",                          6, 3, 0),
    ("powershell",                       6, 3, 0),
]


class AhoCorasickBuilder:
    """
    Build an Aho-Corasick automaton from a set of byte patterns, then
    flatten it into a compact DFA transition table suitable for C codegen.

    The automaton operates on lowercased bytes (the C scanner lowercases
    on the fly).  Each accepting state carries a list of
    (pattern_id, category, severity, flags) tuples.
    """

    def __init__(self):
        self.goto = [{}]       # goto[state][byte] -> state
        self.fail = [0]        # fail[state] -> state
        self.output = [[]]     # output[state] -> [(pid, cat, sev, flags)]
        self._next_state = 1

    # -- trie construction --------------------------------------------------

    def add_pattern(self, pattern_bytes: bytes, pattern_id: int,
                    category: int, severity: int, flags: int):
        state = 0
        for b in pattern_bytes:
            if b not in self.goto[state]:
                self.goto[state][b] = self._next_state
                self.goto.append({})
                self.fail.append(0)
                self.output.append([])
                self._next_state += 1
            state = self.goto[state][b]
        self.output[state].append((pattern_id, category, severity, flags))

    # -- failure link computation (BFS) ------------------------------------

    def build(self):
        q = deque()
        # depth-1 states: fail -> 0
        for b, s in self.goto[0].items():
            self.fail[s] = 0
            q.append(s)

        while q:
            u = q.popleft()
            for b, v in self.goto[u].items():
                q.append(v)
                f = self.fail[u]
                while f != 0 and b not in self.goto[f]:
                    f = self.fail[f]
                self.fail[v] = self.goto[f].get(b, 0)
                if self.fail[v] == v:
                    self.fail[v] = 0
                # merge output from fail chain
                self.output[v] = self.output[v] + self.output[self.fail[v]]

    # -- DFA flattening (precompute all 256 transitions per state) ----------

    def flatten(self):
        """
        Returns (table, matches) where:
          table[state] = [next_state for byte 0..255]
          matches[state] = [(pattern_id, category, severity, flags), ...]
        """
        n = self._next_state
        table = [[0] * 256 for _ in range(n)]
        for state in range(n):
            for byte_val in range(256):
                s = state
                while s != 0 and byte_val not in self.goto[s]:
                    s = self.fail[s]
                table[state][byte_val] = self.goto[s].get(byte_val, 0)
        return table, self.output


def build_content_dfa():
    """Build the Aho-Corasick DFA from CONTENT_DFA_PATTERNS.
    Returns (table, matches, pattern_list) ready for C codegen."""
    ac = AhoCorasickBuilder()
    for pid, (pat, cat, sev, flags) in enumerate(CONTENT_DFA_PATTERNS):
        ac.add_pattern(pat.encode('ascii'), pid, cat, sev, flags)
    ac.build()
    table, matches = ac.flatten()
    return table, matches, CONTENT_DFA_PATTERNS


def parse_policy(yaml_path: Path) -> dict:
    """Parse a DefenseClaw YAML policy file."""
    with open(yaml_path) as f:
        policy = yaml.safe_load(f)
    return policy


def _validate_no_null_bytes(value: str, context: str) -> None:
    """H-8 fix: Reject strings containing null bytes that could truncate C strings."""
    if '\x00' in value:
        raise ValueError(
            f"H-8: Null byte found in {context}: {value!r}. "
            f"Null bytes in policy strings can truncate C agent buffers."
        )


def extract_severity_rules(policy: dict) -> list:
    """Extract severity→action rules from skill_actions section."""
    rules = []
    skill_actions = policy.get("skill_actions", {})
    for severity_name, actions in skill_actions.items():
        # H-8 fix: Validate no null bytes in string keys
        _validate_no_null_bytes(severity_name, "severity name")
        sev_val = SEVERITY_MAP.get(severity_name)
        if sev_val is None:
            continue
        runtime_action = actions.get("runtime", "enable")
        if runtime_action == "disable":
            action_val = ACTION_MAP["block"]
        elif runtime_action == "warn":
            action_val = ACTION_MAP["warn"]
        else:
            continue  # "enable" means ALLOW → no rule needed
        rules.append((sev_val, action_val))
    rules.sort(key=lambda x: x[0], reverse=True)  # highest severity first
    return rules


def extract_sequence_rules(policy: dict) -> list:
    """Extract capability sequence rules from iot_extensions."""
    rules = []
    iot_ext = policy.get("iot_extensions", {})
    sequences = iot_ext.get("capability_sequences", [])
    # H-8 fix: Validate sequence list is non-empty
    if not isinstance(sequences, list):
        raise ValueError("H-8: capability_sequences must be a list")
    for entry in sequences:
        seq = entry.get("sequence", [])
        # H-8 fix: Sequence length must be > 0
        if not seq or len(seq) == 0:
            raise ValueError(
                "H-8: capability_sequences entry has empty sequence. "
                "Empty sequences would match everything, weakening the C agent."
            )
        action = ACTION_MAP.get(entry.get("action", "block"), 1)
        cap_bytes = []
        for cap_name in seq:
            # H-8 fix: Validate no null bytes in capability names
            _validate_no_null_bytes(str(cap_name), "capability name")
            cap_val = CAP_MAP.get(cap_name)
            if cap_val is None:
                print(f"WARNING: unknown capability '{cap_name}', skipping rule",
                      file=sys.stderr)
                break
            cap_bytes.append(cap_val)
        else:
            if len(cap_bytes) <= 4:
                rules.append((cap_bytes, action))
    return rules


def extract_dest_allowlist(policy: dict) -> list:
    """Extract destination allowlist from iot_extensions."""
    iot_ext = policy.get("iot_extensions", {})
    dest_list = iot_ext.get("destination_allowlist", [])
    # H-8 fix: Validate no null bytes in destination strings
    for dest in dest_list:
        _validate_no_null_bytes(str(dest), "destination allowlist entry")
    return dest_list


def extract_rate_limits(policy: dict) -> dict:
    """Extract rate limits from iot_extensions."""
    iot_ext = policy.get("iot_extensions", {})
    rate_limits = iot_ext.get("rate_limits", {
        "tool_calls_per_minute": 60,
        "network_requests_per_minute": 30,
        "actuations_per_minute": 10,
    })
    # H-8 fix: Validate all rate limits are > 0 to prevent disabling rate limiting
    # M-14 fix: Reject float values that would truncate to 0 in uint16
    for key, value in rate_limits.items():
        if isinstance(value, (int, float)) and value <= 0:
            raise ValueError(
                f"Rate limit '{key}' must be > 0, got {value}. "
                f"Zero or negative rate limits would disable rate limiting."
            )
        if isinstance(value, float) and int(value) == 0:
            raise ValueError(
                f"Rate limit '{key}' is {value} which truncates to 0 in uint16. "
                f"Use an integer >= 1."
            )
        if isinstance(value, float):
            rate_limits[key] = int(value)
    return rate_limits


def extract_escalation_modes(policy: dict) -> list:
    """Extract escalation mode table from iot_extensions."""
    iot_ext = policy.get("iot_extensions", {})
    modes = iot_ext.get("escalation_mode", {})
    entries = []
    for cap_name, mode_name in modes.items():
        cap_val = CAP_MAP.get(cap_name)
        mode_val = ESCALATION_MAP.get(mode_name, 0)
        if cap_val is not None:
            entries.append((cap_val, mode_val))
    entries.sort(key=lambda x: x[0])
    return entries


def extract_canary_baseline(policy: dict) -> int:
    """Extract canary baseline from iot_extensions."""
    iot_ext = policy.get("iot_extensions", {})
    canary = iot_ext.get("canary", {})
    return canary.get("baseline_blocks_per_min", 5)


def extract_content_inspection(policy: dict) -> dict:
    """Extract content inspection configuration from iot_extensions."""
    iot_ext = policy.get("iot_extensions", {})
    content_inspection = iot_ext.get("content_inspection", {})

    result = {
        "enabled": content_inspection.get("enabled", False),
        "rules": []
    }

    if not result["enabled"]:
        return result

    categories = content_inspection.get("categories", {})
    for cat_name, config in categories.items():
        if not config.get("enabled", False):
            continue

        cat_val = CONTENT_CATEGORY_MAP.get(cat_name)
        if cat_val is None:
            print(f"WARNING: unknown content category '{cat_name}', skipping",
                  file=sys.stderr)
            continue

        sev_val = SEVERITY_MAP.get(config.get("severity", "high"), 3)
        act_val = ACTION_MAP.get(config.get("action", "block"), 1)

        result["rules"].append({
            "category": cat_val,
            "severity": sev_val,
            "action": act_val,
            "enabled": 1
        })

    result["rules"].sort(key=lambda x: x["category"])
    return result


def extract_ssrf_protection(policy: dict) -> dict:
    """Extract SSRF protection configuration from iot_extensions."""
    iot_ext = policy.get("iot_extensions", {})
    ssrf = iot_ext.get("ssrf_protection", {})

    return {
        "enabled": ssrf.get("enabled", False),
        "block_private_ranges": ssrf.get("block_private_ranges", False),
        "block_loopback": ssrf.get("block_loopback", False),
        "block_link_local": ssrf.get("block_link_local", False),
        "block_cloud_metadata": ssrf.get("block_cloud_metadata", False),
    }


def extract_cloud_escalation(policy: dict) -> dict:
    """Extract cloud escalation configuration from iot_extensions."""
    iot_ext = policy.get("iot_extensions", {})
    cloud_esc = iot_ext.get("cloud_escalation", {})

    return {
        "max_payload_bytes": cloud_esc.get("max_payload_bytes", 1024),
        "include_content": cloud_esc.get("include_content", True),
        "include_local_findings": cloud_esc.get("include_local_findings", True),
    }


def extract_trust_boundaries(policy: dict) -> dict:
    """Extract trust boundary configuration from iot_extensions."""
    iot_ext = policy.get("iot_extensions", {})
    trust = iot_ext.get("trust_boundaries", {})

    return {
        "infer_from_context": trust.get("infer_from_context", True),
        "strict_user_input": trust.get("strict_user_input", True),
        "user_input_block_threshold": SEVERITY_MAP.get(
            trust.get("user_input_block_threshold", "medium"), 2),
        "system_block_threshold": SEVERITY_MAP.get(
            trust.get("system_block_threshold", "high"), 3),
    }


def generate_c_header(policy: dict, version: int) -> str:
    """Generate C header with compiled policy tables."""
    severity_rules = extract_severity_rules(policy)
    sequence_rules = extract_sequence_rules(policy)
    dest_allowlist = extract_dest_allowlist(policy)
    rate_limits = extract_rate_limits(policy)
    escalation_modes = extract_escalation_modes(policy)
    canary_baseline = extract_canary_baseline(policy)
    content_inspection = extract_content_inspection(policy)
    ssrf_protection = extract_ssrf_protection(policy)
    cloud_escalation = extract_cloud_escalation(policy)
    trust_boundaries = extract_trust_boundaries(policy)

    lines = [
        '#ifndef DCLAW_POLICY_TABLES_H',
        '#define DCLAW_POLICY_TABLES_H',
        '',
        '/*',
        f' * Auto-generated by policy_compiler.py',
        f' * Policy version: {version}',
        ' * DO NOT EDIT MANUALLY',
        ' */',
        '',
        '#include "defenseclaw.h"',
        '',
        '#ifdef __GNUC__',
        '#define DCLAW_UNUSED __attribute__((unused))',
        '#else',
        '#define DCLAW_UNUSED',
        '#endif',
        '',
        '/* === Severity Rules === */',
        '',
        'typedef struct {',
        '    uint8_t severity;',
        '    uint8_t action;',
        '} dclaw_severity_rule_t;',
        '',
        'DCLAW_UNUSED',
        'static const dclaw_severity_rule_t severity_rules[] = {',
    ]
    for sev, act in severity_rules:
        lines.append(f'    {{ {sev}, {act} }},')
    lines.append('};')
    lines.append(f'DCLAW_UNUSED static const size_t severity_rules_count = {len(severity_rules)};')
    lines.append('')

    # Sequence rules
    lines.append('/* === Capability Sequence Rules === */')
    lines.append('')
    lines.append('#define DCLAW_MAX_SEQ_LEN 4')
    lines.append('')
    lines.append('typedef struct {')
    lines.append('    uint8_t seq[DCLAW_MAX_SEQ_LEN];')
    lines.append('    uint8_t seq_len;')
    lines.append('    uint8_t action;')
    lines.append('} dclaw_sequence_rule_t;')
    lines.append('')
    lines.append('DCLAW_UNUSED')
    lines.append('static const dclaw_sequence_rule_t sequence_rules[] = {')
    for seq, act in sequence_rules:
        seq_str = ', '.join(f'0x{b:02X}' for b in seq)
        pad = ', 0x00' * (4 - len(seq))
        lines.append(f'    {{ .seq = {{{seq_str}{pad}}}, .seq_len = {len(seq)}, .action = {act} }},')
    lines.append('};')
    lines.append(f'DCLAW_UNUSED static const size_t sequence_rules_count = {len(sequence_rules)};')
    lines.append('')

    # Destination allowlist
    lines.append('/* === Destination Allowlist === */')
    lines.append('')
    lines.append('DCLAW_UNUSED')
    lines.append('static const char *dest_allowlist[] = {')
    for dest in dest_allowlist:
        validate_destination(dest)  # CRT-2: reject unsafe chars
        lines.append(f'    "{escape_c_string(dest)}",')
    lines.append('};')
    lines.append(f'DCLAW_UNUSED static const size_t dest_allowlist_count = {len(dest_allowlist)};')
    lines.append('')

    # Deny hash list (empty — populated by threat intel)
    lines.append('/* === Deny Hash List (sorted for binary search) === */')
    lines.append('')
    lines.append('/* no deny hashes configured */')
    lines.append('DCLAW_UNUSED')
    lines.append('static const uint8_t deny_hashes[1][32] = {{0}};')
    lines.append('DCLAW_UNUSED static const size_t deny_hashes_count = 0;')
    lines.append('')

    # Escalation table
    lines.append('/* === Escalation Mode Table === */')
    lines.append('')
    lines.append('DCLAW_UNUSED')
    lines.append('static const dclaw_escalation_entry_t escalation_table[] = {')
    for cap, mode in escalation_modes:
        lines.append(f'    {{ 0x{cap:02X}, {mode} }},')
    lines.append('};')
    lines.append(f'DCLAW_UNUSED static const size_t escalation_table_count = {len(escalation_modes)};')
    lines.append('')

    # Canary baseline
    lines.append(f'/* === Canary Baseline === */')
    lines.append(f'DCLAW_UNUSED static const uint16_t policy_canary_baseline_blocks_per_min = {canary_baseline};')
    lines.append('')

    # Rate limits
    lines.append('/* === Rate Limit Defaults === */')
    lines.append(f'DCLAW_UNUSED static const uint16_t policy_rate_tool_calls_per_min = {rate_limits.get("tool_calls_per_minute", 60)};')
    lines.append(f'DCLAW_UNUSED static const uint16_t policy_rate_network_per_min = {rate_limits.get("network_requests_per_minute", 30)};')
    lines.append(f'DCLAW_UNUSED static const uint16_t policy_rate_actuations_per_min = {rate_limits.get("actuations_per_minute", 10)};')
    lines.append('')

    # Content inspection rules
    lines.append('/* === Content Inspection Categories === */')
    lines.append('')
    lines.append('typedef struct {')
    lines.append('    uint8_t category;')
    lines.append('    uint8_t severity;')
    lines.append('    uint8_t action;')
    lines.append('    uint8_t enabled;')
    lines.append('} dclaw_content_rule_t;')
    lines.append('')
    lines.append('DCLAW_UNUSED')
    lines.append('static const dclaw_content_rule_t content_rules[] = {')
    for rule in content_inspection["rules"]:
        lines.append(f'    {{ {rule["category"]}, {rule["severity"]}, {rule["action"]}, {rule["enabled"]} }},')
    lines.append('};')
    lines.append(f'DCLAW_UNUSED static const size_t content_rules_count = {len(content_inspection["rules"])};')
    lines.append(f'DCLAW_UNUSED static const uint8_t content_inspection_enabled = {1 if content_inspection["enabled"] else 0};')
    lines.append('')

    # SSRF protection
    lines.append('/* === SSRF Protection === */')
    lines.append(f'DCLAW_UNUSED static const uint8_t ssrf_enabled = {1 if ssrf_protection["enabled"] else 0};')
    lines.append(f'DCLAW_UNUSED static const uint8_t ssrf_block_private = {1 if ssrf_protection["block_private_ranges"] else 0};')
    lines.append(f'DCLAW_UNUSED static const uint8_t ssrf_block_loopback = {1 if ssrf_protection["block_loopback"] else 0};')
    lines.append(f'DCLAW_UNUSED static const uint8_t ssrf_block_link_local = {1 if ssrf_protection["block_link_local"] else 0};')
    lines.append(f'DCLAW_UNUSED static const uint8_t ssrf_block_cloud_metadata = {1 if ssrf_protection["block_cloud_metadata"] else 0};')
    lines.append('')

    # Cloud escalation
    lines.append('/* === Cloud Escalation === */')
    lines.append(f'DCLAW_UNUSED static const uint16_t escalation_max_payload = {cloud_escalation["max_payload_bytes"]};')
    lines.append(f'DCLAW_UNUSED static const uint8_t escalation_include_content = {1 if cloud_escalation["include_content"] else 0};')
    lines.append(f'DCLAW_UNUSED static const uint8_t escalation_include_findings = {1 if cloud_escalation["include_local_findings"] else 0};')
    lines.append('')

    # Trust boundaries
    lines.append('/* === Trust Boundaries === */')
    lines.append(f'DCLAW_UNUSED static const uint8_t trust_infer_from_context = {1 if trust_boundaries["infer_from_context"] else 0};')
    lines.append(f'DCLAW_UNUSED static const uint8_t trust_strict_user_input = {1 if trust_boundaries["strict_user_input"] else 0};')
    lines.append(f'DCLAW_UNUSED static const uint8_t trust_user_input_block_threshold = {trust_boundaries["user_input_block_threshold"]};')
    lines.append(f'DCLAW_UNUSED static const uint8_t trust_system_block_threshold = {trust_boundaries["system_block_threshold"]};')
    lines.append('')

    # ── Aho-Corasick Content DFA ─────────────────────────────────────────
    dfa_table, dfa_matches, dfa_patterns = build_content_dfa()
    num_states = len(dfa_table)

    lines.append('/* === Aho-Corasick Content Scanner DFA === */')
    lines.append('')
    lines.append(f'#define DCLAW_AC_NUM_STATES {num_states}')
    lines.append(f'#define DCLAW_AC_NUM_PATTERNS {len(dfa_patterns)}')
    lines.append('')

    # Pattern metadata table
    lines.append('typedef struct {')
    lines.append('    uint8_t category;  /* dclaw_content_category_t */')
    lines.append('    uint8_t severity;  /* dclaw_severity_t */')
    lines.append('    uint8_t flags;     /* 0=word-boundary, 1=substring, 2=needs_suffix */')
    lines.append('    uint8_t pat_len;   /* original pattern length */')
    lines.append('} dclaw_ac_pattern_t;')
    lines.append('')
    lines.append('DCLAW_UNUSED')
    lines.append('static const dclaw_ac_pattern_t ac_patterns[] = {')
    for pat, cat, sev, flags in dfa_patterns:
        lines.append(f'    {{ {cat}, {sev}, {flags}, {len(pat)} }},  /* "{pat}" */')
    lines.append('};')
    lines.append('')

    # Per-state match lists — collect which states have matches
    # Build a flat array of (pattern_id) entries plus an index table.
    match_entries = []   # flat list of pattern ids
    match_index = []     # (offset, count) per state
    for state_matches in dfa_matches:
        if state_matches:
            match_index.append((len(match_entries), len(state_matches)))
            for pid, _cat, _sev, _flags in state_matches:
                match_entries.append(pid)
        else:
            match_index.append((0, 0))

    lines.append(f'#define DCLAW_AC_MATCH_ENTRIES {len(match_entries)}')
    lines.append('')
    if match_entries:
        lines.append('DCLAW_UNUSED')
        lines.append('static const uint8_t ac_match_pids[] = {')
        # emit in rows of 16
        for i in range(0, len(match_entries), 16):
            chunk = match_entries[i:i+16]
            lines.append('    ' + ', '.join(str(x) for x in chunk) + ',')
        lines.append('};')
    else:
        lines.append('DCLAW_UNUSED')
        lines.append('static const uint8_t ac_match_pids[] = { 0 };')
    lines.append('')

    # Match index table: (offset, count) per state — stored as uint16_t pairs
    lines.append('typedef struct {')
    lines.append('    uint16_t offset;')
    lines.append('    uint8_t  count;')
    lines.append('} dclaw_ac_match_index_t;')
    lines.append('')
    lines.append('DCLAW_UNUSED')
    lines.append('static const dclaw_ac_match_index_t ac_match_index[] = {')
    for off, cnt in match_index:
        lines.append(f'    {{ {off}, {cnt} }},')
    lines.append('};')
    lines.append('')

    # Transition table: ac_transitions[state][byte] -> next_state
    # Use uint16_t since state count can exceed 255
    lines.append('DCLAW_UNUSED')
    lines.append(f'static const uint16_t ac_transitions[{num_states}][256] = {{')
    for state_idx, row in enumerate(dfa_table):
        # Check if all zeros (common for many states)
        if all(v == 0 for v in row):
            lines.append(f'    /* state {state_idx} */ {{0}},')
        else:
            # Emit non-zero entries compactly using designated initializers
            nonzero = [(i, v) for i, v in enumerate(row) if v != 0]
            if len(nonzero) <= 12:
                entries = ', '.join(f'[{i}]={v}' for i, v in nonzero)
                lines.append(f'    /* state {state_idx} */ {{{entries}}},')
            else:
                lines.append(f'    /* state {state_idx} */ {{')
                for i in range(0, 256, 16):
                    chunk = row[i:i+16]
                    lines.append('        ' + ', '.join(f'{v:>3}' for v in chunk) + ',')
                lines.append('    },')
    lines.append('};')
    lines.append('')

    # DFA availability flag
    lines.append('#define DCLAW_AC_DFA_AVAILABLE 1')
    lines.append('')

    lines.append('#endif /* DCLAW_POLICY_TABLES_H */')
    lines.append('')

    return '\n'.join(lines)


def generate_binary_blob(policy: dict, version: int) -> bytes:
    """Generate signed binary policy blob for OTA delivery."""
    severity_rules = extract_severity_rules(policy)
    sequence_rules = extract_sequence_rules(policy)
    dest_allowlist = extract_dest_allowlist(policy)
    canary_baseline = extract_canary_baseline(policy)
    content_inspection = extract_content_inspection(policy)
    ssrf_protection = extract_ssrf_protection(policy)

    # Build payload
    payload = bytearray()

    # Sections-present bitmask (first byte of payload).
    # Bit 7 (0x80) = always set (marker so ota_receiver.c knows this byte exists)
    # Bit 0 = severity rules section present
    # Bit 1 = sequence rules section present
    # Bit 2 = destination allowlist section present
    sections_bitmask = 0x80
    if severity_rules is not None:
        sections_bitmask |= 0x01
    if sequence_rules is not None:
        sections_bitmask |= 0x02
    if dest_allowlist is not None:
        sections_bitmask |= 0x04
    payload.append(sections_bitmask)

    # H-5 fix: Validate rule counts fit in uint8 before appending
    if len(severity_rules) > 255:
        raise ValueError(f"Too many severity rules: {len(severity_rules)} (max 255)")
    if len(sequence_rules) > 255:
        raise ValueError(f"Too many sequence rules: {len(sequence_rules)} (max 255)")
    if len(dest_allowlist) > 255:
        raise ValueError(f"Too many destination allowlist entries: {len(dest_allowlist)} (max 255)")

    # Severity rules
    payload.append(len(severity_rules))
    for sev, act in severity_rules:
        payload.extend(struct.pack('BB', sev, act))

    # Sequence rules
    payload.append(len(sequence_rules))
    for seq, act in sequence_rules:
        padded = seq + [0] * (4 - len(seq))
        payload.extend(struct.pack('4sBB', bytes(padded), len(seq), act))

    # Destination allowlist
    payload.append(len(dest_allowlist))
    for dest in dest_allowlist:
        validate_destination(dest)  # CRT-2: reject unsafe chars
        encoded = dest.encode('ascii')[:67]  # max 64 + 3 overhead
        payload.append(len(encoded))
        payload.extend(encoded)

    # Content inspection rules
    payload.append(1 if content_inspection["enabled"] else 0)
    payload.append(len(content_inspection["rules"]))
    for rule in content_inspection["rules"]:
        payload.extend(struct.pack('BBBB', rule["category"], rule["severity"],
                                   rule["action"], rule["enabled"]))

    # SSRF protection flags
    ssrf_flags = 0
    if ssrf_protection["enabled"]:
        ssrf_flags |= 0x01
    if ssrf_protection["block_private_ranges"]:
        ssrf_flags |= 0x02
    if ssrf_protection["block_loopback"]:
        ssrf_flags |= 0x04
    if ssrf_protection["block_link_local"]:
        ssrf_flags |= 0x08
    if ssrf_protection["block_cloud_metadata"]:
        ssrf_flags |= 0x10
    payload.append(ssrf_flags)

    # Header: version(2) + payload_len(2) + canary_baseline(2) + reserved(2)
    header = struct.pack('>HHHxx', version, len(payload), canary_baseline)
    blob = header + payload

    return bytes(blob)


def sign_blob(blob: bytes, key_path: str) -> bytes:
    """Sign blob with Ed25519. Returns 64-byte signature."""
    if key_path and os.path.exists(key_path):
        try:
            import nacl.signing
            with open(key_path, 'rb') as f:
                key_data = f.read()
            signing_key = nacl.signing.SigningKey(key_data[:32])
            signed = signing_key.sign(blob)
            return signed.signature
        except ImportError:
            print("WARNING: PyNaCl not installed. Using dev stub signature.",
                  file=sys.stderr)
            # H-4 fix: In production mode, refuse to silently fall back to
            # the dev stub signature. Check DCLAW_PRODUCTION or DCLAW_DEV_MODE.
            if os.environ.get("DCLAW_PRODUCTION", "").lower() in ("1", "true", "yes"):
                raise RuntimeError(
                    "PyNaCl is required for signing in production mode "
                    "(DCLAW_PRODUCTION is set). Install with: pip install pynacl"
                )
            if os.environ.get("DCLAW_DEV_MODE", "").upper() == "OFF":
                raise RuntimeError(
                    "PyNaCl is required for signing when DCLAW_DEV_MODE=OFF. "
                    "Install with: pip install pynacl"
                )

    # H-4 fix: Also check production env vars when no key_path is provided.
    if os.environ.get("DCLAW_PRODUCTION", "").lower() in ("1", "true", "yes"):
        raise RuntimeError(
            "Signing key is required in production mode (DCLAW_PRODUCTION is set). "
            "Provide --signing-key with a valid Ed25519 key."
        )
    if os.environ.get("DCLAW_DEV_MODE", "").upper() == "OFF":
        raise RuntimeError(
            "Signing key is required when DCLAW_DEV_MODE=OFF. "
            "Provide --signing-key with a valid Ed25519 key."
        )

    # M-14 fix: Emit a startup warning when falling through to the dev stub
    # signature path without DCLAW_PRODUCTION or a signing key configured.
    # This makes it obvious in CI/CD logs that the policy blob is unsigned.
    print("WARNING: No signing key provided and DCLAW_PRODUCTION is not set. "
          "Using dev stub signature — the resulting policy.bin is NOT "
          "cryptographically signed and will be rejected by production devices.",
          file=sys.stderr)

    # M-5 fix: Set DCLAW_BLOB_UNSIGNED=1 so downstream callers (CI scripts,
    # test harnesses) can programmatically detect that the blob was signed
    # with the dev stub rather than a real Ed25519 key.
    os.environ["DCLAW_BLOB_UNSIGNED"] = "1"

    # M-5 fix: Dev stub signature format (64 bytes):
    #   byte 0:     0xDE  — "dev" marker byte (M-5: added so Go signing path
    #                        can detect unsigned blobs at sig[0] without hashing)
    #   byte 1:     0xED  — legacy marker (kept for backward compat)
    #   bytes 2-33: SHA-256(blob) (32 bytes)
    #   bytes 34-63: zero padding (30 bytes)
    #
    # The Go policy service (policy.go) detects this stub by checking:
    #   sig[0] == 0xDE (fast first-byte check)
    #   sig[1] == 0xED and sig[2:34] == SHA-256(unsigned)
    # and strips it before appending the real HMAC signature.
    digest = hashlib.sha256(blob).digest()  # 32 bytes
    sig = b'\xDE\xED' + digest + b'\x00' * (62 - len(digest))
    return sig


def compute_size_report(c_header: str, binary_blob: bytes, profile: str,
                        profile_limits: dict | None = None) -> str:
    """Generate size validation report."""
    _limits = profile_limits if profile_limits is not None else PROFILE_LIMITS
    limit = _limits.get(profile, 4096)
    blob_size = len(binary_blob)

    report_lines = [
        "Policy compilation report:",
        f"  C header size:    {len(c_header):>6} bytes",
        f"  Binary blob size: {blob_size:>6} bytes",
        f"  Target profile:   {profile}",
        f"  Partition limit:  {limit:>6} bytes",
        f"  Remaining:        {limit - blob_size:>6} bytes",
        "",
    ]

    if blob_size > limit:
        report_lines.append(f"  ERROR: Binary blob ({blob_size}B) exceeds "
                           f"{profile} partition limit ({limit}B)!")
        report_lines.append("  Reduce dest_allowlist or sequence rules.")
    else:
        report_lines.append(f"  OK: Fits within {profile} partition "
                           f"({blob_size}/{limit} = {100*blob_size//limit}% used)")

    return '\n'.join(report_lines)


def main():
    parser = argparse.ArgumentParser(description='Edge Connector Policy Compiler')
    parser.add_argument('--input', required=True, help='Input YAML policy file')
    parser.add_argument('--profile', default='standard',
                       choices=['minimal', 'standard', 'edge'],
                       help='Target device profile')
    parser.add_argument('--version', type=int, default=1,
                       help='Policy version number (monotonic)')
    parser.add_argument('--target-partition-size', type=int, default=0,
                       help='Override partition size limit (bytes)')
    parser.add_argument('--signing-key', default='',
                       help='Ed25519 private key for signing')
    parser.add_argument('--output-header', default='policy_tables.h',
                       help='Output C header path')
    parser.add_argument('--output-binary', default='policy.bin',
                       help='Output signed binary blob path')
    parser.add_argument('--output-report', default='',
                       help='Output size report path (optional)')
    args = parser.parse_args()

    limits = dict(PROFILE_LIMITS)
    if args.target_partition_size > 0:
        limits[args.profile] = args.target_partition_size

    # Parse policy
    policy = parse_policy(Path(args.input))
    print(f"Parsed policy: {policy.get('name', 'unnamed')}")

    # Generate C header
    c_header = generate_c_header(policy, args.version)
    os.makedirs(os.path.dirname(args.output_header) or '.', exist_ok=True)
    with open(args.output_header, 'w') as f:
        f.write(c_header)
    print(f"Generated C header: {args.output_header} ({len(c_header)} bytes)")

    # Generate binary blob
    blob = generate_binary_blob(policy, args.version)
    signature = sign_blob(blob, args.signing_key)
    signed_blob = blob + signature

    os.makedirs(os.path.dirname(args.output_binary) or '.', exist_ok=True)
    with open(args.output_binary, 'wb') as f:
        f.write(signed_blob)
    print(f"Generated binary: {args.output_binary} ({len(signed_blob)} bytes)")

    # Size validation (REQ-44)
    report = compute_size_report(c_header, blob, args.profile, profile_limits=limits)
    print(f"\n{report}")

    if args.output_report:
        with open(args.output_report, 'w') as f:
            f.write(report)

    # Fail if oversized
    partition_limit = limits[args.profile]
    if len(blob) > partition_limit:
        print(f"\nFATAL: Policy blob exceeds {args.profile} partition limit!",
              file=sys.stderr)
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
