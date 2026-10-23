#!/usr/bin/env python3

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

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
import ipaddress
import logging
import os
import struct
import sys
from collections import deque
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger("defenseclaw.policy_compiler")

# Signature type markers — written at a fixed offset in policy.bin so
# consumers can distinguish dev-stub blobs from production-signed ones
# without attempting (and failing) signature verification.
SIGNATURE_TYPE_DEV = 0x00
SIGNATURE_TYPE_ED25519 = 0x01
SIGNATURE_TYPE_HMAC = 0x02

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

def validate_destination(dest: str) -> str:
    """The local SSRF guard can enforce only explicit public IP literals."""
    if not isinstance(dest, str):
        raise ValueError("destination allowlist entries must be strings")
    try:
        address = ipaddress.ip_address(dest)
    except ValueError as exc:
        raise ValueError(f"Destination '{dest}' must be a public IP literal; "
                         "hostnames require an enforced egress proxy") from exc
    if not address.is_global or (address.version == 6 and not dest.startswith(('2', '3'))):
        raise ValueError(f"Destination '{dest}' must be a public IP literal")
    return dest


def validate_policy_extensions(policy: dict) -> None:
    """Reject IoT options that this compiler/device would silently ignore."""
    extensions = policy.get("iot_extensions", {})
    if not isinstance(extensions, dict):
        raise ValueError("iot_extensions must be a mapping")
    supported = {"capability_sequences", "destination_allowlist", "canary"}
    unknown = set(extensions) - supported
    if unknown:
        raise ValueError(f"unsupported iot_extensions: {', '.join(sorted(unknown))}")
    canary = extensions.get("canary", {})
    if not isinstance(canary, dict) or set(canary) - {"baseline_blocks_per_min"}:
        raise ValueError("canary supports only baseline_blocks_per_min")


def escape_c_string(s: str) -> str:
    """Escape quotes and backslashes in C string literals."""
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
    """Reject strings containing null bytes that would truncate C agent buffers."""
    if '\x00' in value:
        raise ValueError(
            f"Null byte found in {context}: {value!r}. "
            f"Null bytes in policy strings can truncate C agent buffers."
        )


def extract_severity_rules(policy: dict) -> list:
    """Extract severity→action rules from skill_actions section."""
    rules = []
    skill_actions = policy.get("skill_actions", {})
    if not isinstance(skill_actions, dict):
        raise ValueError("skill_actions must be a mapping")
    for severity_name, actions in skill_actions.items():
        if severity_name not in SEVERITY_MAP:
            raise ValueError(f"unknown skill_actions severity: {severity_name!r}")
        sev_val = SEVERITY_MAP[severity_name]
        if not isinstance(actions, dict):
            raise ValueError(f"skill_actions.{severity_name} must be a mapping")
        runtime_action = actions.get("runtime", "enable")
        if runtime_action == "disable":
            action_val = ACTION_MAP["block"]
        elif runtime_action == "warn":
            action_val = ACTION_MAP["warn"]
        elif runtime_action == "enable":
            continue  # "enable" means ALLOW → no rule needed
        else:
            raise ValueError(f"invalid skill_actions.{severity_name}.runtime: {runtime_action!r}")
        rules.append((sev_val, action_val))
    rules.sort(key=lambda x: x[0], reverse=True)  # highest severity first
    return rules


def extract_sequence_rules(policy: dict) -> list:
    """Extract capability sequence rules from iot_extensions."""
    rules = []
    iot_ext = policy.get("iot_extensions", {})
    sequences = iot_ext.get("capability_sequences", [])
    if not isinstance(sequences, list):
        raise ValueError("capability_sequences must be a list")
    for entry in sequences:
        if not isinstance(entry, dict) or set(entry) - {"sequence", "action"}:
            raise ValueError("capability_sequences entries support only sequence and action")
        seq = entry.get("sequence", [])
        if not isinstance(seq, list) or not 1 <= len(seq) <= 4:
            raise ValueError("capability sequence must be a list of one to four capabilities")
        action_name = entry.get("action", "block")
        if not isinstance(action_name, str) or action_name not in ACTION_MAP:
            raise ValueError(f"unknown capability sequence action: {action_name!r}")
        action = ACTION_MAP[action_name]
        cap_bytes = []
        for cap_name in seq:
            if not isinstance(cap_name, str) or cap_name not in CAP_MAP:
                raise ValueError(f"unknown capability: {cap_name!r}")
            cap_bytes.append(CAP_MAP[cap_name])
        rules.append((cap_bytes, action))
    return rules


def extract_dest_allowlist(policy: dict) -> list:
    """Extract destination allowlist from iot_extensions."""
    iot_ext = policy.get("iot_extensions", {})
    dest_list = iot_ext.get("destination_allowlist", [])
    if not isinstance(dest_list, list):
        raise ValueError("destination_allowlist must be a list")
    for dest in dest_list:
        _validate_no_null_bytes(str(dest), "destination allowlist entry")
    return dest_list


def extract_canary_baseline(policy: dict) -> int:
    """Extract canary baseline from iot_extensions."""
    iot_ext = policy.get("iot_extensions", {})
    canary = iot_ext.get("canary", {})
    baseline = canary.get("baseline_blocks_per_min", 5)
    if type(baseline) is not int or not 0 <= baseline <= 65535:
        raise ValueError("baseline_blocks_per_min must be an integer from 0 to 65535")
    return baseline


def generate_c_header(policy: dict, version: int) -> str:
    """Generate C header with compiled policy tables."""
    # Version is emitted as uint16_t in the C header
    if version > 65534:
        raise ValueError(f"Policy version {version} exceeds OTA maximum (65534; 65535 is reserved)")
    if version < 0:
        raise ValueError(f"Policy version {version} must be non-negative")

    severity_rules = extract_severity_rules(policy)
    sequence_rules = extract_sequence_rules(policy)
    dest_allowlist = extract_dest_allowlist(policy)

    lines = [
        '#ifndef DCLAW_POLICY_TABLES_H',
        '#define DCLAW_POLICY_TABLES_H',
        '',
        '/*',
        ' * Auto-generated by policy_compiler.py',
        f' * Policy version: {version}',
        ' * DO NOT EDIT MANUALLY',
        ' */',
        '',
        '#ifdef __GNUC__',
        '#pragma GCC diagnostic push',
        '#pragma GCC diagnostic ignored "-Wunused-variable"',
        '#endif',
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
        validate_destination(dest)
        lines.append(f'    "{escape_c_string(dest)}",')
    lines.append('};')
    lines.append(f'DCLAW_UNUSED static const size_t dest_allowlist_count = {len(dest_allowlist)};')
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
        # Sanitize pattern before embedding in C comment to prevent comment injection
        pat_safe = pat.replace("*/", "* /")
        lines.append(f'    {{ {cat}, {sev}, {flags}, {len(pat)} }},  /* "{pat_safe}" */')
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

    lines.append('#ifdef __GNUC__')
    lines.append('#pragma GCC diagnostic pop')
    lines.append('#endif')
    lines.append('')

    lines.append('#endif /* DCLAW_POLICY_TABLES_H */')
    lines.append('')

    return '\n'.join(lines)


def generate_binary_blob(policy: dict, version: int) -> bytes:
    """Generate signed binary policy blob for OTA delivery."""
    # struct.pack('>H', ...) silently truncates values exceeding uint16
    if version > 65534:
        raise ValueError(f"Policy version {version} exceeds OTA maximum (65534; 65535 is reserved)")
    if version < 0:
        raise ValueError(f"Policy version {version} must be non-negative")

    severity_rules = extract_severity_rules(policy)
    sequence_rules = extract_sequence_rules(policy)
    dest_allowlist = extract_dest_allowlist(policy)
    canary_baseline = extract_canary_baseline(policy)

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

    # Rule counts are stored as single bytes in the binary format
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
        validate_destination(dest)
        encoded = dest.encode('ascii')[:67]  # max 64 + 3 overhead
        payload.append(len(encoded))
        payload.extend(encoded)

    # Header: version(2) + payload_len(2) + canary_baseline(2) + reserved(2)
    header = struct.pack('>HHHxx', version, len(payload), canary_baseline)
    blob = header + payload

    return bytes(blob)


def sign_blob(blob: bytes, key_path: str) -> Tuple[bytes, bool]:
    """Sign blob with Ed25519. Returns (signature, is_unsigned) tuple.

    The signature is 65 bytes: 1-byte type marker + 64-byte signature.
    ``is_unsigned`` is True when the dev stub path was used.
    """
    if key_path and os.path.exists(key_path):
        try:
            import nacl.signing
            with open(key_path, 'rb') as f:
                key_data = f.read()
            if len(key_data) < 32:
                raise ValueError(f"Signing key file too short ({len(key_data)} bytes, need >= 32)")
            signing_key = nacl.signing.SigningKey(key_data[:32])
            signed = signing_key.sign(blob)
            # Prepend signature type marker so consumers know this is Ed25519
            return bytes([SIGNATURE_TYPE_ED25519]) + signed.signature, False
        except ImportError:
            print("WARNING: PyNaCl not installed. Using dev stub signature.",
                  file=sys.stderr)
            # Refuse silent fallback to dev stub in production mode
            if os.environ.get("DCLAW_PRODUCTION", "").lower() in ("1", "true", "yes"):
                raise RuntimeError(
                    "PyNaCl is required for signing in production mode "
                    "(DCLAW_PRODUCTION is set). Install with: pip install pynacl"
                )
            if os.environ.get("DCLAW_DEV_MODE", "").strip().lower() in ("off", "0", "false", "no"):
                raise RuntimeError(
                    "PyNaCl is required for signing when DCLAW_DEV_MODE=OFF. "
                    "Install with: pip install pynacl"
                )

    # Also enforce when no key_path is provided at all
    if os.environ.get("DCLAW_PRODUCTION", "").lower() in ("1", "true", "yes"):
        raise RuntimeError(
            "Signing key is required in production mode (DCLAW_PRODUCTION is set). "
            "Provide --signing-key with a valid Ed25519 key."
        )
    if os.environ.get("DCLAW_DEV_MODE", "").strip().lower() in ("off", "0", "false", "no"):
        raise RuntimeError(
            "Signing key is required when DCLAW_DEV_MODE=OFF. "
            "Provide --signing-key with a valid Ed25519 key."
        )

    # Make unsigned blobs visible in CI/CD logs
    print("WARNING: No signing key provided and DCLAW_PRODUCTION is not set. "
          "Using dev stub signature — the resulting policy.bin is NOT "
          "cryptographically signed and will be rejected by production devices.",
          file=sys.stderr)
    logger.warning("SECURITY: policy signed with dev stub — NOT suitable for production")

    # Dev stub signature format (64 bytes):
    #   byte 0:     SIGNATURE_TYPE_DEV (0x00) — type marker
    #   byte 1:     0xDE  — "dev" marker (Go policy.go checks sig[1] for fast detection)
    #   byte 2:     0xED  — legacy marker (kept for backward compat)
    #   bytes 3-34: SHA-256(blob) (32 bytes)
    #   bytes 35-63: zero padding (29 bytes)
    #
    # policy.go detects this stub by checking sig[0]==0x00, sig[1]==0xDE,
    # sig[2]==0xED, sig[3:35]==SHA-256(unsigned) and strips it before
    # appending the real HMAC signature.
    digest = hashlib.sha256(blob).digest()  # 32 bytes
    sig = bytes([SIGNATURE_TYPE_DEV]) + b'\xDE\xED' + digest + b'\x00' * (61 - len(digest))
    return sig, True


def compute_size_report(c_header: str, binary_blob: bytes, profile: str,
                        profile_limits: Optional[dict] = None) -> str:
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


def _validate_output_path(path: str, label: str) -> str:
    """Reject output paths that traverse outside the working directory."""
    normalized = os.path.normpath(path)
    if ".." in normalized:
        raise SystemExit(f"Error: {label} path contains '..': {path}")
    # Absolute paths could escape the working directory
    if os.path.isabs(normalized):
        raise SystemExit(f"Error: {label} path must be relative: {path}")
    resolved = os.path.abspath(normalized)
    cwd = os.getcwd()
    if not resolved.startswith(cwd + os.sep) and resolved != cwd:
        raise SystemExit(f"Error: {label} path escapes working directory: {path}")
    return normalized


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

    _validate_output_path(args.output_header, "--output-header")
    _validate_output_path(args.output_binary, "--output-binary")
    if args.output_report:
        _validate_output_path(args.output_report, "--output-report")

    limits = dict(PROFILE_LIMITS)
    if args.target_partition_size > 0:
        limits[args.profile] = args.target_partition_size

    # Invalid input has a distinct exit status so API callers can return a
    # client error without misclassifying missing tools or filesystem faults.
    try:
        policy = parse_policy(Path(args.input))
        if not isinstance(policy, dict):
            raise ValueError("policy root must be a YAML mapping")
        for field in ("name", "description"):
            if field in policy and not isinstance(policy[field], str):
                raise ValueError(f"{field} must be a string")
        validate_policy_extensions(policy)
        c_header = generate_c_header(policy, args.version)
        blob = generate_binary_blob(policy, args.version)
    except OSError as exc:
        print(f"Cannot read policy input: {exc}", file=sys.stderr)
        return 1
    except (yaml.YAMLError, ValueError, TypeError, AttributeError) as exc:
        print(f"Invalid policy: {exc}", file=sys.stderr)
        return 65  # EX_DATAERR

    partition_limit = limits[args.profile]
    if len(blob) > partition_limit - 64:
        print(f"Invalid policy: blob plus 64-byte signature exceeds {args.profile} partition limit "
              f"({len(blob)} + 64 > {partition_limit} bytes)", file=sys.stderr)
        return 65

    print(f"Parsed policy: {policy.get('name', 'unnamed')}")
    signature, is_unsigned = sign_blob(blob, args.signing_key)
    signed_blob = blob + signature
    if is_unsigned:
        # Callers detect dev-stub blobs via the SIGNATURE_TYPE_DEV marker byte
        logger.info("Policy blob is unsigned (dev stub signature)")

    os.makedirs(os.path.dirname(args.output_header) or '.', exist_ok=True)
    with open(args.output_header, 'w') as f:
        f.write(c_header)
    print(f"Generated C header: {args.output_header} ({len(c_header)} bytes)")

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

    return 0


if __name__ == '__main__':
    sys.exit(main())
