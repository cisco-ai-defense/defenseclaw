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

"""Schema parity between the docs-site policy creator and the CLI loader.

Why this test exists
--------------------
The policy creator at ``docs-site/components/policy-creator/lib/emit.ts``
writes a YAML document. The CLI at ``cli/defenseclaw/commands/cmd_policy.py``
reads that same document. There is no shared schema definition — both
sides hand-maintain their picture of the document. The crash mode this
test guards against is the silent one: a future PR adds a new field to
``emit.ts``, ships it to docs-site, operators paste it into a policy
YAML, and the CLI loader silently drops the field because no ``.get(...)``
call references it. The operator sees the gateway "ignoring" their
configuration with no error.

What this test does
-------------------
1. Parse ``emit.ts`` for the top-level keys written into ``policyYaml``
   (the literal that becomes ``~/.defenseclaw/policies/<name>.yaml``).
2. Parse ``cmd_policy.py`` with ``ast`` and collect every string key
   passed to ``data.get(...)`` or ``policy_data.get(...)`` inside the
   activate / sync functions. These are the keys the loader *consumes*.
3. Assert every emit-side key is consumed by at least one loader getter
   (the converse is fine: the loader is allowed to read keys that the
   creator doesn't emit, e.g. legacy fields that we still tolerate).

What this test does NOT do
--------------------------
- Sub-field drift inside nested objects (e.g. JudgeConfig.min_categories_*).
  Covered by per-feature golden tests.
- Value-level validation. Whether a key is set to a legal value is the
  job of the engine and its loaders.
- "Loader reads a key that's never emitted." That's allowed: legacy
  fields stay readable for backward compatibility.
"""

from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
EMIT_TS = REPO_ROOT / "docs-site" / "components" / "policy-creator" / "lib" / "emit.ts"
CMD_POLICY_PY = REPO_ROOT / "cli" / "defenseclaw" / "commands" / "cmd_policy.py"


def _extract_emit_top_level_keys(emit_src: str) -> set[str]:
    """Return the top-level keys assembled by emit.ts::emit() into ``policyYaml``.

    We walk from the literal ``const policyYaml = {`` to its matching
    closing brace, then scan only depth-1 ``identifier:`` tokens (we
    skip identifiers inside nested ``{`` or ``[``). This matters
    because ``guardrail:`` contains a nested object whose keys
    (``block_threshold``, ``hilt``, …) are NOT top-level policy YAML
    fields and the loader is correct to read them via
    ``guardrail.get(...)`` rather than ``data.get("block_threshold")``.

    We also pick up the conditional ``cisco_ai_defense`` block that is
    spread in via ``...aidBlock``.
    """
    keys: set[str] = set()

    m = re.search(r"const\s+policyYaml\s*=\s*\{", emit_src)
    if not m:
        raise AssertionError(
            "emit.ts: could not find `const policyYaml = {` — refactor of "
            "emit() needs a matching update to this parity test"
        )
    obj_start = m.end()
    # Find the matching brace.
    depth = 1
    i = obj_start
    while i < len(emit_src) and depth > 0:
        ch = emit_src[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        i += 1
    obj_body = emit_src[obj_start : i - 1]

    # Token-level scan: only collect "identifier:" tokens that occur at
    # depth 0 within the outer policyYaml object. We track {} and []
    # depth and skip over JS string literals so colons inside strings
    # don't confuse us. Comments are not stripped because emit() doesn't
    # use any in this literal; if that ever changes the assertion
    # floor below catches the regression.
    j = 0
    inner_depth = 0
    in_str: str | None = None
    while j < len(obj_body):
        ch = obj_body[j]
        if in_str is not None:
            if ch == "\\" and j + 1 < len(obj_body):
                j += 2
                continue
            if ch == in_str:
                in_str = None
            j += 1
            continue
        if ch in ('"', "'", "`"):
            in_str = ch
            j += 1
            continue
        if ch in "{[":
            inner_depth += 1
            j += 1
            continue
        if ch in "}]":
            inner_depth -= 1
            j += 1
            continue
        # At depth 0, look for "identifier:" — but only when the
        # character immediately before the identifier is `,`, `{`, or
        # whitespace at the start. This rejects identifiers that
        # appear on the right-hand side of an expression
        # (e.g. `policy.firewall`).
        if inner_depth == 0:
            id_match = re.match(r"([a-z_][a-z0-9_]*)\s*:", obj_body[j:])
            if id_match:
                # Verify the preceding non-space char is `{` or `,` or
                # we're at the start of the literal — otherwise this is
                # a property access on a longer expression.
                k = j - 1
                while k >= 0 and obj_body[k] in " \t\r\n":
                    k -= 1
                prev_ch = obj_body[k] if k >= 0 else "{"
                if prev_ch in "{,":
                    keys.add(id_match.group(1))
                j += id_match.end()
                continue
        j += 1

    # The conditional aidBlock spread emits `cisco_ai_defense` as the
    # *outer* key when the AID lane is on. Pull it in explicitly.
    if "...aidBlock" in obj_body and re.search(
        r"cisco_ai_defense:\s*\{", emit_src
    ):
        keys.add("cisco_ai_defense")

    return keys


def _extract_loader_consumed_keys(py_src: str) -> set[str]:
    """Return the set of keys read via ``data.get(...)`` or
    ``policy_data.get(...)`` in cmd_policy.py.

    We deliberately don't restrict to specific functions — anything in
    the file is fair game, because a future refactor could split the
    loader into helpers and we don't want the parity check to
    false-positive based on which function holds the getter.
    """
    tree = ast.parse(py_src, filename=str(CMD_POLICY_PY))
    consumed: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        # data.get("foo", ...) or policy_data.get("foo", ...)
        if not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "get":
            continue
        if not isinstance(node.func.value, ast.Name):
            continue
        if node.func.value.id not in {"data", "policy_data"}:
            continue
        if not node.args:
            continue
        key = node.args[0]
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            consumed.add(key.value)
    return consumed


# Top-level emit keys that the CLI loader doesn't need to consume —
# they're either metadata the loader reads via Path().stem fallbacks
# (`name`, `description`) or composite objects whose handling lives in
# different layers. Document each exemption so future readers know the
# intent rather than guessing.
KEYS_LOADER_NEED_NOT_CONSUME = {
    # Emitted as a stable identity / display field; CLI reads it via
    # data.get("name", Path(path).stem) so the *fallback* path covers
    # the case where the field is missing.
    "name",
    # Free-form documentation; CLI surfaces but doesn't act on it.
    "description",
    # `scanners` in the playground is currently a thin
    # ScannerProfileSelection placeholder ("full inline overrides ship
    # in a later phase" per types.ts) and the operator-facing UI does
    # not yet wire it to anything user-editable. When that ships, drop
    # this exemption and route the field through `activate()` so
    # `app.cfg.scanners` is updated. Tracked in the docs-site policy
    # creator roadmap.
    "scanners",
}


class TestPlaygroundSchemaParity(unittest.TestCase):
    """C1: every top-level field the playground emits must be a field
    the CLI loader knows how to consume. Without this lint we'd ship
    silent data-loss bugs whenever the TS and Python sides drift."""

    def test_every_emit_key_is_consumed_by_loader(self) -> None:
        emit_src = EMIT_TS.read_text(encoding="utf-8")
        py_src = CMD_POLICY_PY.read_text(encoding="utf-8")

        emit_keys = _extract_emit_top_level_keys(emit_src)
        loader_keys = _extract_loader_consumed_keys(py_src)

        # Sanity floor: if our parsers regress and silently extract
        # nothing, every assert below would pass vacuously. Surface
        # that as a hard failure instead.
        self.assertGreater(
            len(emit_keys),
            5,
            f"parity test regressed: extracted only {sorted(emit_keys)} from emit.ts. "
            f"Check that the policyYaml literal still exists.",
        )
        self.assertGreater(
            len(loader_keys),
            5,
            f"parity test regressed: extracted only {sorted(loader_keys)} from cmd_policy.py. "
            f"Check that data.get(...) / policy_data.get(...) callsites still exist.",
        )

        unconsumed = emit_keys - loader_keys - KEYS_LOADER_NEED_NOT_CONSUME
        self.assertEqual(
            unconsumed,
            set(),
            f"Playground emit.ts writes the following top-level keys that "
            f"cmd_policy.py never reads: {sorted(unconsumed)}. Operators "
            f"will silently lose these fields when they run `defenseclaw "
            f"policy activate`. Either:\n"
            f"  1. Add a data.get(...)/policy_data.get(...) callsite in "
            f"cmd_policy.py, or\n"
            f"  2. Remove the key from emit.ts::emit() if it's intentionally "
            f"unsupported, or\n"
            f"  3. If this is a known-safe exemption, add it to "
            f"KEYS_LOADER_NEED_NOT_CONSUME with a justification comment.",
        )


if __name__ == "__main__":  # pragma: no cover — runs under unittest discovery
    unittest.main()
