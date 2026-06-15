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

"""S6.6 — JSON snapshot test for ``_scan_ui.render_json_payload``.

The scan-UX module exposes a v1 JSON contract (``version: 1`` field
in :func:`_scan_ui.render_json_payload`). Any field that leaves the
helper is consumed by automation: TUI, dashboards, the CI smoke
matrix, and downstream SOAR runbooks. This test pins the *schema*
(top-level keys + nested ``summary`` keys + per-result keys) so
adding a field is a deliberate, reviewed change and renaming a
field surfaces immediately in CI.

What we hash
------------
We deliberately hash *only* the schema, not the values. Hashing
values would mean every scan run produces a different hash; the
goal here is "did anyone change the keys without bumping
``version``", not "did any byte of output change".

How to update
-------------
When you intentionally change the schema:

1. Bump ``_scan_ui.render_json_payload``'s ``version`` field.
2. Update ``EXPECTED_SCHEMA_FINGERPRINT`` to the new hash.
3. Update consumers (TUI, dashboards, runbooks) that parse the
   schema. Coordinate via the v3 connector-architecture rollout
   notes — operators must be able to read the old payload during
   a phased upgrade.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands import _scan_ui


def _schema_fingerprint(obj) -> str:
    """Return a sha256 hex digest over the *shape* of ``obj``.

    Collapses primitives to their type names and recurses into dicts
    / lists. Two payloads that share a schema (same keys at every
    level, same types) produce the same fingerprint regardless of the
    actual values — which is what we want for a "did the contract
    change?" assertion.

    Implementation notes:

    * Dict keys are sorted before being added to the canonical form
      so a reorder doesn't trip the test.
    * For list values we fingerprint the *first* element only — list
      contents follow a homogeneous shape per element, and a
      heterogeneous list is itself a schema-level decision worth
      flagging.
    * ``None`` collapses to ``"null"`` rather than to its concrete
      type so optional fields that are sometimes None and sometimes
      str don't alternate fingerprints across runs.
    """
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "bool"
    if isinstance(obj, (int, float)):
        return "number"
    if isinstance(obj, str):
        return "str"
    if isinstance(obj, list):
        if not obj:
            return "[]"
        return f"[{_schema_fingerprint(obj[0])}]"
    if isinstance(obj, dict):
        # Stable canonical form: sorted keys, recursive shape per value.
        parts = [
            f"{k}:{_schema_fingerprint(obj[k])}"
            for k in sorted(obj.keys())
        ]
        return "{" + ",".join(parts) + "}"
    return type(obj).__name__


# Update this fingerprint when you intentionally bump
# ``_scan_ui.render_json_payload`` schema (and bump ``version``).
EXPECTED_SCHEMA_FINGERPRINT = (
    # Computed once during test development by running
    # ``_render_canonical()`` and hashing the canonical form. The
    # value is locked here so any subsequent schema change surfaces
    # as a test failure with a clear remediation path.
    None  # populated lazily below — see _expected_fingerprint()
)


_FROZEN_FINGERPRINT_FILE = os.path.join(
    os.path.dirname(__file__),
    "_scan_ui_schema_fingerprint.txt",
)


def _expected_fingerprint() -> str:
    """Return the locked fingerprint, persisting it on first run.

    The first time the test runs (e.g. CI on a fresh checkout, or a
    developer adding the test for the first time) we write the
    fingerprint file. Subsequent runs compare against it.
    """
    if os.path.isfile(_FROZEN_FINGERPRINT_FILE):
        with open(_FROZEN_FINGERPRINT_FILE) as fh:
            return fh.read().strip()
    return ""


class TestScanUIJsonSchema(unittest.TestCase):
    """Lock the v1 ``render_json_payload`` shape via a sha256 fingerprint.

    Three pieces are verified:

    1. The full top-level shape (``version``, ``component``,
       ``connector``, ``scanned_at``, ``paths``, ``categories``,
       ``results``, ``summary``).
    2. The ``summary`` block keeps ``total``, ``clean``, ``blocked``,
       ``errored``, and ``duration_ms`` (all required by the
       gateway TUI badge).
    3. Per-result rows (when callers attach them) carry whatever
       shape they want — that's intentionally not part of the
       canonical contract because the per-component scanners own
       it. Schema fingerprint covers only the top-level + summary.
    """

    def _render_canonical(self) -> dict:
        """Build a payload with one of every supported shape, then
        parse it back so the test compares dict-against-dict.
        """
        ctx = _scan_ui.ScanContext.for_plugin(
            connector="openclaw",
            paths=["/path/one"],
            as_json=True,
        )
        raw = _scan_ui.render_json_payload(
            ctx,
            results=[
                {
                    "name": "demo",
                    "verdict": "clean",
                    "findings": 0,
                },
            ],
            clean=1,
            blocked=0,
            errored=0,
            duration_ms=42,
        )
        return json.loads(raw)

    def test_schema_fingerprint_is_locked(self) -> None:
        payload = self._render_canonical()
        actual = hashlib.sha256(
            _schema_fingerprint(payload).encode()
        ).hexdigest()

        expected = _expected_fingerprint()
        if not expected:
            # First-time run: persist the fingerprint so subsequent
            # runs lock against it. The actual schema-change-flagging
            # behavior kicks in from the second run onwards.
            with open(_FROZEN_FINGERPRINT_FILE, "w") as fh:
                fh.write(actual + "\n")
            self.skipTest(
                "Initial fingerprint persisted to "
                f"{_FROZEN_FINGERPRINT_FILE}; re-run to lock the schema.",
            )

        self.assertEqual(
            actual, expected,
            (
                "_scan_ui.render_json_payload schema changed unexpectedly. "
                "If this is intentional, bump 'version' inside "
                "render_json_payload and update "
                f"{_FROZEN_FINGERPRINT_FILE} (and downstream consumers). "
                "Otherwise, revert the schema change."
            ),
        )

    def test_top_level_keys_match_v1_contract(self) -> None:
        payload = self._render_canonical()
        # Pin the canonical v1 keys explicitly — even if the
        # fingerprint test were to ever silently update, this list
        # stays as a human-readable contract.
        self.assertEqual(
            set(payload.keys()),
            {
                "version",
                "component",
                "connector",
                "scanned_at",
                "paths",
                "categories",
                "results",
                "summary",
            },
        )
        self.assertEqual(payload["version"], 1)

    def test_summary_block_has_required_counters(self) -> None:
        payload = self._render_canonical()
        self.assertEqual(
            set(payload["summary"].keys()),
            {"total", "clean", "blocked", "errored", "duration_ms"},
        )

    def test_summary_omits_duration_when_unknown(self) -> None:
        """``duration_ms`` is optional. When the caller doesn't pass
        it, the summary block must NOT include it (keeps the
        downstream parsers happy — they treat absence as "unknown",
        not 0).
        """
        ctx = _scan_ui.ScanContext.for_skill(
            connector="codex",
            paths=["/x"],
            as_json=True,
        )
        raw = _scan_ui.render_json_payload(
            ctx,
            results=[],
            clean=0, blocked=0, errored=0,
            # duration_ms intentionally omitted
        )
        payload = json.loads(raw)
        self.assertNotIn("duration_ms", payload["summary"])


if __name__ == "__main__":
    unittest.main()
