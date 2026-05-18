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

"""Regression tests for the F5 fix: ``Config.save()`` must round-trip
through the existing on-disk YAML so that operator-configured but
Python-dataclass-UNmodelled keys (``audit_sinks:``,
``otel.resource.attributes:``) survive every ``defenseclaw setup
<connector>`` invocation.

Before this fix, a typical operator workflow silently broke their SIEM
forwarding:

    1. ``defenseclaw setup splunk --logs``  → adds ``audit_sinks: [...]``
    2. ``defenseclaw setup codex``          → calls ``cfg.save()`` →
                                              dataclass-only serializer
                                              dropped the whole block
    3. Splunk dashboards go dark; nothing logs the rewrite.

The fix in ``config.py::Config.save`` reads the existing file, deep-merges
the dataclass output over it, and atomically replaces the file. These
tests assert each behaviour the merge contract promises, including the
"dataclass-still-owns-its-keys" invariant so the byte-stability strips
in ``_config_to_dict`` (legacy ``splunk:`` v4 drop, ``notifications:``
at-defaults drop, etc.) keep working.
"""

import logging
import os
import sys
import tempfile
import unittest

import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.config import (  # noqa: E402
    Config,
    GatewayConfig,
    NotificationsConfig,
    _deep_merge_nested,
    _load_existing_config_yaml,
    _merge_preserving_unmodeled,
    _owned_top_level_keys,
)


def _make_cfg(tmpdir: str, **overrides) -> Config:
    """Build a Config with the minimum required path fields for tests."""
    base: dict = {
        "data_dir": tmpdir,
        "audit_db": os.path.join(tmpdir, "audit.db"),
        "quarantine_dir": os.path.join(tmpdir, "quarantine"),
        "plugin_dir": os.path.join(tmpdir, "plugins"),
        "policy_dir": os.path.join(tmpdir, "policies"),
        "environment": "macos",
    }
    base.update(overrides)
    return Config(**base)


class TestConfigSaveRoundtripPreservesAuditSinks(unittest.TestCase):
    """The core F5 regression: ``audit_sinks:`` must survive ``cfg.save()``.

    Reproduces the operator workflow that previously caused silent
    data loss on every connector switch.
    """

    def test_audit_sinks_block_survives_dataclass_save(self):
        """Pre-existing ``audit_sinks:`` block stays intact after ``cfg.save()``."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            # Simulate `defenseclaw setup splunk --logs` having written
            # the file: dataclass fields + an unmodeled audit_sinks list.
            seeded = {
                "data_dir": tmpdir,
                "environment": "macos",
                "audit_sinks": [
                    {
                        "name": "splunk-hec-localhost",
                        "kind": "splunk_hec",
                        "enabled": True,
                        "splunk_hec": {
                            "endpoint": "http://127.0.0.1:8088/services/collector/event",
                            "token_env": "SPLUNK_HEC_TOKEN",
                            "index": "defenseclaw",
                            "source": "defenseclaw",
                            "sourcetype": "_json",
                            "verify_tls": False,
                        },
                    },
                ],
            }
            with open(cfg_path, "w") as f:
                yaml.safe_dump(seeded, f, sort_keys=False)

            # Now mimic `defenseclaw setup codex` changing a modeled
            # field (claw mode) and calling cfg.save().
            cfg = _make_cfg(tmpdir)
            cfg.claw.mode = "codex"
            cfg.save()

            with open(cfg_path) as f:
                after = yaml.safe_load(f)

        self.assertIn(
            "audit_sinks", after,
            msg=(
                "audit_sinks block was stripped by Config.save() — this is "
                "the F5 regression that broke Splunk forwarding on every "
                "connector switch."
            ),
        )
        self.assertEqual(len(after["audit_sinks"]), 1)
        sink = after["audit_sinks"][0]
        self.assertEqual(sink["name"], "splunk-hec-localhost")
        self.assertEqual(sink["kind"], "splunk_hec")
        self.assertTrue(sink["enabled"])
        self.assertEqual(
            sink["splunk_hec"]["endpoint"],
            "http://127.0.0.1:8088/services/collector/event",
        )
        self.assertEqual(after["claw"]["mode"], "codex")

    def test_multiple_audit_sinks_all_preserved(self):
        """Multi-sink configs (Splunk + remote HEC + webhook) survive intact."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            seeded = {
                "data_dir": tmpdir,
                "audit_sinks": [
                    {"name": "splunk-hec-localhost", "kind": "splunk_hec",
                     "enabled": True, "splunk_hec": {"endpoint": "http://h:8088"}},
                    {"name": "splunk-enterprise-corp", "kind": "splunk_hec",
                     "enabled": False, "splunk_hec": {"endpoint": "https://corp:8088"}},
                    {"name": "webhook-soc", "kind": "http_jsonl",
                     "enabled": True, "http_jsonl": {"url": "https://soc.example.com/ingest"}},
                ],
            }
            with open(cfg_path, "w") as f:
                yaml.safe_dump(seeded, f, sort_keys=False)

            cfg = _make_cfg(tmpdir)
            cfg.save()

            with open(cfg_path) as f:
                after = yaml.safe_load(f)

        names = [s["name"] for s in after["audit_sinks"]]
        self.assertEqual(
            names,
            ["splunk-hec-localhost", "splunk-enterprise-corp", "webhook-soc"],
            msg="audit_sinks order or content was disturbed",
        )


class TestConfigSaveRoundtripPreservesNestedKeys(unittest.TestCase):
    """The deep-merge rescues operator-added unmodelled subkeys (e.g. a
    custom ``otel.exporter.foo``) without disturbing dataclass-owned
    siblings. Modelled dict-typed leaves like ``otel.headers`` and
    ``otel.resource.attributes`` are NOT in this preserve set —
    they're dataclass-authoritative on save (see
    :class:`TestConfigSaveAuthoritativeNestedDicts`)."""

    def test_otel_round_trip_preserves_attributes_when_dataclass_loads_them(self):
        """A load → save with no edits preserves operator-set
        otel.resource.attributes. The dataclass loader (_merge_otel)
        copies headers / attributes from the YAML, so the dataclass
        round-trip output already contains them; the new
        authoritative-path replace happens with the same content,
        leaving the file functionally unchanged. This test guards
        the load+save no-op path (the operator-friendly case)."""
        from defenseclaw.config import (
            OTelConfig,
            OTelResourceConfig,
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            with open(cfg_path, "w") as f:
                yaml.safe_dump({"data_dir": tmpdir, "environment": "macos"}, f)

            # Construct the Config with otel populated as if the
            # loader had read the YAML — we deliberately bypass the
            # module-level `load()` so the test is hermetic and
            # independent of $HOME / $DEFENSECLAW_HOME.
            cfg = _make_cfg(
                tmpdir,
                otel=OTelConfig(
                    enabled=True,
                    protocol="http",
                    resource=OTelResourceConfig(
                        attributes={
                            "defenseclaw.preset": "splunk-o11y",
                            "defenseclaw.preset_name": "Splunk Observability Cloud",
                            "service.name": "defenseclaw-gateway",
                        },
                    ),
                ),
            )
            cfg.save()

            with open(cfg_path) as f:
                after = yaml.safe_load(f)

        self.assertIn("resource", after["otel"])
        self.assertIn("attributes", after["otel"]["resource"])
        attrs = after["otel"]["resource"]["attributes"]
        self.assertEqual(attrs["defenseclaw.preset"], "splunk-o11y")
        self.assertEqual(attrs["service.name"], "defenseclaw-gateway")

    def test_unmodelled_otel_subkeys_survive(self):
        """Operator-added subkeys that the dataclass does NOT model —
        e.g. a forward-compat ``otel.exporter.foo`` block — survive a
        save where the dataclass leaves the parent ``otel`` block
        otherwise default. The recursion still preserves unmodelled
        keys at non-authoritative paths; only the explicit
        ``otel.headers`` / ``otel.resource.attributes`` paths are
        replace-on-save."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            seeded = {
                "data_dir": tmpdir,
                "otel": {
                    "exporter": {"foo": {"enabled": True, "extra": "bar"}},
                },
            }
            with open(cfg_path, "w") as f:
                yaml.safe_dump(seeded, f, sort_keys=False)

            cfg = _make_cfg(tmpdir)
            cfg.save()

            with open(cfg_path) as f:
                after = yaml.safe_load(f)

        self.assertIn("exporter", after.get("otel", {}))
        self.assertEqual(after["otel"]["exporter"]["foo"]["extra"], "bar")


class TestConfigSaveAuthoritativeNestedDicts(unittest.TestCase):
    """Security regression suite for the second P1 finding: when the
    Python dataclass intentionally clears a modeled
    secret-bearing dict (``cfg.otel.headers = {}`` for OTLP
    credential rotation; ``cfg.otel.resource.attributes = {}`` for
    tenant-identifier flip), the on-disk file MUST reflect the
    clear. The pre-fix deep-merge preserved file keys whenever
    ``new`` was empty, leaving stale ``Authorization`` headers and
    stale ``service.name`` resource attributes on disk."""

    def test_otel_headers_clear_overwrites_existing_authorization(self):
        from defenseclaw.config import OTelConfig
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            seeded = {
                "data_dir": tmpdir,
                "otel": {
                    "enabled": True,
                    "headers": {
                        # not a real token — placeholder that
                        # would be a credential-class leak if it
                        # survived a clear
                        "Authorization": "Bearer test-stale-rotated-out",
                        "x-honeycomb-team": "team-stale",
                    },
                },
            }
            with open(cfg_path, "w") as f:
                yaml.safe_dump(seeded, f, sort_keys=False)

            # Simulate an operator rotating credentials by
            # clearing headers explicitly.
            cfg = _make_cfg(
                tmpdir,
                otel=OTelConfig(enabled=True, headers={}),
            )
            cfg.save()

            with open(cfg_path) as f:
                after = yaml.safe_load(f)

        headers = after.get("otel", {}).get("headers", {})
        self.assertNotIn(
            "Authorization", headers,
            msg=("stale Authorization header survived an explicit "
                 "cfg.otel.headers={} save — credential leak across rotation"),
        )
        self.assertNotIn("x-honeycomb-team", headers)
        # The dataclass-emitted empty dict is allowed to render as
        # `headers: {}` or to be stripped entirely; both encode
        # "no headers". We only require the stale keys are gone.
        self.assertEqual(headers, {})

    def test_otel_resource_attributes_clear_drops_service_name(self):
        from defenseclaw.config import (
            OTelConfig,
            OTelResourceConfig,
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            seeded = {
                "data_dir": tmpdir,
                "otel": {
                    "enabled": True,
                    "resource": {
                        "attributes": {
                            "service.name": "tenant-old",
                            "deployment.environment": "prod-east",
                        },
                    },
                },
            }
            with open(cfg_path, "w") as f:
                yaml.safe_dump(seeded, f, sort_keys=False)

            cfg = _make_cfg(
                tmpdir,
                otel=OTelConfig(
                    enabled=True,
                    resource=OTelResourceConfig(attributes={}),
                ),
            )
            cfg.save()

            with open(cfg_path) as f:
                after = yaml.safe_load(f)

        attrs = after.get("otel", {}).get("resource", {}).get("attributes", {})
        self.assertNotIn(
            "service.name", attrs,
            msg=("stale service.name attribute survived an explicit "
                 "attributes={} save — tenant identifier leak"),
        )
        self.assertEqual(attrs, {})


class TestConfigSavePreservesFileMode(unittest.TestCase):
    """P1 security regression: ``Config.save()`` must NOT widen the
    file mode of an existing config.yaml. The pre-fix path opened
    a temp via ``open(tmp, 'w')`` (umask-honoring, typically 0644)
    and ``os.replace``d it onto a 0600 live file, silently
    downgrading the mode to 0644 — exposing gateway / OTLP
    credentials carried in the file (e.g. ``gateway.token``,
    ``otel.headers.Authorization``)."""

    def test_save_preserves_existing_0600_mode(self):
        """A 0600 config.yaml stays 0600 across save."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            with open(cfg_path, "w") as f:
                yaml.safe_dump({"data_dir": tmpdir, "environment": "macos"}, f)
            os.chmod(cfg_path, 0o600)

            cfg = _make_cfg(tmpdir)
            cfg.save()

            mode = os.stat(cfg_path).st_mode & 0o777
        self.assertEqual(
            mode, 0o600,
            msg=("Config.save widened mode to %o; pre-fix umask-honoring "
                 "open() leaked secrets to group/other readers" % mode),
        )

    def test_save_first_create_is_0600(self):
        """A first-save (no pre-existing file) lands at 0600 — the
        explicit O_EXCL + 0o600 mode in os.open ensures the umask
        cannot widen the new file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            self.assertFalse(os.path.exists(cfg_path))

            cfg = _make_cfg(tmpdir)
            cfg.save()

            self.assertTrue(os.path.exists(cfg_path))
            mode = os.stat(cfg_path).st_mode & 0o777
        self.assertEqual(
            mode, 0o600,
            msg=("First-save mode = %o (want 0o600). Process umask "
                 "must not widen the new file." % mode),
        )

    def test_save_does_not_widen_stricter_existing_mode(self):
        """A 0400 (read-only) config.yaml is not widened to 0600.
        Some operators ship 0400 by policy; save must narrow on
        existing-mode mirror, never widen."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            with open(cfg_path, "w") as f:
                yaml.safe_dump({"data_dir": tmpdir, "environment": "macos"}, f)
            os.chmod(cfg_path, 0o400)
            # Make parent dir writable so os.replace can rename.
            os.chmod(tmpdir, 0o700)

            cfg = _make_cfg(tmpdir)
            cfg.save()

            mode = os.stat(cfg_path).st_mode & 0o777
        # 0o400 is the stricter case — `target_mode = existing & 0o600 = 0o400`
        # so the live file lands at 0o400.
        self.assertEqual(
            mode, 0o400,
            msg=("Config.save widened 0o400 to %o; mode mirror was "
                 "supposed to narrow-only, not widen." % mode),
        )

    def test_save_strips_world_readable_bits_on_legacy_0644(self):
        """If a pre-fix install left the file at 0644 (the bug we're
        fixing), the next save with this code MUST narrow it back to
        0600. This is the upgrade path: an operator running a fixed
        sidecar should see their leaky 0644 file fixed on the next
        ``defenseclaw setup`` invocation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            with open(cfg_path, "w") as f:
                yaml.safe_dump({"data_dir": tmpdir, "environment": "macos"}, f)
            os.chmod(cfg_path, 0o644)

            cfg = _make_cfg(tmpdir)
            cfg.save()

            mode = os.stat(cfg_path).st_mode & 0o777
        # existing & 0o600 = 0o600, so the live file should narrow
        # from 0o644 to 0o600.
        self.assertEqual(
            mode, 0o600,
            msg=("Save did not narrow legacy 0o644 to 0o600; got %o. "
                 "Upgrade path leaves credentials world-readable." % mode),
        )


class TestConfigSaveDataclassStillWins(unittest.TestCase):
    """The merge must NOT silently keep stale modeled values. When the
    dataclass intentionally omits a key (default-strip in
    ``_config_to_dict`` or legacy-drop of ``splunk:``), the on-disk file
    must reflect that omission."""

    def test_legacy_splunk_block_is_dropped_on_save(self):
        """v4 migration: top-level ``splunk:`` is rejected by the Go gateway.

        If the operator's file still has it (e.g. upgrading from a very
        old v4 install), ``Config.save`` must strip it on the next save
        even though the file has more content than the dataclass output.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            seeded = {
                "data_dir": tmpdir,
                "splunk": {  # legacy v4 — must NOT survive a save
                    "enabled": True,
                    "hec_url": "https://old.example.com/services/collector",
                    "hec_token": "stale",
                },
            }
            with open(cfg_path, "w") as f:
                yaml.safe_dump(seeded, f, sort_keys=False)

            cfg = _make_cfg(tmpdir)
            cfg.save()

            with open(cfg_path) as f:
                after = yaml.safe_load(f)

        self.assertNotIn(
            "splunk", after,
            msg=(
                "Legacy splunk: key survived save — the Go gateway will "
                "refuse to start with a v4 migration error. See "
                "internal/config/config.go::detectLegacySplunk."
            ),
        )

    def test_default_notifications_block_does_not_resurrect(self):
        """``_config_to_dict`` strips ``notifications:`` when it equals
        defaults. If the file had a non-default block but the operator
        explicitly reset it (``cfg.notifications = NotificationsConfig()``),
        the on-disk file must show the reset, not the old non-default
        block resurrected from the file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            seeded = {
                "data_dir": tmpdir,
                "notifications": {
                    "enabled": True,
                    "categories": {"policy": False},
                },
            }
            with open(cfg_path, "w") as f:
                yaml.safe_dump(seeded, f, sort_keys=False)

            cfg = _make_cfg(tmpdir)
            cfg.notifications = NotificationsConfig()  # explicit reset
            cfg.save()

            with open(cfg_path) as f:
                after = yaml.safe_load(f)

        self.assertNotIn(
            "notifications", after,
            msg=(
                "Operator-reset of a modeled key was overridden by the "
                "file — round-trip merge incorrectly preserved a "
                "dataclass-owned key. This would silently revert "
                "`setup notifications off`."
            ),
        )

    def test_modeled_field_change_overrides_file(self):
        """Modeled fields explicitly set by the dataclass override the file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            with open(cfg_path, "w") as f:
                yaml.safe_dump({
                    "data_dir": tmpdir,
                    "gateway": {"api_bind": "0.0.0.0"},
                }, f, sort_keys=False)

            cfg = _make_cfg(tmpdir, gateway=GatewayConfig(api_bind="127.0.0.1"))
            cfg.save()

            with open(cfg_path) as f:
                after = yaml.safe_load(f)

        self.assertEqual(after["gateway"]["api_bind"], "127.0.0.1")


class TestConfigSaveResilience(unittest.TestCase):
    """``cfg.save()`` must succeed on a fresh install, a missing file,
    and a partially-corrupt existing file."""

    def test_first_save_with_no_existing_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            self.assertFalse(os.path.exists(cfg_path))

            cfg = _make_cfg(tmpdir)
            cfg.save()

            self.assertTrue(os.path.exists(cfg_path))
            with open(cfg_path) as f:
                after = yaml.safe_load(f)
            self.assertEqual(after["data_dir"], tmpdir)
            self.assertEqual(after["environment"], "macos")
            self.assertNotIn("audit_sinks", after)  # nothing to preserve

    def test_corrupt_yaml_falls_back_to_dataclass_only(self):
        """Operator with a half-edited YAML must still be able to recover
        by re-running setup. We log a warning but do NOT raise."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            # Write something yaml.safe_load can't parse.
            with open(cfg_path, "w") as f:
                f.write("data_dir: [unclosed_list\n  audit_sinks:\n - {bad: yaml")

            cfg = _make_cfg(tmpdir)
            with self.assertLogs("defenseclaw.config", level="WARNING") as logs:
                cfg.save()
            self.assertTrue(
                any("failed to parse" in m for m in logs.output),
                msg=f"expected parse-failure warning, got {logs.output!r}",
            )

            # After the fallback the file is rewritten as the
            # dataclass-only view — operator's audit_sinks was lost
            # (it was unrecoverable anyway), but the file is now
            # well-formed and `defenseclaw setup splunk` can rewrite it.
            with open(cfg_path) as f:
                after = yaml.safe_load(f)
            self.assertEqual(after["data_dir"], tmpdir)

    def test_non_mapping_yaml_falls_back(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            # Top-level YAML list — invalid for our schema.
            with open(cfg_path, "w") as f:
                f.write("- not\n- a\n- mapping\n")

            cfg = _make_cfg(tmpdir)
            with self.assertLogs("defenseclaw.config", level="WARNING"):
                cfg.save()

            with open(cfg_path) as f:
                after = yaml.safe_load(f)
            self.assertIsInstance(after, dict)
            self.assertEqual(after["data_dir"], tmpdir)


class TestConfigSaveAtomicity(unittest.TestCase):
    """The save must be atomic via tmp + rename so a crash mid-write
    cannot leave a half-written ``config.yaml`` that bricks the gateway."""

    def test_save_leaves_no_tmp_file_behind(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = _make_cfg(tmpdir)
            cfg.save()
            self.assertFalse(
                os.path.exists(os.path.join(tmpdir, "config.yaml.tmp")),
            )

    def test_save_atomically_replaces_existing_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            with open(cfg_path, "w") as f:
                f.write("audit_sinks: []\n")
            inode_before = os.stat(cfg_path).st_ino

            cfg = _make_cfg(tmpdir)
            cfg.save()

            self.assertTrue(os.path.exists(cfg_path))
            # On POSIX, os.replace from a tmp file changes the inode.
            # On filesystems without inode semantics this is a no-op but
            # the existence-check above still proves the write completed.
            inode_after = os.stat(cfg_path).st_ino
            self.assertNotEqual(
                inode_before, inode_after,
                msg="config.yaml inode unchanged — save was not atomic",
            )


class TestMergeHelpers(unittest.TestCase):
    """Unit tests for the merge primitives so failures pinpoint the layer."""

    def test_owned_top_level_keys_includes_known_modeled_fields(self):
        cfg = _make_cfg("/tmp/dc-test")
        owned = _owned_top_level_keys(cfg)
        for k in ("data_dir", "gateway", "claw", "guardrail", "notifications",
                  "privacy", "splunk", "webhooks"):
            self.assertIn(k, owned, msg=f"expected modeled field {k!r}")
        # Documented unmodeled keys must NOT be in the owned set.
        self.assertNotIn("audit_sinks", owned)

    def test_merge_preserves_unmodeled_top_level_key(self):
        merged = _merge_preserving_unmodeled(
            existing={"audit_sinks": [{"name": "s"}], "data_dir": "/old"},
            new={"data_dir": "/new"},
            owned_top_level=frozenset({"data_dir", "splunk"}),
        )
        self.assertEqual(merged["audit_sinks"], [{"name": "s"}])
        self.assertEqual(merged["data_dir"], "/new")

    def test_merge_drops_owned_key_when_dataclass_omits_it(self):
        merged = _merge_preserving_unmodeled(
            existing={"splunk": {"hec_url": "stale"}, "data_dir": "/d"},
            new={"data_dir": "/d"},
            owned_top_level=frozenset({"data_dir", "splunk"}),
        )
        self.assertNotIn("splunk", merged)

    def test_merge_recurses_into_nested_dicts(self):
        merged = _merge_preserving_unmodeled(
            existing={"otel": {"resource": {"attributes": {"a": 1}}, "enabled": False}},
            new={"otel": {"enabled": True}},
            owned_top_level=frozenset({"otel"}),
        )
        self.assertTrue(merged["otel"]["enabled"])  # dataclass wins
        self.assertEqual(merged["otel"]["resource"]["attributes"]["a"], 1)  # rescued

    def test_merge_lists_are_atomic(self):
        """Lists from the dataclass replace lists from the file. Partial
        list merges would mis-handle operator deletions of modeled list
        elements."""
        merged = _merge_preserving_unmodeled(
            existing={"webhooks": [{"name": "old"}], "data_dir": "/d"},
            new={"webhooks": [{"name": "new"}], "data_dir": "/d"},
            owned_top_level=frozenset({"data_dir", "webhooks"}),
        )
        self.assertEqual(merged["webhooks"], [{"name": "new"}])

    def test_deep_merge_nested_preserves_unknown_subkeys(self):
        out = _deep_merge_nested(
            existing={"a": 1, "b": {"x": 10, "y": 20}, "preserved": True},
            new={"a": 2, "b": {"x": 99}},
        )
        self.assertEqual(out["a"], 2)
        self.assertEqual(out["b"]["x"], 99)
        self.assertEqual(out["b"]["y"], 20)  # preserved nested
        self.assertTrue(out["preserved"])    # preserved top-of-recurse

    def test_load_existing_returns_empty_on_missing_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            self.assertEqual(
                _load_existing_config_yaml(os.path.join(tmpdir, "nope.yaml")),
                {},
            )

    def test_load_existing_emits_warning_on_corrupt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "bad.yaml")
            with open(path, "w") as f:
                f.write("a: [unclosed")
            with self.assertLogs("defenseclaw.config", level="WARNING") as logs:
                self.assertEqual(_load_existing_config_yaml(path), {})
            self.assertTrue(any("failed to parse" in m for m in logs.output))


class TestRealWorldOperatorWorkflow(unittest.TestCase):
    """End-to-end repro of the operator workflow the F5 fix unblocks:
    ``setup splunk`` → ``setup codex`` → audit_sinks must survive."""

    def test_setup_splunk_then_setup_codex_keeps_audit_sinks(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")

            # Step 1: `defenseclaw setup splunk --logs` writes audit_sinks
            # via observability/writer.py (not Config.save). Simulate
            # that with a raw YAML write.
            initial = {
                "data_dir": tmpdir,
                "audit_db": os.path.join(tmpdir, "audit.db"),
                "environment": "macos",
                "claw": {"mode": "off"},
                "audit_sinks": [{
                    "name": "splunk-hec-localhost",
                    "kind": "splunk_hec",
                    "enabled": True,
                    "splunk_hec": {
                        "endpoint": "http://127.0.0.1:8088/services/collector/event",
                        "token_env": "SPLUNK_HEC_TOKEN",
                        "index": "defenseclaw",
                        "source": "defenseclaw",
                        "sourcetype": "_json",
                        "verify_tls": False,
                    },
                }],
            }
            with open(cfg_path, "w") as f:
                yaml.safe_dump(initial, f, sort_keys=False)

            # Step 2: `defenseclaw setup codex` reads the config and
            # eventually calls cfg.save() via execute_guardrail_setup
            # (cmd_setup.py:3716). Simulate the operator-visible
            # behaviour: load via Config(), flip the claw mode, save.
            cfg = _make_cfg(tmpdir)
            cfg.claw.mode = "codex"
            cfg.save()

            # Step 3: gateway reloads — must still see audit_sinks.
            with open(cfg_path) as f:
                final = yaml.safe_load(f)

        self.assertEqual(final["claw"]["mode"], "codex")
        self.assertIn("audit_sinks", final)
        self.assertEqual(len(final["audit_sinks"]), 1)
        self.assertEqual(
            final["audit_sinks"][0]["splunk_hec"]["endpoint"],
            "http://127.0.0.1:8088/services/collector/event",
        )


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    unittest.main()
