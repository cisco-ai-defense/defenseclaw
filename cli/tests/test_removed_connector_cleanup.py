# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""until 1.1: status, doctor and the installers list what OpenHands or OmniGent left, as information.

The gateway teardown (internal/gateway/connector/removed.go) removes what an
older DefenseClaw wrote for them and never blocks anything;
``defenseclaw.removed_connectors`` lists what it could not remove under the
one removal notice.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner
from defenseclaw import removed_connectors
from defenseclaw.commands import cmd_doctor, cmd_status
from defenseclaw.commands.cmd_doctor import _check_removed_connector_cleanup, _DoctorResult
from defenseclaw.commands.cmd_status import status as status_cmd

from tests.helpers import cleanup_app, make_app_context

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_NOTICE = "OpenHands/OmniGent support was removed in 1.0.5; DefenseClaw no longer guards it."
_OPENHANDS_103 = "#!/bin/bash\n# defenseclaw-managed-hook v6\nexec defenseclaw-hook hook --connector openhands\n"


def _write(path: str, body: str, mode: int = 0o600) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    os.chmod(path, mode)
    return path


class _Host(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = self._tmp.name
        self.data = os.path.join(self.home, ".defenseclaw")
        self.hooks = os.path.join(self.data, "hooks")
        os.makedirs(self.hooks)
        env = patch.dict(os.environ, {"OMNIGENT_CONFIG": "", "OMNIGENT_CONFIG_HOME": ""})
        env.start()
        self.addCleanup(env.stop)
        self.addCleanup(self._tmp.cleanup)

    def leftovers(self):
        return removed_connectors.leftovers(self.data, home=self.home)


class LeftoversTests(_Host):
    def test_the_notice_is_the_go_notice(self):
        self.assertEqual(removed_connectors.NOTICE, _NOTICE)
        with open(os.path.join(_REPO, "internal", "gateway", "connector", "removed.go"), encoding="utf-8") as fh:
            self.assertIn(f'RemovedConnectorNotice = "{_NOTICE}"', fh.read())

    def test_a_host_without_them_lists_nothing(self):
        self.assertEqual(self.leftovers(), [])
        self.assertEqual(removed_connectors.leftovers("", home=self.home), [])

    def test_what_the_teardown_could_not_remove_is_listed_under_the_notice(self):
        script = _write(os.path.join(self.hooks, "openhands-hook.sh"), _OPENHANDS_103, 0o700)
        config = _write(os.path.join(self.home, ".openhands", "hooks.json"), '{"PreToolUse": [ "' + script + '"')
        token = _write(os.path.join(self.hooks, ".hook-openhands.token"), "t")
        [left] = self.leftovers()
        self.assertEqual(left.connector, "openhands")
        paths = {item.path for item in left.items}
        self.assertEqual(paths, {config, script, token})
        lines = left.lines()
        self.assertEqual(lines[0], _NOTICE)
        self.assertEqual(left.as_json()["notice"], _NOTICE)

    def test_a_hard_link_elsewhere_is_defenseclaws_hook(self):
        script = _write(os.path.join(self.hooks, "openhands-hook.sh"), _OPENHANDS_103, 0o700)
        outside = os.path.join(self.home, "bin", "guard.sh")
        os.makedirs(os.path.dirname(outside))
        try:
            os.link(script, outside)
        except OSError as exc:
            self.skipTest(f"hard link: {exc}")
        os.remove(script)
        config = _write(
            os.path.join(self.home, ".openhands", "hooks.json"),
            json.dumps({"PreToolUse": [{"hooks": [{"type": "command", "command": f"bash {outside}"}]}]}),
        )
        [left] = self.leftovers()
        self.assertEqual([item.path for item in left.items], [config])

    def test_a_config_that_no_longer_names_defenseclaw_is_not_listed(self):
        _write(
            os.path.join(self.home, ".openhands", "hooks.json"),
            json.dumps({"PreToolUse": [{"hooks": [{"type": "command", "command": "/opt/mine"}]}]}),
        )
        _write(os.path.join(self.home, ".omnigent", "config.yaml"), "policy_modules:\n  - mine\n")
        self.assertEqual(self.leftovers(), [])

    def test_omnigent_import_path_line_is_listed(self):
        pth = _write(os.path.join(self.home, "site", "defenseclaw_omnigent.pth"), self.hooks + "\n/opt/other\n")
        _write(
            os.path.join(self.data, "connector_backups", "omnigent", "pth.json"),
            json.dumps({"version": 1, "connector": "omnigent", "logical_name": "pth", "path": pth}),
        )
        [left] = self.leftovers()
        self.assertIn(pth, [item.path for item in left.items])


class DoctorTests(_Host):
    def _run(self):
        result = _DoctorResult()
        real = removed_connectors.leftovers
        with (
            patch.object(cmd_doctor, "_json_mode", True),
            patch.object(removed_connectors, "leftovers", lambda data_dir, **kw: real(data_dir, home=self.home, **kw)),
        ):
            _check_removed_connector_cleanup(SimpleNamespace(data_dir=self.data), result)
        return result

    def test_one_information_row_never_a_failure(self):
        _write(os.path.join(self.hooks, "openhands-hook.sh"), _OPENHANDS_103, 0o700)
        _write(os.path.join(self.hooks, "defenseclaw_omnigent_policy.py"), "# defenseclaw-managed-policy v3\n")
        result = self._run()
        [check] = result.checks
        self.assertEqual(check["status"], "skip")
        self.assertTrue(check["detail"].startswith(_NOTICE))
        self.assertEqual((result.failed, result.warned), (0, 0))

    def test_prints_no_row_without_leftovers(self):
        self.assertEqual(self._run().checks, [])


class StatusTests(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.app.cfg.data_dir = ""
        self.left = removed_connectors.RemovedConnectorLeftovers(
            "omnigent",
            "OmniGent",
            (removed_connectors.Leftover("/home/u/.omnigent/config.yaml", "could not be checked", "check it"),),
        )

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _invoke(self, *args, left=()):
        with (
            patch.object(cmd_status, "_fetch_runtime_bound_health", return_value=None),
            patch.object(removed_connectors, "leftovers", return_value=list(left)),
        ):
            return CliRunner().invoke(status_cmd, list(args), obj=self.app, catch_exceptions=False)

    def test_json_lists_the_leftovers(self):
        result = self._invoke("--json", left=[self.left])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        doc = json.loads(result.output)
        self.assertEqual(doc["removed_connector_cleanup"][0]["items"][0]["path"], "/home/u/.omnigent/config.yaml")

    def test_json_has_no_key_when_nothing_is_left(self):
        doc = json.loads(self._invoke("--json").output)
        self.assertNotIn("removed_connector_cleanup", doc)

    def test_human_status_shows_the_notice(self):
        result = self._invoke(left=[self.left])
        self.assertIn(_NOTICE, result.output)
        self.assertIn("defenseclaw doctor", result.output)
        self.assertNotIn(_NOTICE, self._invoke().output)


class UpgradeGuideTests(unittest.TestCase):
    def _section(self) -> str:
        path = os.path.join(_REPO, "docs-site", "content", "docs", "appendix", "upgrade-from-0-8.mdx")
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        section = text.split("## Renamed and removed connectors", 1)[1].split("\n## ", 1)[0]
        return re.sub(r"\s+", " ", section)

    def test_a_config_with_only_a_removed_connector_is_refused_as_the_page_says(self):
        from defenseclaw import migrations

        section = self._section()
        for name in removed_connectors.NAMES:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as data_dir:
                with open(os.path.join(data_dir, "config.yaml"), "w", encoding="utf-8") as fh:
                    fh.write(f"config_version: 9\nguardrail:\n  connector: {name}\n  connectors:\n    {name}: {{}}\n")
                with self.assertRaises(migrations.MigrationError) as raised:
                    migrations.migrate(data_dir, check=True)
                message = str(raised.exception)
                self.assertIn("nothing was changed", message)
                self.assertIn(f"`defenseclaw setup remove {name} --yes --force`", message)
        self.assertIn(
            "If OpenHands or OmniGent is the only connector it lists, the upgrade stops before it changes anything",
            section,
        )

    def test_the_page_states_the_notice_and_the_kept_backups(self):
        from defenseclaw.removed_connectors import kept_backups_root

        section = self._section()
        self.assertIn(f"`{_NOTICE}`", section)
        self.assertIn("never a failure", section)
        self.assertEqual(
            kept_backups_root("~/.defenseclaw"), os.path.normpath("~/.defenseclaw-removed-connector-backups")
        )
        self.assertIn("`~/.defenseclaw-removed-connector-backups/<connector>`", section)


if __name__ == "__main__":
    unittest.main()
