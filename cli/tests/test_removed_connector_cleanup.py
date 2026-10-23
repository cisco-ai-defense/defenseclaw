# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""until 1.1: status, doctor and uninstall list what a removed connector left.

The gateway's teardown (internal/gateway/connector/removed.go) only replaces
DefenseClaw's hook script with a stub that blocks every call and revokes the
tokens; ``defenseclaw.removed_connectors`` lists everything else, with the
step to remove it by hand.
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
_OPENHANDS_STUB = (
    "#!/bin/sh -p\n# defenseclaw-managed-hook v0 (disabled tombstone)\n"
    'echo \'{"decision":"deny","reason":"OpenHands support was removed in DefenseClaw 1.0.4."}\'\nexit 2\n'
)
_OPENHANDS_103 = "#!/bin/bash\n# defenseclaw-managed-hook v6\nexec defenseclaw-hook hook --connector openhands\n"
_OMNIGENT_STUB = "# defenseclaw-managed-policy v0 (disabled tombstone)\n_REASON = 'OmniGent support was removed in DefenseClaw 1.0.4.'\n"


def _write(path: str, body: str) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    return path


def _backup(data_dir: str, name: str, logical: str, path: str) -> None:
    _write(
        os.path.join(data_dir, "connector_backups", name, logical + ".json"),
        json.dumps({"version": 1, "connector": name, "logical_name": logical, "path": path, "existed": True}),
    )


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

    def tearDown(self):
        self._tmp.cleanup()

    def openhands(self, script: str = _OPENHANDS_STUB) -> str:
        script_path = os.path.join(self.hooks, "openhands-hook.sh")
        config = _write(
            os.path.join(self.home, ".openhands", "hooks.json"),
            json.dumps({"pre_tool_use": [{"hooks": [{"type": "command", "command": script_path}]}]}),
        )
        _backup(self.data, "openhands", "config", config)
        _write(script_path, script)
        _write(os.path.join(self.hooks, ".hookcfg.openhands"), "DEFENSECLAW_CONNECTOR=openhands\n")
        return config

    def items(self, name: str) -> dict[str, removed_connectors.Leftover]:
        for left in removed_connectors.leftovers(self.data, home=self.home):
            if left.connector == name:
                return {item.path: item for item in left.items}
        return {}


class LeftoversTests(_Host):
    def test_lists_everything_the_openhands_teardown_left(self):
        config = self.openhands()
        items = self.items("openhands")
        script = os.path.join(self.hooks, "openhands-hook.sh")
        self.assertEqual(
            list(items),
            [
                config,
                script,
                os.path.join(self.hooks, ".hookcfg.openhands"),
                os.path.join(self.data, "connector_backups", "openhands"),
            ],
        )
        self.assertIn("remove every hook whose command runs openhands-hook.sh", items[config].step)
        self.assertIn("blocks every call", items[config].what)
        self.assertEqual(items[script].what, "the stub that blocks every OpenHands call")
        self.assertEqual(items[os.path.join(self.hooks, ".hookcfg.openhands")].step, "delete it")

    # Review fix (G-deadcode loop round 3): the teardown saves an edited
    # OmniGent policy module under connector_backups/omnigent before it writes
    # the stub (removed.go keepEdited); the leftovers list each saved copy.
    def test_a_saved_edited_omnigent_module_is_listed(self):
        backups = os.path.join(self.data, "connector_backups", "omnigent")
        saved = _write(os.path.join(backups, "defenseclaw_omnigent_policy.py.edited-0123456789abcdef"), "# mine\n")
        _write(os.path.join(backups, "module.json"), "{}")
        _write(os.path.join(self.hooks, "defenseclaw_omnigent_policy.py"), _OMNIGENT_STUB)
        items = self.items("omnigent")
        self.assertIn(backups, items)
        self.assertNotIn(os.path.join(backups, "module.json"), items)
        self.assertEqual(
            items[saved].what,
            "your edited defenseclaw_omnigent_policy.py, as it was when the teardown replaced it with the stub "
            "that blocks every call",
        )
        self.assertEqual(
            items[saved].step, "copy back what you need (not into DefenseClaw's hooks folder), then delete it"
        )

    def test_a_script_the_teardown_has_not_replaced_says_to_run_it(self):
        self.openhands(_OPENHANDS_103)
        _write(os.path.join(self.hooks, ".otlp-openhands.token"), "t")
        items = self.items("openhands")
        teardown = "run defenseclaw-gateway connector teardown --connector openhands"
        self.assertEqual(items[os.path.join(self.hooks, "openhands-hook.sh")].step, teardown)
        self.assertEqual(items[os.path.join(self.hooks, ".otlp-openhands.token")].step, teardown)

    # Review fix (G-deadcode loop round 2): a copy of the old OpenHands hook
    # in the hooks folder reads the hook token, and without it lets every
    # call run in fail mode open, so the teardown keeps it, whatever is at
    # the script path, and the leftovers say when it may go. OmniGent's token
    # still points at the teardown.
    def test_the_openhands_hook_token_is_listed_as_kept(self):
        token = os.path.join(self.hooks, ".hook-openhands.token")
        for script in (_OPENHANDS_103, None):
            with self.subTest(stub=script is None):
                self.openhands(script or _OPENHANDS_STUB)
                _write(token, "t")
                item = self.items("openhands")[token]
                self.assertIn("which DefenseClaw keeps", item.what)
                self.assertIn("or a copy of it in this folder", item.what)
                self.assertEqual(
                    item.step,
                    "delete it only once no OpenHands hooks.json, in your home or in any workspace, runs "
                    "openhands-hook.sh or a copy of it, and OpenHands was restarted",
                )

    def test_a_script_defenseclaw_did_not_write_is_named_as_not_changed(self):
        self.openhands("#!/bin/sh\necho mine\n")
        self.assertIn("not changed", self.items("openhands")[os.path.join(self.hooks, "openhands-hook.sh")].what)

    # Review fixes (G-deadcode loop round 3): the teardown keeps the tokens
    # while an old hook may still run at the script path; the leftovers say
    # what to do by hand first, and the tokens point at that step.
    def test_a_script_defenseclaw_cannot_prove_it_wrote_keeps_the_tokens_behind_its_step(self):
        script = os.path.join(self.hooks, "openhands-hook.sh")
        token = _write(os.path.join(self.hooks, ".otlp-openhands.token"), "t")
        target = _write(os.path.join(self.hooks, "old-hook.sh"), _OPENHANDS_103)
        for plant in ("#!/bin/sh\n#\n#\n" + _OPENHANDS_103.split("\n", 1)[1], None):
            with self.subTest(symlink=plant is None):
                self.openhands(plant or "x")
                if plant is None:
                    os.remove(script)
                    try:
                        os.symlink(target, script)
                    except OSError as exc:
                        self.skipTest(f"symlink: {exc}")
                items = self.items("openhands")
                self.assertIn("teardown keeps its tokens", items[script].what)
                self.assertEqual(
                    items[script].step, removed_connectors._foreign_step(removed_connectors._CONNECTORS[0])
                )
                self.assertIn("move it out of DefenseClaw's hooks folder", items[script].step)
                self.assertEqual(items[token].step, f"follow the step for {script} first")

    def test_a_hard_linked_script_keeps_the_tokens_behind_its_step(self):
        self.openhands(_OPENHANDS_103)
        script = os.path.join(self.hooks, "openhands-hook.sh")
        token = _write(os.path.join(self.hooks, ".otlp-openhands.token"), "t")
        try:
            os.link(script, os.path.join(self.home, "elsewhere-hook.sh"))
        except OSError as exc:
            self.skipTest(f"hard link: {exc}")
        items = self.items("openhands")
        self.assertIn("with 2 names (hard links)", items[script].what)
        self.assertIn(
            "-samefile " + script if os.name != "nt" else "fsutil hardlink list " + script, items[script].step
        )
        self.assertIn("delete every other name of this file", items[script].step)
        self.assertEqual(items[token].step, f"follow the step for {script} first")

    def test_a_config_that_no_longer_names_defenseclaw_is_not_listed(self):
        config = self.openhands()
        _write(config, '{"pre_tool_use": []}')
        self.assertNotIn(config, self.items("openhands"))

    def test_windows_launcher_hooks_are_listed(self):
        config = _write(
            os.path.join(self.home, ".openhands", "hooks.json"),
            json.dumps(
                {
                    "pre_tool_use": [
                        {"hooks": [{"command": "C:\\\\dc\\\\defenseclaw-hook.exe hook --connector openhands"}]}
                    ]
                }
            ),
        )
        self.assertIn(config, self.items("openhands"))

    def test_lists_everything_the_omnigent_teardown_left(self):
        config = _write(
            os.path.join(self.home, ".omnigent", "config.yaml"), "policy_modules: [defenseclaw_omnigent_policy]\n"
        )
        explicit = _write(os.path.join(self.home, "explicit.yaml"), "policy_modules: [defenseclaw_omnigent_policy]\n")
        pth = _write(os.path.join(self.home, "venv", "defenseclaw_omnigent.pth"), self.hooks + "\n")
        _backup(self.data, "omnigent", "pth", pth)
        module = _write(os.path.join(self.hooks, "defenseclaw_omnigent_policy.py"), _OMNIGENT_STUB)
        with patch.dict(os.environ, {"OMNIGENT_CONFIG": explicit}):
            items = self.items("omnigent")
        for path in (config, explicit, pth, module, os.path.join(self.data, "connector_backups", "omnigent")):
            self.assertIn(path, items)
        self.assertIn("remove defenseclaw_omnigent_policy from policy_modules", items[config].step)
        self.assertEqual(items[module].what, "the stub that blocks every OmniGent call")

    def test_a_host_without_them_lists_nothing(self):
        _write(os.path.join(self.home, ".openhands", "hooks.json"), '{"pre_tool_use": []}')
        self.assertEqual(removed_connectors.leftovers(self.data, home=self.home), [])
        self.assertEqual(removed_connectors.leftovers("", home=self.home), [])

    def test_lines_leave_out_what_the_data_removal_takes(self):
        config = self.openhands()
        [left] = removed_connectors.leftovers(self.data, home=self.home)
        lines = left.lines(without_under=self.data)
        self.assertEqual(
            lines[0], "OpenHands support was removed in DefenseClaw 1.0.4. Left for you to remove by hand:"
        )
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[1].startswith(f"  - {config}: "))
        self.assertEqual(left.as_json()["items"][0]["path"], config)


class DecodedConfigTests(_Host):
    """Review fixes (G-deadcode loop round 2): configs are read for their decoded values."""

    def _item(self, name: str, path: str):
        return self.items(name).get(path)

    def test_openhands_names_written_with_escapes_or_other_spellings_are_listed(self):
        config = os.path.join(self.home, ".openhands", "hooks.json")
        for body in (
            r'{"pre_tool_use":[{"hooks":[{"command":"/h/.defenseclaw/hooks/openhands\u002dhook.sh"}]}]}',
            r'{"pre_tool_use":[{"hooks":[{"command":"\u006f\u0070\u0065\u006e\u0068\u0061\u006e\u0064\u0073-hook.sh"}]}]}',
            '{"pre_tool_use":[{"hooks":[{"command":"C:/dc/OpenHands-Hook.SH"}]}]}',
            '{"pre_tool_use":[{"hooks":[{"command":"defenseclaw-hook.exe hook --connector=openhands"}]}]}',
            r'{"pre_tool_use":[{"hooks":[{"command":"defenseclaw-hook.exe hook --connector \"openhands\""}]}]}',
            r'{"pre_tool_use":[{"hooks":[{"command":"defenseclaw-hook.exe hook \u002d\u002dconnector open-hands"}]}]}',
            r'{"pre_tool_use":[{"hooks":[{"command":"defenseclaw-hook.exe hook --connector\tOpenHands"}]}]}',
            "\ufeff" + r'{"pre_tool_use":[{"hooks":[{"command":"openhands\u002dhook.sh"}]}]}',
        ):
            with self.subTest(body=body):
                _write(config, body)
                item = self._item("openhands", config)
                self.assertIsNotNone(item, body)
                self.assertIn("remove every hook whose command runs openhands-hook.sh", item.step)

    def test_omnigent_names_written_with_yaml_escapes_are_listed(self):
        config = os.path.join(self.home, ".omnigent", "config.yaml")
        for body in (
            'policy_modules: ["defenseclaw_omnigent_polic\\x79"]\n',
            'policy_modules:\n  - "\\u0064efenseclaw_omnigent_policy"\n',
            'x: &h "defenseclaw_omnigent_polic\\x79.defenseclaw_policy"\npolicies:\n  g:\n    handler: *h\n',
            'policies:\n  ? "defenseclaw_omnigent_polic\\x79"\n  : {}\n',
        ):
            with self.subTest(body=body):
                _write(config, body)
                item = self._item("omnigent", config)
                self.assertIsNotNone(item, body)
                self.assertIn("remove defenseclaw_omnigent_policy from policy_modules", item.step)

    def test_a_config_that_cannot_be_checked_is_listed_for_a_check_by_hand(self):
        for name, path, body in (
            ("openhands", os.path.join(self.home, ".openhands", "hooks.json"), '{"pre_tool_use": ['),
            ("omnigent", os.path.join(self.home, ".omnigent", "config.yaml"), "policy_modules: [\n"),
        ):
            with self.subTest(name=name):
                _write(path, body)
                item = self._item(name, path)
                self.assertIsNotNone(item)
                self.assertIn("could not be checked", item.what)
                self.assertTrue(item.step.startswith("check it by hand: "), item.step)

    def test_configs_that_do_not_name_the_hook_are_not_listed(self):
        for name, path, body in (
            ("openhands", os.path.join(self.home, ".openhands", "hooks.json"), '{"pre_tool_use": []}'),
            (
                "openhands",
                os.path.join(self.home, ".openhands", "hooks.json"),
                '{"pre_tool_use":[{"hooks":[{"command":"defenseclaw-hook.exe hook --connector opencode"}]}]}',
            ),
            ("openhands", os.path.join(self.home, ".openhands", "hooks.json"), "  \n"),
            ("omnigent", os.path.join(self.home, ".omnigent", "config.yaml"), "policy_modules:\n  - corp_policy\n"),
        ):
            with self.subTest(name=name, body=body):
                _write(path, body)
                self.assertIsNone(self._item(name, path))

    def test_a_yaml_alias_bomb_is_checked_quickly(self):
        lines = ['a0: &a0 ["x", "y"]']
        for i in range(1, 30):
            lines.append(f"a{i}: &a{i} [*a{i - 1}, *a{i - 1}]")
        config = _write(os.path.join(self.home, ".omnigent", "config.yaml"), "\n".join(lines) + "\n")
        self.assertIsNone(self._item("omnigent", config))


class PthTests(_Host):
    """Review fixes (G-deadcode loop round 2): only DefenseClaw's .pth line is removed by hand."""

    def _pth(self, body: str):
        pth = _write(os.path.join(self.home, "venv", "defenseclaw_omnigent.pth"), body.replace("{hooks}", self.hooks))
        _backup(self.data, "omnigent", "pth", pth)
        return pth, self.items("omnigent").get(pth)

    def test_a_pth_with_only_defenseclaws_line_is_deleted(self):
        for body in ("{hooks}\n", "\ufeff{hooks}\r\n"):
            with self.subTest(body=body):
                _, item = self._pth(body)
                self.assertIsNotNone(item)
                self.assertTrue(item.step.startswith("delete this file once no OmniGent config.yaml names"), item.step)

    def test_a_pth_with_other_import_paths_keeps_them(self):
        for body in ("/opt/corp/lib\n{hooks}\n", "{hooks}\nimport corp_site\n"):
            with self.subTest(body=body):
                _, item = self._pth(body)
                self.assertIsNotNone(item)
                self.assertTrue(item.step.startswith(f"remove only the line {self.hooks} "), item.step)
                self.assertNotIn("delete this file", item.step)

    def test_a_pth_without_defenseclaws_line_is_not_listed(self):
        for body in ("/opt/corp/lib\n", ""):
            with self.subTest(body=body):
                _, item = self._pth(body)
                self.assertIsNone(item)


class GoParityTests(unittest.TestCase):
    """The Go teardown writes the stubs these readers recognize, with the same steps."""

    def test_go_stubs_and_steps_match(self):
        with open(os.path.join(_REPO, "internal", "gateway", "connector", "removed.go"), encoding="utf-8") as fh:
            source = fh.read()
        for c in removed_connectors._CONNECTORS:
            self.assertIn(f'"{c.marker}"', source)
        # Both deny reasons, OpenHands' and OmniGent's, say it.
        self.assertGreaterEqual(source.count(removed_connectors.STUB_PHRASE), 2)
        self.assertRegex(source, re.escape('"# defenseclaw-managed-hook v0 (disabled tombstone)\\n"'))
        self.assertRegex(source, re.escape('"# defenseclaw-managed-policy v0 (disabled tombstone)\\n"'))
        for phrase in (
            "from this file, then restart OpenHands",
            "from this file, then restart OmniGent",
            "the stub that blocks every ",
            "delete it once nothing above runs it",
            "copy back what you need, then delete this folder",
            'removedEditedInfix = ".edited-"',
            ", as it was when the teardown replaced it with the stub that blocks every call",
            "copy back what you need (not into DefenseClaw's hooks folder), then delete it",
            " (DefenseClaw's hook folder) from this file, and keep every other line, once no OmniGent config.yaml names ",
            "; it holds other import paths too",
            "; it holds nothing else",
            "), so it may still name DefenseClaw's hook",
            " names (hard links); teardown leaves it and its tokens, so every name still reaches the gateway, which blocks every call",
            "not changed: DefenseClaw cannot prove it wrote it (a link, no DefenseClaw marker in its first lines, or not a regular file)",
            "if it is not yours, delete it; if it is, move it out of DefenseClaw's hooks folder; then run ",
            "delete every other name of this file (",
            "follow the step for ",
        ):
            self.assertIn(phrase, source)


class DoctorTests(_Host):
    def test_warns_with_each_step(self):
        config = self.openhands()
        result = _DoctorResult()
        with (
            patch.object(cmd_doctor, "_json_mode", True),
            patch.object(removed_connectors, "leftovers", lambda data_dir: _leftovers(data_dir, self.home)),
        ):
            _check_removed_connector_cleanup(SimpleNamespace(data_dir=self.data), result)
        [check] = result.checks
        self.assertEqual(check["status"], "warn")
        self.assertIn("OpenHands", check["label"])
        self.assertIn(config, check["detail"])
        self.assertIn("remove every hook whose command runs openhands-hook.sh", check["detail"])

    def test_prints_no_row_without_leftovers(self):
        result = _DoctorResult()
        with patch.object(removed_connectors, "leftovers", lambda data_dir: _leftovers(data_dir, self.home)):
            _check_removed_connector_cleanup(SimpleNamespace(data_dir=self.data), result)
        self.assertEqual(result.checks, [])


_REAL_LEFTOVERS = removed_connectors.leftovers


def _leftovers(data_dir: str, home: str):
    return _REAL_LEFTOVERS(data_dir, home=home)


class StatusTests(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.app.cfg.data_dir = ""
        self.left = removed_connectors.RemovedConnectorLeftovers(
            "omnigent",
            "OmniGent",
            (removed_connectors.Leftover("/home/u/.omnigent/config.yaml", "OmniGent still imports it", "remove it"),),
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

    def test_human_status_points_at_doctor(self):
        result = self._invoke(left=[self.left])
        self.assertIn("OmniGent was removed in 1.0.4; 1 item(s) to remove by hand", result.output)
        self.assertIn("defenseclaw doctor", result.output)
        self.assertNotIn("to remove by hand", self._invoke().output)


if __name__ == "__main__":
    unittest.main()
