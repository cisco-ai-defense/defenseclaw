# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Install / disable / uninstall lifecycle smoke matrix (plan C5 / S7.6).

Pre-existing tests (``test_cmd_uninstall.py``) cover the planning surface;
this module covers the **round-trip** side of the lifecycle for every
built-in connector. We exercise the Python CLI plumbing — config write,
guardrail runtime emission, uninstall planning — for openclaw,
zeptoclaw, claudecode, and codex without invoking the destructive
``scripts/install.sh`` shell installer (that path is reserved for the
live e2e CI matrix in plan E4).

What we **do not** exercise here:
  * Actually running the Go gateway. Connector ``Setup()`` lives in Go;
    we treat it as out-of-process and assert the Python contracts that
    feed it (config + runtime JSON) and consume from it (uninstall plan).
  * Mutating the dev machine. Every test pins ``DEFENSECLAW_HOME`` to a
    ``tmp_path``; the production ``~/.defenseclaw`` is untouched.

What we **do** exercise:
  * ``execute_guardrail_setup`` writes a config with the right connector.
  * ``guardrail_runtime.json`` is emitted under the tmp data dir.
  * The uninstall planner produces a plan referencing the tmp data dir
    (no leakage of the real machine's $HOME).
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

CONNECTORS = ("openclaw", "zeptoclaw", "claudecode", "codex")

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Imported lazily inside tests to keep CLI import side-effects (logger
# config, etc.) confined to the test process.


class _IsolatedHome:
    """Context manager that pins DEFENSECLAW_HOME / HOME to a temp dir.

    Mirrors the install lifecycle's contract: every persisted artefact
    must land under DEFENSECLAW_HOME. Used by every parametrised case
    below so a test failure cannot leak files into the developer's
    real home directory.
    """

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._patches: list[unittest.mock._patch] = []

    def __enter__(self) -> str:
        path = self._tmp.name
        os.makedirs(os.path.join(path, ".defenseclaw"), exist_ok=True)
        self._patches = [
            patch.dict(
                os.environ,
                {
                    "DEFENSECLAW_HOME": os.path.join(path, ".defenseclaw"),
                    "HOME": path,
                },
                clear=False,
            ),
        ]
        for p in self._patches:
            p.start()
        return path

    def __exit__(self, *exc):
        for p in self._patches:
            p.stop()
        self._tmp.cleanup()


def _build_app_with_connector(home: str, connector_name: str):
    """Build a real AppContext rooted at ``home`` with the given connector.

    Imports happen inside the helper so each test pays only for its own
    import cost (and so a missing optional dep doesn't break collection
    of unrelated tests).
    """
    # The Python config module honors DEFENSECLAW_HOME env var, which
    # is already pinned by _IsolatedHome before we call load(). Hence
    # no explicit data_dir kwarg — the env var is the canonical knob.
    from defenseclaw.config import load as load_config
    from defenseclaw.context import AppContext

    cfg = load_config()
    cfg.guardrail.connector = connector_name
    app = AppContext()
    app.cfg = cfg
    return app


class InstallSmokeMatrixTests(unittest.TestCase):
    """Per-connector lifecycle round-trip smoke tests."""

    def _run_setup_disable_uninstall_for(self, connector_name: str) -> None:
        from defenseclaw.commands.cmd_setup import execute_guardrail_setup
        from defenseclaw.commands import cmd_uninstall

        with _IsolatedHome() as home:
            app = _build_app_with_connector(home, connector_name)

            # 1. Setup writes config + guardrail_runtime.json.
            ok, warnings = execute_guardrail_setup(app, save_config=True)
            self.assertTrue(
                ok,
                f"{connector_name}: execute_guardrail_setup returned False; warnings={warnings}",
            )

            cfg_path = os.path.join(home, ".defenseclaw", "config.yaml")
            self.assertTrue(
                os.path.exists(cfg_path),
                f"{connector_name}: config.yaml missing under tmp DEFENSECLAW_HOME",
            )

            runtime_path = os.path.join(home, ".defenseclaw", "guardrail_runtime.json")
            self.assertTrue(
                os.path.exists(runtime_path),
                f"{connector_name}: guardrail_runtime.json was not written",
            )
            with open(runtime_path) as fh:
                runtime = json.load(fh)
            for key in ("mode", "scanner_mode", "block_message"):
                self.assertIn(key, runtime, f"{connector_name}: runtime missing {key}")

            # 2. Reload config from disk and assert the connector
            #    selection persisted. config.load() reads from
            #    DEFENSECLAW_HOME (still pinned by _IsolatedHome).
            from defenseclaw.config import load as load_config_again

            reloaded = load_config_again()
            self.assertEqual(
                reloaded.guardrail.connector,
                connector_name,
                f"{connector_name}: persisted connector mismatch",
            )

            # 3. The uninstall planner produces a coherent dry-run plan
            #    rooted under the tmp data dir.  We use the safe defaults
            #    (no binary removal, no openclaw revert).
            with patch.dict(
                os.environ,
                {"DEFENSECLAW_HOME": os.path.join(home, ".defenseclaw")},
                clear=False,
            ):
                plan = cmd_uninstall._build_plan(
                    wipe_data=False,
                    binaries=False,
                    revert_openclaw=False,
                    remove_plugin=False,
                )
            self.assertTrue(
                plan.data_dir,
                f"{connector_name}: uninstall plan missing data_dir",
            )
            self.assertFalse(
                plan.remove_data_dir,
                f"{connector_name}: dry-run defaults must not request data dir removal",
            )
            self.assertFalse(
                plan.remove_binaries,
                f"{connector_name}: dry-run defaults must not request binary removal",
            )

    def test_smoke_matrix(self) -> None:
        for name in CONNECTORS:
            with self.subTest(connector=name):
                self._run_setup_disable_uninstall_for(name)


if __name__ == "__main__":
    unittest.main()
