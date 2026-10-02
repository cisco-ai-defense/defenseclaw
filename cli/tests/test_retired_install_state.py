# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The native Windows uninstaller accepts state from pre-release builds."""

from __future__ import annotations

import os
import unittest

from defenseclaw.commands import windows_native_uninstall as native
from defenseclaw.retired_install_state import (
    RETIRED_INSTALL_STATE_CONNECTORS,
    RETIRED_INSTALL_STATE_FIELDS,
)

_ROOT = os.path.abspath(os.path.join(os.sep, "profile"))


def _expected_paths() -> dict[str, str]:
    install_root = os.path.join(_ROOT, "AppData", "Local", "Programs", "DefenseClaw")
    return {
        "install_root": install_root,
        "command_dir": os.path.join(install_root, "bin"),
        "data_root": os.path.join(_ROOT, ".defenseclaw"),
        "runtime": os.path.join(install_root, "runtime", "python"),
        "maintenance_path": os.path.join(_ROOT, "setup", "defenseclaw-setup.exe"),
    }


def _state(connector: str, **extra: object) -> dict[str, object]:
    state: dict[str, object] = {
        "schema_version": 1,
        "version": "0.8.11",
        "source_commit": "0123456789abcdef0123456789abcdef01234567",
        "distribution_flavor": "oss",
        "install_kind": "native-windows-exe",
        "install_scope": "user",
        "path_entry_owned": True,
        "connector": connector,
        "mode": "observe",
        "unsigned_local_artifact": False,
        "release_signing_required": True,
        "toolchain": {},
        "installed_at_utc": "2026-09-01T00:00:00Z",
    }
    state.update(_expected_paths())
    state.update(extra)
    return state


class RetiredInstallStateTests(unittest.TestCase):
    def test_current_state_validates(self) -> None:
        self.assertEqual(native._validate_install_state(_state("codex"), _expected_paths())[0], "0.8.11")

    def test_retired_connector_and_bindings_are_accepted(self) -> None:
        bindings = {field: os.path.join(_ROOT, field) for field in RETIRED_INSTALL_STATE_FIELDS}
        for connector in sorted(RETIRED_INSTALL_STATE_CONNECTORS) + ["codex"]:
            with self.subTest(connector=connector):
                native._validate_install_state(_state(connector, **bindings), _expected_paths())

    def test_schema_stays_closed(self) -> None:
        with self.assertRaises(native.NativeWindowsUninstallRefusal):
            native._validate_install_state(_state("codex", unexpected_home="/x"), _expected_paths())
        with self.assertRaises(native.NativeWindowsUninstallRefusal):
            native._validate_install_state(_state("unknown-agent"), _expected_paths())
        field = sorted(RETIRED_INSTALL_STATE_FIELDS)[0]
        with self.assertRaises(native.NativeWindowsUninstallRefusal):
            native._validate_install_state(_state("codex", **{field: 7}), _expected_paths())


if __name__ == "__main__":
    unittest.main()
