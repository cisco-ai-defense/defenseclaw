# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for :mod:`defenseclaw.gateway` — the gateway-binary resolver.

The resolver fixed a concrete UX bug where ``defenseclaw tui`` failed
in the shell that just finished ``make all``.  These tests pin down
the three-tier resolution order so a future refactor can't silently
regress it.
"""

from __future__ import annotations

import os
import stat
import tempfile
import unittest
from unittest.mock import patch

from defenseclaw import gateway


class ResolveGatewayBinaryTests(unittest.TestCase):
    def setUp(self) -> None:
        # Work in a tmp dir so the "canonical fallback" branch doesn't
        # accidentally hit a real ~/.local/bin/defenseclaw-gateway the
        # developer happens to have installed.
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

        # Move the canonical install dir into the sandbox for the
        # duration of each test.  Patching a module-level constant is
        # the simplest way to redirect both canonical_install_path() and
        # the fallback lookup inside resolve_gateway_binary().
        self._orig_install_dir = gateway._CANONICAL_INSTALL_DIR
        gateway._CANONICAL_INSTALL_DIR = self._tmp.name
        self.addCleanup(lambda: setattr(
            gateway, "_CANONICAL_INSTALL_DIR", self._orig_install_dir,
        ))

        # Scrub the env override — real CI envs occasionally set it.
        self._env_backup = os.environ.pop("DEFENSECLAW_GATEWAY_BIN", None)
        self.addCleanup(self._restore_env)

    def _restore_env(self) -> None:
        if self._env_backup is not None:
            os.environ["DEFENSECLAW_GATEWAY_BIN"] = self._env_backup
        else:
            os.environ.pop("DEFENSECLAW_GATEWAY_BIN", None)

    def _make_executable(self, path: str) -> None:
        """Create an empty file at *path* with the exec bit set."""
        with open(path, "w") as f:
            f.write("#!/bin/sh\n")
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)

    def test_env_override_wins_over_path_and_fallback(self):
        # Override wins even when the canonical path would also resolve:
        # packagers rely on this to vendor the binary elsewhere.
        canonical = gateway.canonical_install_path()
        self._make_executable(canonical)

        override = os.path.join(self._tmp.name, "custom-gw")
        self._make_executable(override)
        os.environ["DEFENSECLAW_GATEWAY_BIN"] = override

        with patch.object(gateway.shutil, "which", return_value="/from/path/gw"):
            self.assertEqual(gateway.resolve_gateway_binary(), override)

    def test_env_override_is_returned_verbatim_even_if_missing(self):
        # Honour the override even when the file is missing so the real
        # exec error surfaces to the user instead of a generic "not
        # found" — much easier to debug a "no such file" from the
        # caller than our opaque fallback.
        override = os.path.join(self._tmp.name, "does-not-exist")
        os.environ["DEFENSECLAW_GATEWAY_BIN"] = override

        with patch.object(gateway.shutil, "which", return_value=None):
            self.assertEqual(gateway.resolve_gateway_binary(), override)

    def test_path_wins_when_no_override(self):
        with patch.object(gateway.shutil, "which", return_value="/opt/bin/defenseclaw-gateway"):
            self.assertEqual(
                gateway.resolve_gateway_binary(),
                "/opt/bin/defenseclaw-gateway",
            )

    def test_falls_back_to_canonical_when_path_empty(self):
        # The bug this helper was written to fix: just-installed binary
        # at ~/.local/bin that isn't on PATH yet.
        canonical = gateway.canonical_install_path()
        self._make_executable(canonical)

        with patch.object(gateway.shutil, "which", return_value=None):
            self.assertEqual(gateway.resolve_gateway_binary(), canonical)

    def test_returns_none_when_nothing_resolves(self):
        # Canonical dir exists (it's the tmpdir) but no binary inside.
        with patch.object(gateway.shutil, "which", return_value=None):
            self.assertIsNone(gateway.resolve_gateway_binary())

    def test_canonical_fallback_requires_exec_bit(self):
        # A stray non-executable file at the canonical path must not
        # masquerade as a working binary.
        canonical = gateway.canonical_install_path()
        with open(canonical, "w") as f:
            f.write("not an executable")
        # Explicitly strip any exec bit that the umask may have granted.
        os.chmod(canonical, 0o644)

        with patch.object(gateway.shutil, "which", return_value=None):
            self.assertIsNone(gateway.resolve_gateway_binary())


if __name__ == "__main__":
    unittest.main()
