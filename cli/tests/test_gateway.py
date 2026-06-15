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


class OrchestratorClientWireFormatTests(unittest.TestCase):
    """Tests that pin the exact HTTP request the OrchestratorClient
    sends for the AI-discovery endpoints.

    These tests caught two production bugs (from the
    dedup-evidence-confidence review):

    * F1 — the validate endpoint posted ``Content-Type: application/x-yaml``
      which the sidecar's CSRF gate rejects with HTTP 415. Pre-fix
      this was 100% broken in production but the unit tests stubbed
      the client entirely.
    * F3 — ``ai_usage_component_locations`` / ``_history`` interpolated
      ``ecosystem`` and ``name`` straight into the URL via f-string,
      so any name with ``/``, ``?``, ``#``, ``%``, or whitespace
      produced a malformed URL.
    """

    def _client_with_capturing_session(self):
        """Build an OrchestratorClient whose Session captures every
        outbound request. Returns ``(client, requests)`` where
        ``requests`` is a list of ``SimpleNamespace`` capturing
        method, url, headers, json body, and form-data body for each
        call.
        """
        from types import SimpleNamespace
        from unittest.mock import MagicMock

        captured: list = []

        def fake_request(method, url, **kwargs):
            captured.append(SimpleNamespace(
                method=method,
                url=url,
                headers={**kwargs.get("headers", {})},
                json=kwargs.get("json"),
                data=kwargs.get("data"),
                params=kwargs.get("params"),
            ))
            resp = MagicMock()
            resp.status_code = 200
            resp.json = MagicMock(return_value={"valid": True, "ok": True})
            resp.raise_for_status = MagicMock()
            return resp

        client = gateway.OrchestratorClient(token="t")
        client._session.get = lambda url, **kw: fake_request("GET", url, **kw)
        client._session.post = lambda url, **kw: fake_request("POST", url, **kw)
        return client, captured

    def test_validate_uses_json_envelope_with_yaml_field(self):
        # The wire format MUST be JSON ({"yaml": "..."}) so the
        # request passes the sidecar's CSRF gate (Content-Type:
        # application/json). Any change to a raw-yaml body is a
        # production regression -- pin both the field name and the
        # Content-Type via requests' json= keyword (which forces
        # application/json automatically).
        client, captured = self._client_with_capturing_session()
        client.ai_usage_validate_confidence_policy("version: 1\n")

        self.assertEqual(len(captured), 1)
        req = captured[0]
        self.assertEqual(req.method, "POST")
        self.assertTrue(req.url.endswith("/api/v1/ai-usage/confidence/policy/validate"))
        self.assertEqual(req.json, {"yaml": "version: 1\n"})
        # The pre-fix bug was data=yaml + Content-Type=application/x-yaml.
        # If either ever shows up here again, the validate endpoint
        # will 415 in production.
        self.assertIsNone(req.data, "must not pass raw body via data=")
        # requests.Session.post(json=...) sets Content-Type to
        # application/json automatically; we don't pass headers ourselves.
        self.assertNotIn("Content-Type", req.headers)

    def test_locations_url_encodes_ecosystem_and_name(self):
        client, captured = self._client_with_capturing_session()
        client.ai_usage_component_locations("npm", "@org/foo bar")

        self.assertEqual(len(captured), 1)
        url = captured[0].url
        # Spaces, @, /, all must be percent-encoded so the gateway
        # mux can split on slashes correctly. parseComponentPath
        # rejects three-segment paths like "@org/foo/bar/locations"
        # so without encoding this call would 400 in production.
        self.assertIn("%40org%2Ffoo%20bar", url)
        self.assertTrue(url.endswith("/locations"))
        self.assertIn("/api/v1/ai-usage/components/npm/", url)

    def test_history_url_encodes_ecosystem_and_name(self):
        client, captured = self._client_with_capturing_session()
        client.ai_usage_component_history("py%pi", "open?ai")

        url = captured[0].url
        self.assertIn("py%25pi", url)        # % → %25
        self.assertIn("open%3Fai", url)      # ? → %3F
        self.assertTrue(url.endswith("/history"))

    def test_validate_413_is_normalized_to_failure_payload(self):
        # The 413 path bypasses raise_for_status and returns a
        # synthetic {"valid": false, ...} so callers don't need a
        # special-case branch for over-cap files.
        from unittest.mock import MagicMock

        client = gateway.OrchestratorClient(token="t")
        resp = MagicMock()
        resp.status_code = 413
        resp.raise_for_status = MagicMock()
        client._session.post = lambda *a, **kw: resp

        out = client.ai_usage_validate_confidence_policy("x" * 100)
        self.assertEqual(out, {"valid": False, "error": "policy file exceeds size limit"})


if __name__ == "__main__":
    unittest.main()
