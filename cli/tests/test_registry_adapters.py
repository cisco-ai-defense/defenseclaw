# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for every registry adapter — clawhub, smithery, http_yaml /
http_json, file, git, skills_sh.

These complement ``test_registry_sync.py`` (which stubs
``fetch_manifest`` to test promotion logic) by exercising each adapter's
HTTP / git / parsing behaviour against fixture responses. We mock at
the ``_base.requests`` boundary (so the SSRF + size + redirect guards
in ``_base.http_get`` actually run) and stub DNS via the ``resolver``
parameter so the suite never touches real network.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.config import RegistrySource
from defenseclaw.registries.adapters import IngestError, fetch_manifest
from defenseclaw.registries.adapters import _base as adapter_base
from defenseclaw.registries.adapters.clawhub import fetch_clawhub
from defenseclaw.registries.adapters.file import fetch_file
from defenseclaw.registries.adapters.git import fetch_git
from defenseclaw.registries.adapters.http_manifest import fetch_http
from defenseclaw.registries.adapters.skills_sh import (
    DEFAULT_BASE_URL,
    KNOWN_VIEWS,
    fetch_skills_sh,
)
from defenseclaw.registries.adapters.smithery import fetch_smithery

# ---------------------------------------------------------------------------
# requests.get mock
# ---------------------------------------------------------------------------

class _FakeResp:
    """Tiny shim mirroring the requests.Response surface http_get touches.

    We only emulate the bits actually called inside _base.http_get:
    ``__enter__`` / ``__exit__``, ``close``, ``raise_for_status``,
    ``iter_content``, ``headers``, ``is_redirect``. Each fake response
    is single-use because http_get streams once.
    """

    def __init__(
        self,
        body: bytes = b"",
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
        redirect_to: str | None = None,
    ):
        self._body = body
        self.status_code = status
        self.headers = dict(headers or {})
        self.is_redirect = redirect_to is not None
        if redirect_to:
            self.headers.setdefault("Location", redirect_to)
        self._closed = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        self._closed = True

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests

            raise requests.HTTPError(f"HTTP {self.status_code}")

    def iter_content(self, chunk_size: int = 65536):
        # Yield as a single chunk — _base.http_get treats the stream
        # as opaque so the chunk boundary doesn't matter for behaviour.
        if self._body:
            yield self._body


class _MockTransport:
    """Sequence-aware mock for requests.get.

    Each call to ``requests.get`` consumes one response from the
    ``responses`` list. If a route map is supplied we look up by URL
    instead so tests with retries / pagination don't need to stack
    responses in call order.
    """

    def __init__(
        self,
        *,
        responses: list[_FakeResp] | None = None,
        routes: dict[str, _FakeResp] | None = None,
    ):
        self._responses = list(responses or [])
        self._routes = dict(routes or {})
        self.calls: list[dict] = []

    def __call__(self, url, *, headers=None, timeout=None, stream=None,
                 allow_redirects=None):
        self.calls.append({
            "url": url,
            "headers": dict(headers or {}),
            "timeout": timeout,
            "stream": stream,
            "allow_redirects": allow_redirects,
        })
        if url in self._routes:
            return self._routes[url]
        if not self._responses:
            raise AssertionError(f"unexpected request to {url}")
        return self._responses.pop(0)


def _stub_resolver():
    """Resolver that maps known public-looking hosts to 8.8.8.8.

    Hosts not in the table return [] — _base.http_get's SSRF guard
    treats that as "could not validate", so unknown hosts get rejected
    just like in production. 8.8.8.8 is globally routable and not
    flagged as ``is_reserved`` (unlike RFC5737 ranges) so it passes
    every guard.
    """
    table = {
        "catalog.example.com": ["8.8.8.8"],
        "registry.example.com": ["8.8.8.8"],
        "registry.npmjs.org": ["8.8.8.8"],
        "registry.smithery.ai": ["8.8.8.8"],
        "server.example.com": ["8.8.8.8"],
        "skills.sh": ["8.8.8.8"],
        "mirror.example.com": ["8.8.8.8"],
        "evil.invalid": ["127.0.0.1"],
        "internal.invalid": ["10.0.0.5"],
    }

    def _resolve(host):
        return list(table.get(host, []))
    return _resolve


# ---------------------------------------------------------------------------
# clawhub
# ---------------------------------------------------------------------------

class TestClawhubAdapter(unittest.TestCase):
    """Verifies the npm-metadata path produces a valid Manifest and that
    the SSRF / size guards are now wired through (they were skipped in
    the previous direct-requests.get implementation)."""

    def _src(self, url: str = "") -> RegistrySource:
        return RegistrySource(id="ch", kind="clawhub", url=url, content="skill")

    def test_default_npmjs_extracts_plugins(self):
        body = json.dumps({
            "openclaw": {
                "plugins": {
                    "demo-skill": {
                        "version": "1.2.3",
                        "license": "Apache-2.0",
                        "description": "desc",
                        "homepage": "https://example.com",
                    },
                    "another-one": {"version": "0.0.1"},
                },
            },
            "time": {"modified": "2026-01-01T00:00:00Z"},
        }).encode("utf-8")

        transport = _MockTransport(responses=[_FakeResp(body)])
        with patch.object(adapter_base.requests, "get", transport):
            manifest, raw = fetch_clawhub(
                self._src(), resolver=_stub_resolver(),
            )

        self.assertEqual(manifest.publisher, "clawhub")
        self.assertEqual(manifest.generated_at, "2026-01-01T00:00:00Z")
        names = sorted(e.name for e in manifest.entries)
        self.assertEqual(names, ["another-one", "demo-skill"])
        self.assertEqual(raw, body)
        self.assertTrue(transport.calls[0]["url"].endswith("/openclaw/latest"))
        self.assertEqual(
            transport.calls[0]["headers"]["Accept"], "application/json",
        )

    def test_top_level_plugins_fallback(self):
        body = json.dumps({
            "plugins": {"top-level-only": {}},
        }).encode("utf-8")
        with patch.object(
            adapter_base.requests, "get",
            _MockTransport(responses=[_FakeResp(body)]),
        ):
            manifest, _ = fetch_clawhub(self._src(), resolver=_stub_resolver())
        self.assertEqual([e.name for e in manifest.entries], ["top-level-only"])

    def test_invalid_plugin_names_skipped(self):
        body = json.dumps({
            "openclaw": {
                "plugins": {
                    "ok-name": {},
                    "../escape": {},        # rejected by NAME_RE
                    "x" * 200: {},          # too long
                },
            },
        }).encode("utf-8")
        with patch.object(
            adapter_base.requests, "get",
            _MockTransport(responses=[_FakeResp(body)]),
        ):
            manifest, _ = fetch_clawhub(self._src(), resolver=_stub_resolver())
        self.assertEqual([e.name for e in manifest.entries], ["ok-name"])

    def test_missing_plugins_map_yields_empty_manifest(self):
        # An openclaw package without a plugins map is a valid (if
        # unusual) state — it means "no skills published". We surface
        # that as an empty manifest rather than an error so a
        # mid-bootstrap registry doesn't permanently fail sync.
        body = b'{"name":"openclaw"}'
        with patch.object(
            adapter_base.requests, "get",
            _MockTransport(responses=[_FakeResp(body)]),
        ):
            manifest, _ = fetch_clawhub(self._src(), resolver=_stub_resolver())
        self.assertEqual(manifest.entries, [])

    def test_non_dict_plugins_field_raises(self):
        # An older / mis-published openclaw package that ships
        # `plugins: ["a","b"]` instead of a dict — the adapter
        # explicitly refuses so an operator's `registry sync` fails
        # loudly instead of silently importing zero entries.
        body = b'{"openclaw":{"plugins":["bad"]}}'
        with patch.object(
            adapter_base.requests, "get",
            _MockTransport(responses=[_FakeResp(body)]),
        ), self.assertRaises(IngestError) as cm:
            fetch_clawhub(self._src(), resolver=_stub_resolver())
        self.assertIn("plugins map", str(cm.exception))

    def test_non_json_body_raises(self):
        with patch.object(
            adapter_base.requests, "get",
            _MockTransport(responses=[_FakeResp(b"<html>oops</html>")]),
        ), self.assertRaises(IngestError) as cm:
            fetch_clawhub(self._src(), resolver=_stub_resolver())
        self.assertIn("not valid JSON", str(cm.exception))

    def test_http_error_propagates_as_ingest_error(self):
        with patch.object(
            adapter_base.requests, "get",
            _MockTransport(responses=[_FakeResp(b"", status=503)]),
        ), self.assertRaises(IngestError):
            fetch_clawhub(self._src(), resolver=_stub_resolver())

    def test_ssrf_guard_rejects_internal_registry(self):
        # No requests.get patch is needed — the SSRF guard fires
        # before we ever try the network. This is the key regression
        # test: the previous direct-requests implementation silently
        # allowed http://internal.invalid as a registry URL.
        with self.assertRaises(IngestError) as cm:
            fetch_clawhub(
                self._src(url="http://internal.invalid"),
                resolver=_stub_resolver(),
            )
        self.assertIn("private", str(cm.exception))

    def test_non_http_registry_url_rejected(self):
        with self.assertRaises(IngestError) as cm:
            fetch_clawhub(
                self._src(url="ftp://example.com"),
                resolver=_stub_resolver(),
            )
        self.assertIn("http(s)", str(cm.exception))


# ---------------------------------------------------------------------------
# smithery
# ---------------------------------------------------------------------------

class TestSmitheryAdapter(unittest.TestCase):
    def _src(self, url: str = "") -> RegistrySource:
        return RegistrySource(id="sm", kind="smithery", url=url, content="mcp")

    def _post(self, body: bytes, url: str = "https://registry.smithery.ai/servers"):
        transport = _MockTransport(responses=[_FakeResp(body)])
        with patch.object(adapter_base.requests, "get", transport):
            manifest, raw = fetch_smithery(
                self._src(url=url), resolver=_stub_resolver(),
            )
        return manifest, raw, transport

    def test_servers_envelope_extracted(self):
        body = json.dumps({
            "servers": [
                {
                    "qualifiedName": "demo-server",
                    "version": "0.1.0",
                    "license": "MIT",
                    "deployment": {
                        "transport": "stdio",
                        "command": "/usr/bin/demo",
                        "args": ["--mcp"],
                        "env": {"DEMO_TOKEN": ""},
                    },
                },
            ],
        }).encode("utf-8")
        manifest, _, _ = self._post(body)
        self.assertEqual([e.name for e in manifest.entries], ["demo-server"])
        e = manifest.entries[0]
        self.assertEqual(e.transport, "stdio")
        self.assertEqual(e.command, "/usr/bin/demo")
        self.assertEqual(e.args, ["--mcp"])
        self.assertEqual(e.env_required, ["DEMO_TOKEN"])

    def test_data_envelope_also_supported(self):
        body = json.dumps({
            "data": [
                {
                    "name": "@scope/something",
                    "deployment": {
                        "transport": "http",
                        "url": "https://server.example.com/mcp",
                    },
                },
            ],
        }).encode("utf-8")
        manifest, _, _ = self._post(body)
        # Slash and @ get normalised into a NAME_RE-compatible value.
        self.assertEqual([e.name for e in manifest.entries], ["scope-something"])
        self.assertEqual(manifest.entries[0].transport, "http")
        self.assertEqual(
            manifest.entries[0].url, "https://server.example.com/mcp",
        )

    def test_top_level_array_supported(self):
        body = json.dumps([
            {
                "name": "bare-array-form",
                "deployment": {
                    "transport": "stdio",
                    "command": "/bin/echo",
                },
            },
        ]).encode("utf-8")
        manifest, _, _ = self._post(body)
        self.assertEqual([e.name for e in manifest.entries], ["bare-array-form"])

    def test_unknown_envelope_raises(self):
        body = b'{"foo":"bar"}'
        transport = _MockTransport(responses=[_FakeResp(body)])
        with patch.object(adapter_base.requests, "get", transport), \
                self.assertRaises(IngestError) as cm:
            fetch_smithery(self._src(), resolver=_stub_resolver())
        self.assertIn("missing a servers array", str(cm.exception))

    def test_non_json_response_raises(self):
        transport = _MockTransport(responses=[_FakeResp(b"yaml: not-json")])
        with patch.object(adapter_base.requests, "get", transport), \
                self.assertRaises(IngestError) as cm:
            fetch_smithery(self._src(), resolver=_stub_resolver())
        self.assertIn("not valid JSON", str(cm.exception))

    def test_malformed_rows_silently_skipped(self):
        body = json.dumps({
            "servers": [
                None,
                "string-row",
                {},                     # empty dict — missing name → skip
                {                       # bad command chars → skip
                    "name": "bad-cmd",
                    "deployment": {
                        "transport": "stdio",
                        "command": "echo;rm -rf /",
                    },
                },
                {                       # stdio with no command → skip
                    "name": "no-cmd",
                    "deployment": {"transport": "stdio"},
                },
                {                       # non-stdio with no url → skip
                    "name": "no-url",
                    "deployment": {"transport": "http"},
                },
                {                       # ok row
                    "name": "good",
                    "deployment": {
                        "transport": "stdio", "command": "/bin/ok",
                    },
                },
            ],
        }).encode("utf-8")
        manifest, _, _ = self._post(body)
        self.assertEqual([e.name for e in manifest.entries], ["good"])

    def test_non_stdio_url_must_be_https_and_public(self):
        # smithery entries with http:// URLs or URLs that resolve to
        # internal IPs go straight into asset_policy.mcp.registry once
        # promoted, so they must be filtered at ingest time. The
        # adapter rejects each row but keeps clean ones.
        body = json.dumps({
            "servers": [
                {
                    "name": "plain-http",
                    "deployment": {
                        "transport": "http",
                        "url": "http://server.example.com/mcp",
                    },
                },
                {
                    "name": "internal",
                    "deployment": {
                        "transport": "http",
                        "url": "https://internal.invalid/mcp",
                    },
                },
                {
                    "name": "ok",
                    "deployment": {
                        "transport": "http",
                        "url": "https://server.example.com/mcp",
                    },
                },
            ],
        }).encode("utf-8")
        manifest, _, _ = self._post(body)
        self.assertEqual([e.name for e in manifest.entries], ["ok"])

    def test_unknown_transport_rejected_after_validate_entry(self):
        # H-3: Smithery now routes synthesized rows through
        # validate_entry() which strictly enforces KNOWN_TRANSPORTS.
        # The previous behavior silently coerced unknown transports to
        # "stdio" — masking publisher bugs and (worse) admitting
        # entries the downstream scanner could not properly classify.
        # The strict path drops the row instead so the operator sees
        # a 0-entry manifest and a structured warning rather than a
        # mis-labelled "stdio" command pretending to be carrier-pigeon.
        body = json.dumps({
            "servers": [
                {
                    "name": "weird",
                    "deployment": {
                        "transport": "carrier-pigeon",
                        "command": "/bin/ok",
                        "url": "https://server.example.com/mcp",
                    },
                },
                {
                    "name": "ok",
                    "deployment": {
                        "transport": "stdio",
                        "command": "/bin/ok",
                    },
                },
            ],
        }).encode("utf-8")
        manifest, _, _ = self._post(body)
        # Only the validly-typed entry survives; the carrier-pigeon
        # row is dropped via the IngestError per-row handler.
        self.assertEqual([e.name for e in manifest.entries], ["ok"])

    def test_invalid_env_var_name_rejected(self):
        # H-3: validate_entry enforces ENV_VAR_RE — names that don't
        # match must be rejected, not stored. Smithery's previous
        # synthesizer copied env keys verbatim with only a length cap.
        body = json.dumps({
            "servers": [
                {
                    "name": "lower-env",
                    "deployment": {
                        "transport": "stdio",
                        "command": "/bin/ok",
                        # lowercase + dash — fails ENV_VAR_RE
                        "env": ["api-key"],
                    },
                },
                {
                    "name": "good-env",
                    "deployment": {
                        "transport": "stdio",
                        "command": "/bin/ok",
                        "env": ["API_KEY"],
                    },
                },
            ],
        }).encode("utf-8")
        manifest, _, _ = self._post(body)
        self.assertEqual([e.name for e in manifest.entries], ["good-env"])

    def test_auth_env_passed_as_bearer(self):
        body = b'{"servers":[]}'
        transport = _MockTransport(responses=[_FakeResp(body)])
        try:
            os.environ["TEST_SMITHERY_TOK"] = "  abc123  "
            src = RegistrySource(
                id="sm", kind="smithery", auth_env="TEST_SMITHERY_TOK",
            )
            with patch.object(adapter_base.requests, "get", transport):
                fetch_smithery(src, resolver=_stub_resolver())
        finally:
            os.environ.pop("TEST_SMITHERY_TOK", None)
        self.assertEqual(
            transport.calls[0]["headers"]["Authorization"], "Bearer abc123",
        )

    def test_size_cap_aborts_huge_response(self):
        # Synthesise a body bigger than MAX_MANIFEST_BYTES (8 MiB).
        big = b'{"servers":[]}' + b" " * (
            adapter_base.MAX_MANIFEST_BYTES + 1024
        )
        transport = _MockTransport(
            responses=[_FakeResp(big, headers={
                "Content-Length": str(len(big)),
            })],
        )
        with patch.object(adapter_base.requests, "get", transport), \
                self.assertRaises(IngestError) as cm:
            fetch_smithery(self._src(), resolver=_stub_resolver())
        self.assertIn("max", str(cm.exception))


# ---------------------------------------------------------------------------
# http_yaml / http_json
# ---------------------------------------------------------------------------

class TestHTTPManifestAdapter(unittest.TestCase):
    def _src(self, url: str, kind: str = "http_yaml") -> RegistrySource:
        return RegistrySource(id="h", kind=kind, url=url, content="skill")

    def test_yaml_body_parses(self):
        body = (
            b"schema_version: 1\n"
            b"publisher: corp\n"
            b"entries:\n"
            b"  - {name: my-skill, type: skill, "
            b"source_url: 'https://example.com/x.tgz'}\n"
        )
        transport = _MockTransport(responses=[_FakeResp(body)])
        with patch.object(adapter_base.requests, "get", transport):
            manifest, raw = fetch_http(
                self._src("https://catalog.example.com/skills.yaml"),
                resolver=_stub_resolver(),
            )
        self.assertEqual(manifest.publisher, "corp")
        self.assertEqual(manifest.entries[0].name, "my-skill")
        self.assertEqual(raw, body)

    def test_json_body_parses(self):
        body = json.dumps({
            "schema_version": 1,
            "entries": [
                {
                    "name": "from-json",
                    "type": "skill",
                    "source_url": "clawhub://from-json",
                },
            ],
        }).encode("utf-8")
        with patch.object(
            adapter_base.requests, "get",
            _MockTransport(responses=[_FakeResp(body)]),
        ):
            manifest, _ = fetch_http(
                self._src("https://catalog.example.com/x.json", "http_json"),
                resolver=_stub_resolver(),
            )
        self.assertEqual(manifest.entries[0].name, "from-json")

    def test_redirect_chain_revalidated(self):
        # Server returns a redirect; http_get must call guard_url on
        # the new Location, then issue a second request. We simulate
        # by routing the redirect target back through requests.get.
        first = _FakeResp(b"", status=302, redirect_to="https://mirror.example.com/x.json")
        second = _FakeResp(b'{"schema_version":1,"entries":[]}')
        transport = _MockTransport(responses=[first, second])
        with patch.object(adapter_base.requests, "get", transport):
            manifest, _ = fetch_http(
                self._src("https://catalog.example.com/x.json", "http_json"),
                resolver=_stub_resolver(),
            )
        self.assertEqual(manifest.entries, [])
        self.assertEqual(len(transport.calls), 2)
        self.assertEqual(
            transport.calls[1]["url"], "https://mirror.example.com/x.json",
        )

    def test_redirect_to_private_blocked(self):
        first = _FakeResp(
            b"", status=302,
            redirect_to="https://internal.invalid/x.json",
        )
        transport = _MockTransport(responses=[first])
        with patch.object(adapter_base.requests, "get", transport), \
                self.assertRaises(IngestError) as cm:
            fetch_http(
                self._src("https://catalog.example.com/x.json", "http_json"),
                resolver=_stub_resolver(),
            )
        self.assertIn("redirect blocked", str(cm.exception))

    def test_empty_url_rejected(self):
        with self.assertRaises(IngestError):
            fetch_http(self._src(""), resolver=_stub_resolver())

    def test_huge_content_length_aborts_before_read(self):
        body = b'{"x":1}'
        resp = _FakeResp(body, headers={
            "Content-Length": str(adapter_base.MAX_MANIFEST_BYTES + 100),
        })
        with patch.object(
            adapter_base.requests, "get",
            _MockTransport(responses=[resp]),
        ), self.assertRaises(IngestError):
            fetch_http(
                self._src("https://catalog.example.com/big.yaml"),
                resolver=_stub_resolver(),
            )


# ---------------------------------------------------------------------------
# file
# ---------------------------------------------------------------------------

class TestFileAdapter(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dc-file-adapter-")
        self.path = Path(self.tmp) / "manifest.yaml"
        self.path.write_text(
            "schema_version: 1\n"
            "entries:\n"
            "  - {name: from-file, type: skill, source_url: 'https://x.example/s'}\n"
        )

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_absolute_path_loads(self):
        src = RegistrySource(
            id="f", kind="file", url=str(self.path), content="skill",
        )
        manifest, _ = fetch_file(src)
        self.assertEqual([e.name for e in manifest.entries], ["from-file"])

    def test_file_scheme_stripped(self):
        src = RegistrySource(
            id="f", kind="file", url=f"file://{self.path}", content="skill",
        )
        manifest, _ = fetch_file(src)
        self.assertEqual(manifest.entries[0].name, "from-file")

    def test_relative_path_rejected(self):
        src = RegistrySource(
            id="f", kind="file", url="manifest.yaml", content="skill",
        )
        with self.assertRaises(IngestError) as cm:
            fetch_file(src)
        self.assertIn("absolute", str(cm.exception))

    def test_missing_file_rejected(self):
        src = RegistrySource(
            id="f", kind="file",
            url=str(Path(self.tmp) / "nope.yaml"), content="skill",
        )
        with self.assertRaises(IngestError):
            fetch_file(src)

    def test_directory_rejected(self):
        src = RegistrySource(
            id="f", kind="file", url=self.tmp, content="skill",
        )
        with self.assertRaises(IngestError) as cm:
            fetch_file(src)
        self.assertIn("not a regular file", str(cm.exception))

    def test_size_cap_enforced(self):
        big = self.path.with_name("big.yaml")
        big.write_bytes(b" " * (adapter_base.MAX_MANIFEST_BYTES + 1))
        src = RegistrySource(
            id="f", kind="file", url=str(big), content="skill",
        )
        with self.assertRaises(IngestError):
            fetch_file(src)


# ---------------------------------------------------------------------------
# git
# ---------------------------------------------------------------------------

@unittest.skipUnless(
    subprocess.run(  # noqa: S603,S607 - intentional path lookup
        ["which", "git"], capture_output=True, check=False,
    ).returncode == 0,
    "git not available",
)
class TestGitAdapter(unittest.TestCase):
    """End-to-end test against a local file:// repo via http(s) shim.

    Because the SSRF guard rejects file:// schemes outright, we can't
    point fetch_git at a tempdir. Instead we monkeypatch
    ``subprocess.run`` to write the expected manifest into the
    tempdir the adapter passes as the clone target, simulating a
    successful clone without going to the network.
    """

    def _src(self, url: str = "https://catalog.example.com/registry.git"):
        return RegistrySource(id="g", kind="git", url=url, content="skill")

    def _fake_clone(self, manifest: bytes, name: str = "defenseclaw-registry.yaml"):
        def _run(cmd, **kwargs):
            # cmd = ["git", "clone", "--depth", "1", "--no-tags",
            #        "--single-branch", "--", url, tmp]
            tmp = cmd[-1]
            (Path(tmp) / name).write_bytes(manifest)

            class _R:
                returncode = 0
                stderr = ""

            return _R()
        return _run

    def test_success_loads_yaml(self):
        body = (
            b"schema_version: 1\n"
            b"entries:\n"
            b"  - {name: git-skill, type: skill, source_url: 'https://x/y'}\n"
        )
        with patch("subprocess.run", side_effect=self._fake_clone(body)):
            manifest, raw = fetch_git(self._src(), resolver=_stub_resolver())
        self.assertEqual([e.name for e in manifest.entries], ["git-skill"])
        self.assertEqual(raw, body)

    def test_yml_filename_also_picked_up(self):
        body = b'{"schema_version":1,"entries":[]}'
        with patch(
            "subprocess.run",
            side_effect=self._fake_clone(body, name="defenseclaw-registry.yml"),
        ):
            manifest, _ = fetch_git(self._src(), resolver=_stub_resolver())
        self.assertEqual(manifest.entries, [])

    def test_clone_failure_reports_stderr(self):
        def _fail(cmd, **kwargs):
            class _R:
                returncode = 128
                stderr = "fatal: bad refs"
            return _R()

        with patch("subprocess.run", side_effect=_fail), \
                self.assertRaises(IngestError) as cm:
            fetch_git(self._src(), resolver=_stub_resolver())
        self.assertIn("fatal: bad refs", str(cm.exception))

    def test_no_manifest_at_root_rejected(self):
        def _empty(cmd, **kwargs):
            class _R:
                returncode = 0
                stderr = ""
            return _R()

        with patch("subprocess.run", side_effect=_empty), \
                self.assertRaises(IngestError) as cm:
            fetch_git(self._src(), resolver=_stub_resolver())
        self.assertIn("no defenseclaw-registry manifest", str(cm.exception))

    def test_ssh_url_rejected(self):
        with self.assertRaises(IngestError):
            fetch_git(
                self._src(url="git@github.com:owner/repo.git"),
                resolver=_stub_resolver(),
            )

    def test_credentials_in_url_rejected(self):
        with self.assertRaises(IngestError):
            fetch_git(self._src(
                url="https://user:secret@catalog.example.com/repo.git",
            ), resolver=_stub_resolver())

    def test_shell_metacharacters_rejected(self):
        with self.assertRaises(IngestError):
            fetch_git(self._src(
                url="https://catalog.example.com/repo;rm -rf /.git",
            ), resolver=_stub_resolver())

    def test_empty_url_rejected(self):
        with self.assertRaises(IngestError):
            fetch_git(self._src(url=""), resolver=_stub_resolver())

    def test_private_host_rejected_by_ssrf(self):
        # The git URL should run through guard_git_url → guard_url, so
        # an internal host fails before we ever exec git. Without
        # this guard the operator could point a registry at internal
        # infra and trigger an outbound git clone the gateway would
        # otherwise refuse for HTTP fetches.
        with self.assertRaises(IngestError) as cm:
            fetch_git(
                self._src(url="https://internal.invalid/repo.git"),
                resolver=_stub_resolver(),
            )
        self.assertIn("private", str(cm.exception))


# ---------------------------------------------------------------------------
# skills.sh
# ---------------------------------------------------------------------------

class TestSkillsShAdapter(unittest.TestCase):
    """Tests for the skills.sh adapter against fixture API responses.

    Rather than hand-rolling JSON in every test we reuse the shape
    documented at https://skills.sh/docs/api so a future schema drift
    surfaces here first.
    """

    def _src(self, url: str = "") -> RegistrySource:
        return RegistrySource(id="ss", kind="skills_sh", url=url, content="skill")

    def _curated_payload(self):
        return {
            "data": [
                {
                    "owner": "vercel-labs",
                    "totalInstalls": 89240,
                    "featuredRepo": "agent-skills",
                    "featuredSkill": "Next.js Development",
                    "skills": [
                        {
                            "id": "vercel-labs/agent-skills/next-js-development",
                            "slug": "next-js-development",
                            "name": "Next.js Development",
                            "source": "vercel-labs/agent-skills",
                            "installs": 24531,
                            "sourceType": "github",
                            "installUrl": "https://github.com/vercel-labs/agent-skills",
                            "url": "https://skills.sh/vercel-labs/agent-skills/next-js-development",
                        },
                        {
                            # Duplicate fork — must be filtered out.
                            "id": "vercel-labs/agent-skills/copy-of-it",
                            "slug": "copy-of-it",
                            "name": "Copy",
                            "source": "vercel-labs/agent-skills",
                            "installs": 0,
                            "sourceType": "github",
                            "installUrl": "https://github.com/vercel-labs/agent-skills",
                            "url": "https://skills.sh/vercel-labs/agent-skills/copy-of-it",
                            "isDuplicate": True,
                        },
                    ],
                },
                {
                    "owner": "anthropics",
                    "totalInstalls": 50000,
                    "skills": [
                        {
                            "id": "anthropics/skills/frontend-design",
                            "slug": "frontend-design",
                            "name": "Frontend Design",
                            "source": "anthropics/skills",
                            "installs": 379000,
                            "sourceType": "github",
                            "installUrl": "https://github.com/anthropics/skills",
                            "url": "https://skills.sh/anthropics/skills/frontend-design",
                        },
                    ],
                },
            ],
            "totalOwners": 87,
            "totalSkills": 342,
            "generatedAt": "2026-03-31T08:00:00.000Z",
        }

    def _list_payload(self, view: str, items: list[dict], has_more: bool = False):
        return {
            "data": items,
            "pagination": {
                "page": 0, "perPage": len(items),
                "total": len(items), "hasMore": has_more,
            },
            "view": view,
        }

    def _skill(self, owner: str, repo: str, slug: str):
        return {
            "id": f"{owner}/{repo}/{slug}",
            "slug": slug,
            "name": slug.replace("-", " ").title(),
            "source": f"{owner}/{repo}",
            "installs": 1,
            "sourceType": "github",
            "installUrl": f"https://github.com/{owner}/{repo}",
            "url": f"https://skills.sh/{owner}/{repo}/{slug}",
        }

    def test_default_url_uses_curated_view(self):
        body = json.dumps(self._curated_payload()).encode("utf-8")
        transport = _MockTransport(responses=[_FakeResp(body)])
        with patch.object(adapter_base.requests, "get", transport):
            manifest, _ = fetch_skills_sh(
                self._src(), resolver=_stub_resolver(),
            )
        self.assertEqual(transport.calls[0]["url"],
                         f"{DEFAULT_BASE_URL}/api/v1/skills/curated")
        names = sorted(e.name for e in manifest.entries)
        # Two distinct skills survive; the duplicate is dropped.
        self.assertEqual(names, [
            "anthropics-skills-frontend-design",
            "vercel-labs-agent-skills-next-js-development",
        ])
        e = next(x for x in manifest.entries if "next-js" in x.name)
        self.assertEqual(e.type, "skill")
        self.assertEqual(e.publisher, "vercel-labs")
        self.assertEqual(e.source_url, "https://github.com/vercel-labs/agent-skills")
        self.assertEqual(e.tags, ["github"])

    def test_view_keyword_url(self):
        body = json.dumps(self._curated_payload()).encode("utf-8")
        transport = _MockTransport(responses=[_FakeResp(body)])
        with patch.object(adapter_base.requests, "get", transport):
            fetch_skills_sh(self._src(url="curated"), resolver=_stub_resolver())
        self.assertEqual(
            transport.calls[0]["url"],
            f"{DEFAULT_BASE_URL}/api/v1/skills/curated",
        )

    def test_paginated_all_time_walks_pages(self):
        page0 = self._list_payload("all-time", [
            self._skill("a", "b", "one"),
            self._skill("a", "b", "two"),
        ], has_more=True)
        page1 = self._list_payload("all-time", [
            self._skill("c", "d", "three"),
        ], has_more=False)
        transport = _MockTransport(responses=[
            _FakeResp(json.dumps(page0).encode("utf-8")),
            _FakeResp(json.dumps(page1).encode("utf-8")),
        ])
        with patch.object(adapter_base.requests, "get", transport):
            manifest, raw = fetch_skills_sh(
                self._src(url="all-time"), resolver=_stub_resolver(),
            )
        self.assertEqual([e.name for e in manifest.entries], [
            "a-b-one", "a-b-two", "c-d-three",
        ])
        # The cached "raw" bytes must be the FIRST page's body so an
        # operator inspecting manifest.json sees real server output,
        # not a stitched-together view.
        self.assertEqual(raw, json.dumps(page0).encode("utf-8"))
        # We sent ?view=all-time in the query string.
        self.assertIn("view=all-time", transport.calls[0]["url"])
        self.assertIn("page=0", transport.calls[0]["url"])
        self.assertIn("page=1", transport.calls[1]["url"])

    def test_max_caps_paged_results(self):
        page = self._list_payload("trending", [
            self._skill("a", "b", f"slug-{i}") for i in range(20)
        ], has_more=True)
        transport = _MockTransport(responses=[
            _FakeResp(json.dumps(page).encode("utf-8")),
        ])
        with patch.object(adapter_base.requests, "get", transport):
            manifest, _ = fetch_skills_sh(
                self._src(url="https://skills.sh?view=trending&max=5"),
                resolver=_stub_resolver(),
            )
        self.assertEqual(len(manifest.entries), 5)

    def test_invalid_view_rejected(self):
        with self.assertRaises(IngestError) as cm:
            fetch_skills_sh(
                self._src(url="https://skills.sh?view=carrier-pigeon"),
                resolver=_stub_resolver(),
            )
        self.assertIn("view must be one of", str(cm.exception))

    def test_invalid_per_page_rejected(self):
        with self.assertRaises(IngestError):
            fetch_skills_sh(
                self._src(url="https://skills.sh?view=all-time&per_page=999"),
                resolver=_stub_resolver(),
            )

    def test_invalid_max_rejected(self):
        with self.assertRaises(IngestError):
            fetch_skills_sh(
                self._src(url="https://skills.sh?view=all-time&max=999999"),
                resolver=_stub_resolver(),
            )

    def test_non_https_source_url_rejected(self):
        with self.assertRaises(IngestError):
            fetch_skills_sh(
                self._src(url="ftp://skills.sh/api"),
                resolver=_stub_resolver(),
            )

    def test_non_github_install_url_dropped(self):
        page = self._list_payload("trending", [
            {
                **self._skill("a", "b", "ok"),
                "installUrl": "https://github.com/a/b",
            },
            {
                **self._skill("a", "b", "weird"),
                "installUrl": "ftp://example.com/x",
            },
            {
                **self._skill("a", "b", "spoofed"),
                "sourceType": "github",
                # github-typed but pointing at a non-github URL → drop.
                "installUrl": "https://evil.example.com/repo",
            },
            {
                **self._skill("a", "b", "downgrade"),
                # http:// install URL is rejected even though the
                # host is github.com — TLS downgrade must not be
                # silently accepted.
                "installUrl": "http://github.com/a/b",
            },
        ], has_more=False)
        transport = _MockTransport(responses=[
            _FakeResp(json.dumps(page).encode("utf-8")),
        ])
        with patch.object(adapter_base.requests, "get", transport):
            manifest, _ = fetch_skills_sh(
                self._src(url="trending"),
                resolver=_stub_resolver(),
            )
        self.assertEqual([e.name for e in manifest.entries], ["a-b-ok"])

    def test_well_known_source_type_kept(self):
        # well-known sources skip the "github.com in URL" check.
        page = self._list_payload("all-time", [
            {
                "id": "mintlify.com/mintlify",
                "slug": "mintlify",
                "name": "Mintlify",
                "source": "mintlify.com",
                "installs": 9,
                "sourceType": "well-known",
                "installUrl": "https://mintlify.com",
                "url": "https://skills.sh/mintlify.com/mintlify",
            },
        ], has_more=False)
        transport = _MockTransport(responses=[
            _FakeResp(json.dumps(page).encode("utf-8")),
        ])
        with patch.object(adapter_base.requests, "get", transport):
            manifest, _ = fetch_skills_sh(
                self._src(url="all-time"),
                resolver=_stub_resolver(),
            )
        self.assertEqual([e.name for e in manifest.entries],
                         ["mintlify.com-mintlify"])
        self.assertEqual(manifest.entries[0].tags, ["well-known"])

    def test_malformed_rows_silently_skipped(self):
        page = self._list_payload("hot", [
            None,
            "string-row",
            {},                                          # missing id
            {"id": "x"},                                 # missing slug/source
            {                                            # missing slug
                "id": "owner/repo/",
                "slug": "",
                "source": "owner/repo",
                "installUrl": "https://github.com/owner/repo",
                "sourceType": "github",
            },
            {                                            # name strips to empty
                "id": "----",
                "slug": "----",
                "source": "----",
                "installUrl": "https://github.com/x/y",
                "sourceType": "github",
            },
            self._skill("good", "repo", "ok"),
        ], has_more=False)
        transport = _MockTransport(responses=[
            _FakeResp(json.dumps(page).encode("utf-8")),
        ])
        with patch.object(adapter_base.requests, "get", transport):
            manifest, _ = fetch_skills_sh(
                self._src(url="hot"),
                resolver=_stub_resolver(),
            )
        self.assertEqual([e.name for e in manifest.entries], ["good-repo-ok"])

    def test_auth_token_from_env(self):
        body = json.dumps(self._curated_payload()).encode("utf-8")
        transport = _MockTransport(responses=[_FakeResp(body)])
        try:
            os.environ["TEST_SKILLSSH_TOK"] = "sk_live_xxxxxxxxxx"
            src = RegistrySource(
                id="ss", kind="skills_sh", auth_env="TEST_SKILLSSH_TOK",
                content="skill",
            )
            with patch.object(adapter_base.requests, "get", transport):
                fetch_skills_sh(src, resolver=_stub_resolver())
        finally:
            os.environ.pop("TEST_SKILLSSH_TOK", None)
        self.assertEqual(
            transport.calls[0]["headers"]["Authorization"],
            "Bearer sk_live_xxxxxxxxxx",
        )

    def test_known_views_complete(self):
        # If the upstream API ever publishes a new view we want this
        # constant to fail loudly so the adapter gets an explicit
        # opt-in rather than silently dropping the operator request.
        self.assertEqual(
            set(KNOWN_VIEWS), {"all-time", "trending", "hot", "curated"},
        )


# ---------------------------------------------------------------------------
# fetch_manifest dispatch
# ---------------------------------------------------------------------------

class TestDispatch(unittest.TestCase):
    """The dispatcher must hand work to the right adapter and reject
    unknown kinds. We pre-mock requests so the HTTPS adapters succeed."""

    def test_skills_sh_routed_to_adapter(self):
        body = json.dumps({"data": []}).encode("utf-8")
        transport = _MockTransport(responses=[_FakeResp(body)])
        src = RegistrySource(
            id="ss", kind="skills_sh", url="curated", content="skill",
        )
        with patch.object(adapter_base.requests, "get", transport):
            manifest, _ = fetch_manifest(src, resolver=_stub_resolver())
        self.assertEqual(manifest.publisher, "skills.sh")

    def test_unknown_kind_rejected(self):
        with self.assertRaises(IngestError):
            fetch_manifest(
                RegistrySource(id="x", kind="totally-fake", content="skill"),
            )


# ---------------------------------------------------------------------------
# H-2 — DNS-rebind defense
# ---------------------------------------------------------------------------
#
# These tests live alongside the adapter tests because the pin is wired
# inside ``_base.http_get``: we need the integration assertion that
# the SSRF-vetted IP literal actually shows up in the connect path,
# not just in resolve_and_pin's return value.

class TestDNSRebindPin(unittest.TestCase):
    """The connect-pin must short-circuit urllib3.util.connection so a
    second DNS lookup performed by ``requests`` cannot resolve to a
    different IP than the one ``guard_url`` validated.
    """

    def test_pin_replaces_create_connection_during_fetch(self):
        # The fake transport never actually opens a TCP connection;
        # we only need to prove that during the with-block, the
        # urllib3 connect function is the pinned one. After the
        # block exits, the original is restored.
        from urllib3.util import connection as urllib3_connection

        body = b'{"servers":[]}'
        transport = _MockTransport(responses=[_FakeResp(body)])

        original_connect = urllib3_connection.create_connection
        seen_during: list[object] = []

        class _Spy:
            def __enter__(self):
                seen_during.append(urllib3_connection.create_connection)
                return self

            def __exit__(self, *exc):
                pass

        # Wrap the fetch so we can capture the live create_connection
        # at the moment requests.get is invoked. We patch
        # adapter_base.requests.get with a side-effecting transport
        # that records the function pointer urllib3 would use.
        def _recording_get(*args, **kwargs):
            seen_during.append(urllib3_connection.create_connection)
            return transport(*args, **kwargs)

        with patch.object(adapter_base.requests, "get", _recording_get):
            adapter_base.http_get(
                "https://catalog.example.com/manifest.yaml",
                resolver=_stub_resolver(),
            )

        # During the fetch, the connect function MUST have been the
        # pinned one (i.e. NOT the original urllib3 function). After
        # the fetch the original must be restored.
        self.assertTrue(seen_during)
        self.assertIsNot(seen_during[0], original_connect)
        self.assertIs(urllib3_connection.create_connection, original_connect)

    def test_pin_blocks_unexpected_hosts(self):
        """Defense in depth: a side-channel HTTP call to an unrelated
        host during a pinned fetch must raise SSRFError rather than
        sneaking out of the guard.
        """
        from defenseclaw.registries.ssrf import SSRFError
        from urllib3.util import connection as urllib3_connection

        # Build a real PinnedConnect wrapper and verify its connect
        # rejects requests for any host other than the pinned target.
        pin = adapter_base._PinnedConnect("catalog.example.com", 443, "8.8.8.8")
        with pin:
            patched = urllib3_connection.create_connection
            with self.assertRaises(SSRFError):
                patched(("metadata.google.internal", 80))


if __name__ == "__main__":
    unittest.main()
