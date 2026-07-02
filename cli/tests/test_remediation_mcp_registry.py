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

"""Regression tests for the MCP / registry / plugin security remediations.

One focused test per finding:

* F-0321 — remote MCP scan validates the URL through the central SSRF guard.
* F-0322 — local MCP scan refuses non-allowlisted stdio launchers.
* F-0342 — the stdio launcher allowlist is positive (npx/uvx only).
* F-0343 — registry MCP scan does not forward operator env secrets.
* F-0344 — registry MCP URL guard delegates to the central SSRF guard
  (closing the CGNAT gap).
* F-0347 — legacy archive downloads are SSRF-guarded (direct + redirect).
* F-0323 — named MCP scan honours a block on the *resolved* URL.
* F-0324 — ``mcp scan --all`` skips blocked servers.
* F-0341 — Authorization is dropped for the rest of a redirect chain once
  it leaves the original origin.
* F-0345 — authenticated git clones disable redirect following.
* F-0346 — a connector change invalidates a prior registry approval.
* F-0807 — a sha256 change invalidates a prior registry approval.
* F-0301 — local plugin install rejects traversal names / out-of-tree dest.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from click.testing import CliRunner
from defenseclaw.commands.cmd_mcp import mcp
from defenseclaw.commands.cmd_plugin import plugin
from defenseclaw.commands.cmd_registry import (
    _registry_mcp_url_allowed,
    _run_mcp_scan,
)
from defenseclaw.config import MCPScannerConfig, MCPServerEntry, RegistrySource
from defenseclaw.enforce.policy import PolicyEngine
from defenseclaw.models import ScanResult
from defenseclaw.registries.adapters import _base
from defenseclaw.registries.adapters._base import http_get
from defenseclaw.registries.adapters.git import fetch_git
from defenseclaw.registries.cache import _entry_payload_changed, _verdict_from_entry
from defenseclaw.registries.manifest import ManifestEntry
from defenseclaw.registry import RegistryError, _stream_download
from defenseclaw.scanner.mcp import MCPScannerWrapper, is_safe_stdio_scan_command

from tests.helpers import cleanup_app, make_app_context

# ---------------------------------------------------------------------------
# Shared fixtures / stubs
# ---------------------------------------------------------------------------

@pytest.fixture
def app_ctx():
    app, tmp_dir, db_path = make_app_context()
    try:
        yield app
    finally:
        cleanup_app(app, db_path, tmp_dir)


def _resolver_map(mapping: dict[str, list[str]]):
    """Build a DNS stub returning the mapped IPs (or [] => guard rejects)."""
    def _resolve(host: str) -> list[str]:
        return mapping.get(host, [])
    return _resolve


def _clean_result(target: str) -> ScanResult:
    return ScanResult(
        scanner="mcp-scanner",
        target=target,
        timestamp=datetime.now(timezone.utc),
        findings=[],
    )


class _FakeResp:
    """Minimal stand-in for a streaming requests.Response."""

    def __init__(self, *, is_redirect=False, location="", body=b"", status=200):
        self.is_redirect = is_redirect
        self.status_code = status
        self.headers: dict[str, str] = {}
        if location:
            self.headers["Location"] = location
        self._body = body

    def __enter__(self) -> _FakeResp:
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def close(self) -> None:
        pass

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(response=self)

    def iter_content(self, chunk_size: int = 65536):
        yield self._body


class _RecordingGet:
    """Callable that records (url, headers) and returns queued responses."""

    def __init__(self, responses: list[_FakeResp]):
        self._responses = list(responses)
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, url, *, headers=None, timeout=None, stream=None,
                 allow_redirects=None):
        self.calls.append((url, dict(headers or {})))
        return self._responses.pop(0)


# ---------------------------------------------------------------------------
# F-0321 — remote MCP scan URL validation
# ---------------------------------------------------------------------------

def test_f0321_remote_scan_blocks_private_and_loopback_targets():
    wrapper = MCPScannerWrapper(MCPScannerConfig())

    # Private (RFC1918) target rejected by default — fail closed before
    # the SDK ever dials the host.
    with pytest.raises(ValueError, match="refusing to scan remote MCP target"):
        wrapper.scan("http://10.20.30.40:9/mcp")

    # --allow-private also opts in to loopback scans. Patch the SDK leg so the
    # test proves the guard lets the URL through without touching the network.
    with patch.object(MCPScannerWrapper, "_scan_remote", return_value=[]):
        result = wrapper.scan("http://127.0.0.1:9/admin", allow_private=True)
    assert result.is_clean()

    # --allow-private lets an explicit private target through the guard;
    # patch the SDK leg so the test never touches the network.
    with patch.object(MCPScannerWrapper, "_scan_remote", return_value=[]):
        result = wrapper.scan("http://10.20.30.40:9/mcp", allow_private=True)
    assert result.is_clean()


# ---------------------------------------------------------------------------
# F-0322 — local MCP scan stdio command validation
# ---------------------------------------------------------------------------

def test_f0322_local_scan_rejects_non_allowlisted_command():
    wrapper = MCPScannerWrapper(MCPScannerConfig())
    evil = MCPServerEntry(
        name="evil", command="bash", args=["-c", "touch /tmp/pwned"],
        url="", transport="stdio",
    )
    with pytest.raises(ValueError, match="not an allowlisted stdio launcher"):
        wrapper.scan("evil", server_entry=evil)


# ---------------------------------------------------------------------------
# F-0342 — stdio launcher allowlist is positive (package runners plus the
# narrowly validated Codex Desktop native runtime)
# ---------------------------------------------------------------------------

def test_f0342_stdio_command_allowlist():
    # Allowed launchers keep working.
    assert is_safe_stdio_scan_command("npx", ["pkg"]) is True
    assert is_safe_stdio_scan_command("uvx", ["some-mcp", "--flag"]) is True

    # Arbitrary binaries / interpreters / paths are rejected.
    assert is_safe_stdio_scan_command("bash", ["-c", "x"]) is False
    assert is_safe_stdio_scan_command("python3", ["-c", "x"]) is False
    assert is_safe_stdio_scan_command("/usr/local/bin/npx", ["pkg"]) is False
    assert is_safe_stdio_scan_command("./npx", ["pkg"]) is False
    assert is_safe_stdio_scan_command("../evil", []) is False
    assert is_safe_stdio_scan_command("", []) is False
    assert is_safe_stdio_scan_command("npx", []) is False
    assert is_safe_stdio_scan_command("uvx", []) is False
    assert is_safe_stdio_scan_command("uvx", ["--quiet"]) is False
    # Code-exec flags smuggled into an otherwise-allowed launcher.
    assert is_safe_stdio_scan_command("npx", ["-c", "rce"]) is False


@pytest.mark.skipif(os.name != "nt", reason="Codex native runtime is Windows-only")
def test_codex_bundled_node_repl_is_admitted_only_from_trusted_layout(
    monkeypatch, tmp_path,
):
    from defenseclaw.scanner import mcp as mcp_scanner

    local_app_data = tmp_path / "Local"
    runtime_root = local_app_data / "OpenAI" / "Codex" / "runtimes"
    binary = runtime_root / "cua_node" / "runtime-id" / "bin" / "node_repl.exe"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"test executable fixture")

    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    monkeypatch.setenv("DEFENSECLAW_TRUSTED_BIN_PREFIXES", str(runtime_root))

    assert mcp_scanner.is_safe_stdio_scan_command(str(binary), []) is True

    wrong_layout = runtime_root / "other" / "runtime-id" / "bin" / "node_repl.exe"
    wrong_layout.parent.mkdir(parents=True)
    wrong_layout.write_bytes(b"test executable fixture")
    assert mcp_scanner.is_safe_stdio_scan_command(str(wrong_layout), []) is False

    outside = tmp_path / "outside" / "node_repl.exe"
    outside.parent.mkdir()
    outside.write_bytes(b"test executable fixture")
    assert mcp_scanner.is_safe_stdio_scan_command(str(outside), []) is False

    sibling_prefix = (
        tmp_path
        / "Local"
        / "OpenAI"
        / "Codex"
        / "runtimes-evil"
        / "cua_node"
        / "runtime-id"
        / "bin"
        / "node_repl.exe"
    )
    sibling_prefix.parent.mkdir(parents=True)
    sibling_prefix.write_bytes(b"test executable fixture")
    assert mcp_scanner.is_safe_stdio_scan_command(str(sibling_prefix), []) is False


# ---------------------------------------------------------------------------
# F-0343 — registry MCP scan must not forward operator env secrets
# ---------------------------------------------------------------------------

def test_f0343_registry_scan_does_not_forward_env_secrets(app_ctx, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "super-secret-value")
    captured: dict = {}

    def _fake_scan(self, target, server_entry=None, *, allow_private=False):
        captured["server_entry"] = server_entry
        return _clean_result(target)

    entry = ManifestEntry(
        name="evil-mcp", type="mcp", transport="stdio",
        command="npx", args=["evil-mcp"], env_required=["GITHUB_TOKEN"],
    )
    src = RegistrySource(id="s", kind="git", url="https://x.example", content="mcp")

    # F-0541: stdio scanning is opt-in — pass scan_stdio=True so this
    # test still exercises the env-forwarding path.
    with patch.object(MCPScannerWrapper, "scan", _fake_scan):
        _run_mcp_scan(app_ctx, app_ctx.cfg, src, entry, scan_stdio=True)

    server_entry = captured["server_entry"]
    assert server_entry is not None
    # The declared env var is present (so the server still sees the key
    # name) but carries an empty placeholder — never the live secret.
    assert server_entry.env == {"GITHUB_TOKEN": ""}
    assert "super-secret-value" not in server_entry.env.values()


# ---------------------------------------------------------------------------
# F-1261 — npx/uvx stay allowed launchers; the real controls are
# (a) env-scrubbing of execution-control vars (F-0221) and (b) opt-in
# stdio scanning during `registry sync` (F-0541).
# ---------------------------------------------------------------------------

def test_f1261_npx_uvx_remain_allowed_launchers():
    # KEEP: npx/uvx are deliberately retained as valid stdio launchers.
    assert is_safe_stdio_scan_command("npx", ["some-mcp"]) is True
    assert is_safe_stdio_scan_command("uvx", ["some-mcp", "--flag"]) is True


def test_f1261_exec_control_env_stripped_from_scan_subprocess():
    """F-0221: untrusted MCP entry env cannot redirect the launcher.

    Even with npx/uvx allowed, a publisher/connector-config that sets
    PATH / NODE_PATH / LD_PRELOAD on the entry must not have those reach
    the spawned subprocess env — the safe baseline wins.
    """
    from defenseclaw.scanner.mcp import _safe_subprocess_env

    with patch.dict(os.environ, {"PATH": "/usr/bin:/bin"}, clear=True):
        env = _safe_subprocess_env({
            "PATH": "/tmp/evil",
            "NODE_PATH": "/tmp/evil",
            "LD_PRELOAD": "/tmp/evil/hook.so",
            "SERVER_FLAG": "keep-me",
        })
    assert env["PATH"] == "/usr/bin:/bin"
    assert "NODE_PATH" not in env
    assert "LD_PRELOAD" not in env
    # Non-exec server config still passes through.
    assert env["SERVER_FLAG"] == "keep-me"


def test_f1261_registry_sync_does_not_spawn_stdio_by_default(app_ctx):
    """F-0541: routine `registry sync` must NOT spawn a stdio package
    unless `--scan-stdio` is passed."""
    entry = ManifestEntry(
        name="some-mcp", type="mcp", transport="stdio",
        command="npx", args=["some-mcp"],
    )
    src = RegistrySource(id="s", kind="git", url="https://x.example", content="mcp")

    # Default: stdio scan is skipped, scanner.scan never called.
    with patch.object(MCPScannerWrapper, "scan") as mock_scan:
        result = _run_mcp_scan(app_ctx, app_ctx.cfg, src, entry)
    assert result is None
    assert mock_scan.call_count == 0

    # Opt-in: --scan-stdio runs the scan (scanner.scan is called once).
    called: dict = {}

    def _fake_scan(self, target, server_entry=None, *, allow_private=False):
        called["target"] = target
        return _clean_result(target)

    with patch.object(MCPScannerWrapper, "scan", _fake_scan):
        result = _run_mcp_scan(
            app_ctx, app_ctx.cfg, src, entry, scan_stdio=True,
        )
    assert result is not None
    assert called["target"] == "some-mcp"


# ---------------------------------------------------------------------------
# F-0344 — registry MCP URL guard delegates to the central SSRF guard
# ---------------------------------------------------------------------------

def test_f0344_registry_url_guard_blocks_cgnat():
    # RFC 6598 CGNAT (100.64.0.0/10) — missed by the old ad-hoc check,
    # blocked by the central guard.
    assert _registry_mcp_url_allowed("http://100.64.0.1:8080/mcp") is False
    # Loopback / link-local still blocked.
    assert _registry_mcp_url_allowed("http://127.0.0.1/mcp") is False
    assert _registry_mcp_url_allowed("http://169.254.1.1/mcp") is False
    # Operator opt-in unblocks the CGNAT overlay case.
    assert _registry_mcp_url_allowed(
        "http://100.64.0.1:8080/mcp", allow_private=True
    ) is True
    # A public address is allowed.
    assert _registry_mcp_url_allowed("http://93.184.216.34/mcp") is True


def test_f0344_remote_scan_pins_sdk_dns_against_rebind():
    # F-0344 DNS-rebind hardening: the remote scan must resolve-and-pin the
    # target, then pin the SDK's getaddrinfo to that vetted IP. A low-TTL
    # rebind that flips to loopback at connect time must NOT be honoured;
    # the SDK leg sees the originally-vetted public IP instead.
    import socket

    public_ip = "93.184.216.34"
    resolved_phases: list[str] = []

    real_getaddrinfo = socket.getaddrinfo

    def rebinding_getaddrinfo(host, *args, **kwargs):
        if host == "rebind.example":
            # First answer (the guard's resolve_and_pin) is public; a
            # second, rebound answer would be loopback. The pin must
            # prevent that second lookup from reaching DNS at all.
            phase = "guard" if not resolved_phases else "rebind"
            resolved_phases.append(phase)
            ip = public_ip if phase == "guard" else "127.0.0.1"
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))]
        return real_getaddrinfo(host, *args, **kwargs)

    seen_ip: dict[str, str] = {}

    def fake_scan_remote(self, scanner, target, analyzers):
        # Stand in for the async-httpx SDK leg: resolve the hostname the
        # way the SDK would at connect time.
        seen_ip["ip"] = socket.getaddrinfo("rebind.example", 443)[0][4][0]
        return []

    wrapper = MCPScannerWrapper(MCPScannerConfig())
    with patch.object(socket, "getaddrinfo", rebinding_getaddrinfo):
        with patch.object(MCPScannerWrapper, "_scan_remote", fake_scan_remote):
            # Avoid importing the heavy real SDK during the test.
            import sys as _sys
            import types as _types

            stub = _types.ModuleType("mcpscanner")
            stub.Config = lambda **k: object()
            stub.Scanner = lambda *a, **k: object()
            core = _types.ModuleType("mcpscanner.core")
            models = _types.ModuleType("mcpscanner.core.models")

            import enum as _enum

            class _AnalyzerEnum(_enum.Enum):
                YARA = "yara"
                API = "api"
                LLM = "llm"

            models.AnalyzerEnum = _AnalyzerEnum
            with patch.dict(_sys.modules, {
                "mcpscanner": stub,
                "mcpscanner.core": core,
                "mcpscanner.core.models": models,
            }):
                result = wrapper.scan("https://rebind.example/mcp")

    assert result.is_clean()
    # The SDK leg resolved to the vetted public IP, never the rebound
    # loopback address — proving the connect-time lookup was pinned.
    assert seen_ip["ip"] == public_ip


# ---------------------------------------------------------------------------
# F-0347 — legacy archive downloads are SSRF-guarded
# ---------------------------------------------------------------------------

def test_f0347_stream_download_blocks_loopback_and_redirect(tmp_path):
    dest = str(tmp_path / "download")

    # Direct loopback target refused before any network call.
    class _NoNet:
        def get(self, *a, **k):  # pragma: no cover - must not be reached
            raise AssertionError("network call should not happen for loopback")

    with patch("defenseclaw.registry.requests", _NoNet()):
        with pytest.raises(RegistryError, match="unsafe URL"):
            _stream_download("http://127.0.0.1/plugin.tgz", dest)

    # A public URL that 30x-redirects to an internal host is refused on
    # the redirect hop (each hop is re-validated, redirects disabled).
    resolver = _resolver_map({
        "public.example": ["93.184.216.34"],
        "evil.internal": ["127.0.0.1"],
    })
    redirect = _FakeResp(is_redirect=True, location="http://evil.internal/evil.tgz")

    class _FakeRequests:
        def __init__(self, responses):
            self.get = _RecordingGet(responses)

    fake = _FakeRequests([redirect])
    with patch("defenseclaw.registry.requests", fake):
        with pytest.raises(RegistryError, match="redirect blocked by SSRF guard"):
            _stream_download(
                "http://public.example/r", dest, resolver=resolver,
            )
    # The first hop used allow_redirects=False (manual follow); verify it
    # was a single recorded GET before the guard fired.
    assert len(fake.get.calls) == 1
    assert fake.get.calls[0][0] == "http://public.example/r"


# ---------------------------------------------------------------------------
# F-0323 — named MCP scan honours a block on the resolved URL
# ---------------------------------------------------------------------------

def test_f0323_named_scan_blocked_by_resolved_url(app_ctx):
    pe = PolicyEngine(app_ctx.store)
    pe.block("mcp", "http://internal.example/mcp", "blocked by url")
    app_ctx.cfg.mcp_servers = lambda connector=None: [
        MCPServerEntry(
            name="alias", url="http://internal.example/mcp", transport="sse",
        )
    ]

    result = CliRunner().invoke(
        mcp, ["scan", "alias"], obj=app_ctx, catch_exceptions=False,
    )
    assert result.exit_code == 2, result.output
    assert "BLOCKED" in result.output


# ---------------------------------------------------------------------------
# F-0324 — `mcp scan --all` skips blocked servers
# ---------------------------------------------------------------------------

def test_f0324_scan_all_skips_blocked_server(app_ctx):
    pe = PolicyEngine(app_ctx.store)
    pe.block("mcp", "blocked-srv", "operator block")
    app_ctx.cfg.mcp_servers = lambda connector=None: [
        MCPServerEntry(name="blocked-srv", url="http://x.example/mcp", transport="sse"),
    ]

    with patch("defenseclaw.commands.cmd_mcp._run_scan") as mock_run:
        result = CliRunner().invoke(
            mcp, ["scan", "--all"], obj=app_ctx, catch_exceptions=False,
        )
    assert result.exit_code == 0, result.output
    assert mock_run.call_count == 0
    assert "BLOCKED" in result.output


# ---------------------------------------------------------------------------
# F-0341 — Authorization is dropped for the rest of the chain after a
# cross-origin redirect
# ---------------------------------------------------------------------------

def test_f0341_auth_not_reattached_after_leaving_origin(monkeypatch):
    monkeypatch.setenv("DC_TEST_TOKEN", "bearer-secret")
    resolver = _resolver_map({
        "registry.example": ["93.184.216.34"],
        "attacker.example": ["93.184.216.34"],
    })

    # registry.example (auth) -> attacker.example/one -> attacker.example/two
    responses = [
        _FakeResp(is_redirect=True, location="https://attacker.example/one"),
        _FakeResp(is_redirect=True, location="https://attacker.example/two"),
        _FakeResp(body=b"payload"),
    ]
    recorder = _RecordingGet(responses)
    monkeypatch.setattr(_base.requests, "get", recorder)

    body = http_get(
        "https://registry.example/manifest",
        auth_env="DC_TEST_TOKEN",
        resolver=resolver,
    )
    assert body == b"payload"

    # 3 hops recorded.
    assert len(recorder.calls) == 3
    # Original request carried the bearer token.
    assert recorder.calls[0][1].get("Authorization") == "Bearer bearer-secret"
    # Both attacker hops MUST NOT carry it — including the second hop,
    # which shares an origin with the first attacker hop (the old bug).
    assert "Authorization" not in recorder.calls[1][1]
    assert "Authorization" not in recorder.calls[2][1]


# ---------------------------------------------------------------------------
# F-0345 — authenticated git clones disable redirect following
# ---------------------------------------------------------------------------

def test_f0345_authed_git_clone_disables_redirects(monkeypatch):
    monkeypatch.setenv("DC_GIT_TOKEN", "git-bearer")
    resolver = _resolver_map({"catalog.example.com": ["93.184.216.34"]})
    manifest_body = (
        b"schema_version: 1\n"
        b"entries:\n"
        b"  - {name: s, type: skill, source_url: 'https://x/y'}\n"
    )
    captured: dict = {}

    def _fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        # cmd[-1] is the clone target tempdir.
        from pathlib import Path
        (Path(cmd[-1]) / "defenseclaw-registry.yaml").write_bytes(manifest_body)

        class _R:
            returncode = 0
            stderr = ""
        return _R()

    src = RegistrySource(
        id="g", kind="git", url="https://catalog.example.com/registry.git",
        content="skill", auth_env="DC_GIT_TOKEN",
    )
    with patch("subprocess.run", side_effect=_fake_run):
        fetch_git(src, resolver=resolver)

    cmd = captured["cmd"]
    assert "-c" in cmd
    # The redirect-disable config is present and precedes the clone
    # subcommand (it may not be the FIRST -c now that the rebind pin is
    # also injected as a -c config).
    assert "http.followRedirects=false" in cmd
    assert cmd.index("http.followRedirects=false") < cmd.index("clone")
    # F-0345 rebind pin: git's connect is bound to the vetted IP via
    # curloptResolve (curl --resolve), preserving Host/SNI.
    assert "http.curloptResolve=catalog.example.com:443:93.184.216.34" in cmd
    assert cmd.index("http.curloptResolve=catalog.example.com:443:93.184.216.34") < cmd.index("clone")


def test_f0345_unauthed_git_clone_keeps_default_redirects(monkeypatch):
    resolver = _resolver_map({"catalog.example.com": ["93.184.216.34"]})
    manifest_body = b'{"schema_version":1,"entries":[]}'
    captured: dict = {}

    def _fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        from pathlib import Path
        (Path(cmd[-1]) / "defenseclaw-registry.json").write_bytes(manifest_body)

        class _R:
            returncode = 0
            stderr = ""
        return _R()

    src = RegistrySource(
        id="g", kind="git", url="https://catalog.example.com/registry.git",
        content="skill",
    )
    with patch("subprocess.run", side_effect=_fake_run):
        fetch_git(src, resolver=resolver)

    # No auth header => no redirect override (preserves normal git UX).
    assert "http.followRedirects=false" not in captured["cmd"]
    # The rebind pin is applied regardless of auth (defends the clone
    # connect itself, not just the token).
    assert "http.curloptResolve=catalog.example.com:443:93.184.216.34" in captured["cmd"]


# ---------------------------------------------------------------------------
# F-0346 / F-0807 — connector & sha256 are part of the payload identity
# ---------------------------------------------------------------------------

def test_f0346_connector_change_invalidates_prior_approval():
    entry = ManifestEntry(
        name="srv", type="mcp", transport="stdio", command="npx",
        args=["x"], connector="codex", sha256="a" * 64,
    )
    prior = _verdict_from_entry(entry)
    prior.approved = True

    # Same shape — approval carries over.
    assert _entry_payload_changed(prior, entry) is False

    # Broadening the connector scope (codex -> "") must invalidate it.
    rescoped = ManifestEntry(
        name="srv", type="mcp", transport="stdio", command="npx",
        args=["x"], connector="", sha256="a" * 64,
    )
    assert _entry_payload_changed(prior, rescoped) is True


def test_f0807_sha256_change_invalidates_prior_approval():
    entry = ManifestEntry(
        name="skill", type="skill", source_url="https://x/y.tgz",
        sha256="a" * 64, connector="codex",
    )
    prior = _verdict_from_entry(entry)
    prior.approved = True

    assert _entry_payload_changed(prior, entry) is False

    swapped = ManifestEntry(
        name="skill", type="skill", source_url="https://x/y.tgz",
        sha256="b" * 64, connector="codex",
    )
    assert _entry_payload_changed(prior, swapped) is True


# ---------------------------------------------------------------------------
# F-0301 — local plugin install rejects traversal names / out-of-tree dest
# ---------------------------------------------------------------------------

def test_f0301_local_install_rejects_parent_traversal(app_ctx, tmp_path):
    victim_root = tmp_path / "victim-root"
    plugin_dir = victim_root / "plugins"
    plugin_dir.mkdir(parents=True)
    app_ctx.cfg.plugin_dir = str(plugin_dir)

    marker = victim_root / "outside-plugin-dir.txt"
    marker.write_text("must survive\n")

    # A local source path ending in ``/..`` yields basename ``..`` →
    # dest would be the PARENT of plugin_dir.
    child = tmp_path / "source-root" / "child"
    child.mkdir(parents=True)
    source_arg = str(child / "..")

    clean = _clean_result(source_arg)
    with patch(
        "defenseclaw.scanner.plugin.PluginScannerWrapper.scan",
        return_value=clean,
    ):
        result = CliRunner().invoke(
            plugin, ["install", "--force", source_arg],
            obj=app_ctx, catch_exceptions=False,
        )

    assert result.exit_code != 0, result.output
    assert "invalid plugin name" in result.output.lower()
    # The out-of-tree file and the managed dir must both be intact.
    assert marker.exists()
    assert plugin_dir.exists()
