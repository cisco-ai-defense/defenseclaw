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

"""MCP scanner — native SDK integration.

Uses the cisco-ai-mcp-scanner Python SDK directly instead of shelling out
to the mcp-scanner CLI.  Maps SDK ToolScanResult/SecurityFinding →
DefenseClaw models.

Supports both remote (URL) and local (stdio) MCP servers:
  - Remote: uses ``scan_remote_server_tools`` with the URL directly.
  - Local:  creates a temporary MCP config file and uses
    ``scan_mcp_config_file`` which spawns the server process.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from defenseclaw.config import (
    CiscoAIDefenseConfig,
    InspectLLMConfig,
    LLMConfig,
    MCPScannerConfig,
    MCPServerEntry,
)
from defenseclaw.models import Finding, ScanResult
from defenseclaw.registries.ssrf import (
    SSRFError,
    pinned_getaddrinfo,
    resolve_and_pin,
)
from defenseclaw.scanner._llm_env import inject_llm_env, litellm_model

if TYPE_CHECKING:
    pass


# env vars whose names contain any of these
# substrings are treated as potentially sensitive and never inherited
# into the spawned MCP subprocess during a local scan. This is a
# deliberately broad allowlist because LLM SDKs ship dozens of
# provider-specific names (OPENAI_API_KEY, ANTHROPIC_API_KEY,
# GOOGLE_API_KEY, GEMINI_API_KEY, AZURE_OPENAI_KEY, BEDROCK_*, AWS_*,
# COHERE_API_KEY, GROQ_API_KEY, MISTRAL_API_KEY, PERPLEXITY_API_KEY,
# DEEPSEEK_API_KEY, OPENROUTER_API_KEY, XAI_API_KEY, TOGETHER_API_KEY,
# REPLICATE_API_TOKEN, HF_TOKEN/HUGGINGFACE_TOKEN, ...). Operators that
# need to preserve a specific env var for the scanned MCP server should
# put it on the `env:` block of the MCP entry; that block IS preserved.
_SENSITIVE_ENV_SUBSTRINGS = (
    "API_KEY", "APIKEY", "API_TOKEN", "TOKEN", "SECRET", "PASSWORD",
    "PASSWD", "AUTH", "CREDENTIAL", "PRIVATE_KEY", "ACCESS_KEY",
    "BEARER", "SESSION", "COOKIE", "WEBHOOK", "HEC_TOKEN",
    "OPENAI", "ANTHROPIC", "GOOGLE", "GEMINI", "AZURE_OPENAI",
    "BEDROCK", "AWS_", "COHERE", "GROQ", "MISTRAL", "PERPLEXITY",
    "DEEPSEEK", "OPENROUTER", "XAI_", "TOGETHER", "REPLICATE",
    "HF_TOKEN", "HUGGINGFACE", "DATABRICKS", "SAGEMAKER",
    "CISCO", "DEFENSECLAW", "SPLUNK",
    "GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN",
)

# Baseline env vars that are SAFE to inherit into the subprocess —
# things the spawned MCP server typically needs to find binaries,
# config dirs, and locale.
_SAFE_INHERIT_ENV = (
    "PATH", "HOME", "USER", "SHELL", "TERM", "LOGNAME",
    "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TZ",
    "PWD", "PYTHONPATH", "NODE_PATH", "DISPLAY",
)

# F-0221: env vars that control how/what an executable RESOLVES, LOADS,
# or RUNS. The scan subprocess env is layered with operator/publisher-
# supplied ``MCPServerEntry.env`` (sourced from connector config /
# publisher manifest — both untrusted), so a config that sets
# ``PATH=/tmp/evil``, ``NODE_PATH``/``PYTHONPATH=/tmp/inject`` or
# ``LD_PRELOAD``/``LD_LIBRARY_PATH``/``DYLD_*`` could redirect what the
# allowlisted ``npx``/``uvx`` launcher resolves or pre-loads, defeating
# the launcher allowlist entirely. We REFUSE to let untrusted entries
# set any of these — the safe baseline value (e.g. a minimal PATH) wins.
# Non-exec env vars the server legitimately needs still pass through.
#
# ``DYLD_*`` (macOS) and ``LD_*`` (glibc) are matched by prefix below
# because the dynamic loader honours a whole family of names
# (DYLD_INSERT_LIBRARIES, DYLD_LIBRARY_PATH, LD_PRELOAD, LD_AUDIT,
# LD_LIBRARY_PATH, …).
_EXEC_CONTROL_ENV_NAMES = frozenset({
    "PATH",
    "NODE_PATH",
    "NODE_OPTIONS",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
})
_EXEC_CONTROL_ENV_PREFIXES = ("LD_", "DYLD_")


def _is_exec_control_env_name(name: str) -> bool:
    """Return True for env vars that steer executable resolution/loading.

    F-0221: such names are never accepted from untrusted
    operator/publisher ``MCPServerEntry.env`` — only the safe baseline
    may set them.
    """
    if not isinstance(name, str):
        return False
    upper = name.upper()
    if upper in _EXEC_CONTROL_ENV_NAMES:
        return True
    for prefix in _EXEC_CONTROL_ENV_PREFIXES:
        if upper.startswith(prefix):
            return True
    return False


def _is_sensitive_env_name(name: str) -> bool:
    upper = name.upper()
    for token in _SENSITIVE_ENV_SUBSTRINGS:
        if token in upper:
            return True
    return False


def _safe_subprocess_env(operator_env: dict | None) -> dict:
    """Build a scrubbed environment for a spawned MCP subprocess.

    a full ``os.environ`` inheritance leaks
    every operator-set secret to the scanned server. We start from an
    allowlisted baseline (``PATH``, ``HOME``, ``LANG``, …), strip any
    name that looks sensitive, then layer on top whatever the operator
    explicitly placed on ``MCPServerEntry.env``.

    F-0221: ``MCPServerEntry.env`` is sourced from connector config /
    publisher manifest — both UNTRUSTED. We therefore do NOT let those
    entries win for execution-control variables (``PATH``, ``NODE_PATH``,
    ``PYTHONPATH``, ``LD_PRELOAD``/``LD_LIBRARY_PATH``, ``DYLD_*``, …):
    allowing them would let an untrusted config redirect what the
    allowlisted ``npx``/``uvx`` launcher resolves or pre-loads and so
    bypass the launcher allowlist. The safe baseline ``PATH`` (and the
    rest of the loader environment) wins; such names are dropped from the
    untrusted overlay with a clear warning. Non-exec env vars the server
    legitimately needs still pass through.
    """
    out: dict[str, str] = {}
    for name in _SAFE_INHERIT_ENV:
        v = os.environ.get(name)
        if v is None:
            continue
        if _is_sensitive_env_name(name):
            continue
        out[name] = v
    if operator_env:
        for k, v in operator_env.items():
            if not isinstance(k, str):
                continue
            # F-0221: refuse to let an untrusted entry set exec-control
            # vars; the safe baseline value (if any) is preserved.
            if _is_exec_control_env_name(k):
                print(
                    f"warning: ignoring execution-control env var {k!r} from "
                    f"untrusted MCP entry (using safe baseline instead)",
                    file=sys.stderr,
                )
                continue
            out[k] = "" if v is None else str(v)
    return out


# Launchers that resolve and run a *named package* rather than an
# arbitrary operator/publisher-supplied script or binary. A malicious
# manifest can at worst point one of these at a package (which the
# scanner then inspects); it cannot turn the scan into "run this
# absolute path / shell interpreter". Bare interpreters (bash, sh,
# python, node -e, …), absolute paths, and relative paths are rejected
# so the local-scan spawn cannot be coerced into arbitrary code
# execution as the operator before any admission decision.
_SAFE_STDIO_LAUNCHERS = frozenset({"npx", "uvx"})

# argv tokens that turn an otherwise-allowlisted launcher into an
# arbitrary-code-execution primitive (e.g. ``npx -c "<shell>"``).
_FORBIDDEN_STDIO_FLAGS = frozenset({
    "-c", "--command", "--eval", "-e", "--exec", "--script", "-x",
})


def is_safe_stdio_scan_command(command: str, args: list | None) -> bool:
    """Return True only when *command* is an allowlisted package runner.

    This is the single source of truth for "is it safe to spawn this
    stdio MCP server during a scan" and is shared by both the registry
    sync path (:mod:`defenseclaw.commands.cmd_registry`) and the local
    ``mcp scan`` path so the two can never drift.

    The check is a positive allowlist, not a denylist:

    * the command must be a bare launcher name (no path separators) so
      absolute / relative executable paths are rejected outright;
    * that name must be in :data:`_SAFE_STDIO_LAUNCHERS`;
    * no argv token may be a code-exec flag (``-c`` / ``-e`` / …).
    """
    if not isinstance(command, str):
        return False
    cmd = command.strip()
    if not cmd:
        return False
    # No path components — only bare launcher names. This blocks
    # absolute paths (``/tmp/evil``), relative paths (``./evil``,
    # ``../evil``), and Windows-style paths regardless of host OS.
    if "/" in cmd or "\\" in cmd:
        return False
    if os.sep in cmd or (os.altsep and os.altsep in cmd):
        return False
    if cmd.lower() not in _SAFE_STDIO_LAUNCHERS:
        return False
    for a in args or []:
        if not isinstance(a, str):
            return False
        if a.strip() in _FORBIDDEN_STDIO_FLAGS:
            return False
    return True


def _inspect_to_llm(il: InspectLLMConfig) -> LLMConfig:
    """Translate a legacy ``InspectLLMConfig`` into the unified
    :class:`LLMConfig` shape so we can drive the shared helpers. Used
    only on the back-compat path — real call sites should pass an
    already-resolved ``LLMConfig`` via ``llm=``.
    """
    return LLMConfig(
        model=il.model,
        provider=il.provider,
        api_key=il.api_key,
        api_key_env=il.api_key_env,
        base_url=il.base_url,
        timeout=il.timeout,
        max_retries=il.max_retries,
    )


class MCPScannerWrapper:
    """Wraps the cisco-ai-mcp-scanner SDK.

    The wrapper accepts EITHER a legacy :class:`InspectLLMConfig` (the
    v<5 shape, still used by older tests) OR a unified
    :class:`LLMConfig` via ``llm=``. When both are supplied the
    ``llm=`` argument wins. Internally everything is driven through
    :class:`LLMConfig` and the shared
    :mod:`defenseclaw.scanner._llm_env` helpers so the mcp-scanner
    sees the same env var injection as every other scanner.
    """

    def __init__(
        self,
        config: MCPScannerConfig,
        inspect_llm: InspectLLMConfig | None = None,
        cisco_ai_defense: CiscoAIDefenseConfig | None = None,
        *,
        llm: LLMConfig | None = None,
    ) -> None:
        self.config = config
        self.inspect_llm = inspect_llm or InspectLLMConfig()
        self.cisco_ai_defense = cisco_ai_defense or CiscoAIDefenseConfig()
        # ``_llm`` is the canonical internal view. Prefer the explicit
        # ``llm=`` arg; fall back to inspect_llm's translated shape.
        self._llm: LLMConfig = llm if llm is not None else _inspect_to_llm(self.inspect_llm)

    def name(self) -> str:
        return "mcp-scanner"

    def _inject_env(self) -> None:
        """Inject LLM API key into provider-specific env var(s).

        Delegates to the shared helper so every LiteLLM-backed scanner
        picks the same env vars. Non-overwriting by default — if the
        operator has already set ``OPENAI_API_KEY``/etc., we respect
        it. Local providers (ollama/vllm) are auto-skipped.
        """
        inject_llm_env(self._llm)

    def scan(
        self,
        target: str,
        server_entry: MCPServerEntry | None = None,
        *,
        allow_private: bool = False,
    ) -> ScanResult:
        import time
        import warnings

        warnings.filterwarnings("ignore", message="Pydantic serializer warnings")

        try:
            from mcpscanner import Config as MCPConfig
            from mcpscanner import Scanner as MCPSDKScanner
            from mcpscanner.core.models import AnalyzerEnum
        except ImportError:
            print(
                "error: cisco-ai-mcp-scanner not installed.\n"
                "  Install with: pip install cisco-ai-mcp-scanner\n"
                "\n"
                "  Or install DefenseClaw with the mcp-scan extra:\n"
                "  pip install defenseclaw[mcp-scan]",
                file=sys.stderr,
            )
            raise SystemExit(1)

        llm = self._llm
        aid = self.cisco_ai_defense

        # when scanning a LOCAL stdio MCP
        # server we MUST NOT inject the operator's LLM API key into
        # os.environ — the mcp-scanner SDK spawns the MCP subprocess
        # with the parent process's full environment, so any env var
        # we set here (OPENAI_API_KEY, ANTHROPIC_API_KEY,
        # GOOGLE_API_KEY, …) leaks to the very server we're about to
        # scan. The SDK accepts the key via MCPConfig.llm_provider_api_key
        # below, so the LLM analyzer keeps working without env
        # injection. Remote scans don't spawn a child process and
        # need the env injection to keep parity with other scanners.
        is_local = (
            server_entry is not None
            and server_entry.command
            and not server_entry.url
        )

        # Fail closed BEFORE any subprocess spawn / network call. A
        # local stdio scan must only launch an allowlisted package
        # runner (never an arbitrary binary / shell), and a remote scan
        # must pass the central SSRF guard (http/https only; private,
        # loopback, link-local and CGNAT blocked unless the operator
        # explicitly opts in with allow_private).
        if is_local:
            if not is_safe_stdio_scan_command(server_entry.command, server_entry.args):
                raise ValueError(
                    f"refusing to scan local MCP server {server_entry.name!r}: "
                    f"command {server_entry.command!r} is not an allowlisted "
                    f"stdio launcher (allowed: "
                    f"{', '.join(sorted(_SAFE_STDIO_LAUNCHERS))})"
                )
        pinned_target: tuple[str, str, int] | None = None
        if not is_local:
            try:
                # F-0344: resolve-and-pin (not just validate). The MCP
                # scanner SDK connects with async httpx, which re-resolves
                # the hostname at dial time — a DNS rebind between this
                # check and that connect would defeat a validate-only
                # guard. We capture the vetted IP here and pin the SDK's
                # resolver to it for the duration of the remote scan.
                ip, host, port = resolve_and_pin(target, allow_private=allow_private)
                pinned_target = (host, port, ip)
            except SSRFError as exc:
                raise ValueError(
                    f"refusing to scan remote MCP target {target!r}: {exc}"
                ) from exc

        if not is_local:
            self._inject_env()

        # ``llm_model`` must be LiteLLM-shaped (``provider/model``) —
        # the mcp-scanner SDK passes it straight through to LiteLLM.
        # ``litellm_model()`` stitches bare ``llm.model`` + ``llm.provider``
        # when needed, otherwise uses the already-prefixed string.
        #
        # ``llm_base_url`` is forwarded verbatim. The mcp-scanner SDK
        # only adds ``api_base`` to the LiteLLM request when this value
        # is truthy (mcpscanner/core/analyzers/llm_analyzer.py),
        # otherwise LiteLLM's own provider-default discovery handles
        # routing — which works for Bedrock, Gemini, Vertex, Azure,
        # Groq, Mistral, DeepSeek, OpenRouter, etc. So an empty string
        # is the correct default; operators who need a custom endpoint
        # set ``llm.base_url`` (or ``scanners.mcp_scanner.llm.base_url``)
        # explicitly.
        sdk_config = MCPConfig(
            api_key=aid.resolved_api_key(),
            endpoint_url=aid.endpoint,
            llm_provider_api_key=llm.resolved_api_key(),
            llm_model=litellm_model(llm),
            llm_base_url=llm.base_url,
            llm_timeout=llm.effective_timeout(),
            llm_max_retries=llm.effective_max_retries(),
        )

        scanner = MCPSDKScanner(sdk_config)
        analyzers = self._parse_analyzers(AnalyzerEnum)

        start = time.monotonic()

        if is_local:
            all_findings = self._scan_local(scanner, server_entry, analyzers)
        elif pinned_target is not None:
            # Pin the SDK's DNS resolution to the IP we vetted above so a
            # rebind cannot redirect the connect to an internal address.
            host, port, ip = pinned_target
            with pinned_getaddrinfo(host, port, ip):
                all_findings = self._scan_remote(scanner, target, analyzers)
        else:
            all_findings = self._scan_remote(scanner, target, analyzers)

        elapsed = time.monotonic() - start
        return self._convert(all_findings, target, elapsed)

    def _parse_analyzers(self, analyzer_enum_cls: type) -> list | None:
        """Resolve configured analyzer names into SDK enum values.

        Selection is *model-driven* via the ``"auto"`` sentinel. ``auto``
        means "run YARA always, and add the LLM analyzer only when a
        model is actually configured for this scanner
        (``resolve_llm('scanners.mcp')`` yielded one)". This is what lets
        the unified LLM lane be default-on without firing LLM calls — and
        failing — on installs that never set a model. Once the config
        default flips from ``"yara"`` to ``"auto"`` (see
        ``MCPScannerConfig.analyzers`` / the Go parity default), every
        scan picks YARA+LLM when a model resolves and YARA-only otherwise.

        An explicit comma-separated list (``yara`` / ``yara,llm,api`` / …)
        is honoured verbatim as a local-only escape hatch — ``yara`` keeps
        a scan YARA-only even when a model is configured. An empty value
        preserves the legacy "let the SDK run every analyzer" meaning
        (``None``) so deliberately blanking the field is not silently
        narrowed.
        """
        cfg = self.config
        raw = (cfg.analyzers or "").strip()
        if not raw:
            return None

        analyzer_map = {e.value: e for e in analyzer_enum_cls}

        if raw.lower() == "auto":
            return self._auto_analyzers(analyzer_map)

        valid_names = sorted(analyzer_map.keys())
        analyzers = []
        for name in raw.split(","):
            name = name.strip().lower()
            if not name:
                continue
            if name in analyzer_map:
                analyzers.append(analyzer_map[name])
            else:
                print(
                    f"warning: unknown analyzer {name!r}, valid options: {', '.join(valid_names)}",
                    file=sys.stderr,
                )
        if not analyzers:
            print(
                f"warning: no valid analyzers after parsing "
                f"{cfg.analyzers!r}, falling back to all analyzers",
                file=sys.stderr,
            )
            return None
        return analyzers

    def _auto_analyzers(self, analyzer_map: dict) -> list | None:
        """Model-driven analyzer set for the ``"auto"`` default.

        YARA always runs — it needs no model and no network. The LLM
        analyzer is added only when the resolved LLM actually carries a
        model (surfaced as a non-empty ``litellm_model``); with no model
        we fall back to YARA-only so a default-on scan is a safe no-op
        (no LLM call, no error) instead of a hard failure.
        """
        selected: list = []
        yara = analyzer_map.get("yara")
        if yara is not None:
            selected.append(yara)
        if litellm_model(self._llm):
            llm = analyzer_map.get("llm")
            if llm is not None:
                selected.append(llm)
        # If the SDK enum exposes neither name, defer to its own default
        # (None = all) rather than handing it an empty list.
        return selected or None

    def _scan_local(self, scanner: object, entry: MCPServerEntry,
                    analyzers: list | None) -> list[object]:
        """Scan a local stdio MCP server via a temporary config file."""

        server_def: dict = {"command": entry.command}
        if entry.args:
            server_def["args"] = entry.args
        # ALWAYS hand the spawned MCP
        # subprocess an explicit, scrubbed env dict. When the MCP SDK
        # spawns a stdio server with env=None the child inherits the
        # parent's process environment — including OPENAI_API_KEY,
        # ANTHROPIC_API_KEY, GOOGLE_API_KEY, AWS_*, GITHUB_TOKEN,
        # SPLUNK_HEC_TOKEN and every other secret the operator has
        # exported in their shell. Even when the operator did not
        # supply env= for the MCP entry, we fall back to a minimal
        # baseline (PATH/HOME/etc.) plus the operator-specified env
        # only, never the parent's full environment.
        server_def["env"] = _safe_subprocess_env(entry.env)

        config_data = {"mcpServers": {entry.name: server_def}}

        fd, tmp_path = tempfile.mkstemp(suffix=".json", prefix="defenseclaw-mcp-")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(config_data, f)

            scan_kwargs: dict = {"config_path": tmp_path}
            if analyzers is not None:
                scan_kwargs["analyzers"] = analyzers

            errors: list[tuple[str, str]] = []
            handler = _ErrorCapture(errors)
            loggers = _attach_error_handler(handler)
            try:
                results = asyncio.run(scanner.scan_mcp_config_file(**scan_kwargs))
            finally:
                for lgr in loggers:
                    lgr.removeHandler(handler)

            # Partition captured ERROR logs. An unreachable *LLM backend*
            # (Ollama / vLLM / a cloud endpoint) must NOT abort a local
            # MCP scan: the YARA lane ran fine and its findings are the
            # whole point of the scan. Only a genuine *MCP server*
            # connection failure — the stdio server we spawned — is fatal.
            # Pre-fix this conflated the two and turned an unreachable LLM
            # into a misleading "failed to connect to local server".
            llm_errors = [m for (name, m) in errors if _is_llm_backend_error(name, m, self._llm)]
            other_errors = [m for (name, m) in errors if not _is_llm_backend_error(name, m, self._llm)]

            connection_errors = [
                e for e in other_errors
                if "connect" in e.lower() or "connection" in e.lower()
            ]
            if connection_errors:
                raise RuntimeError(
                    f"failed to connect to local server {entry.name!r} "
                    f"({entry.command}): {connection_errors[0]}"
                )
            if llm_errors:
                # Graceful degrade: keep the YARA findings, surface a skip
                # notice so the operator knows semantic analysis was
                # skipped (rather than silently passing).
                print(
                    f"warning: LLM skipped (backend unreachable) while scanning "
                    f"{entry.name!r}: {llm_errors[0]}",
                    file=sys.stderr,
                )
            if not results and other_errors:
                raise RuntimeError(
                    f"scan failed for local server {entry.name!r} "
                    f"({entry.command}): {other_errors[0]}"
                )

            all_findings: list[object] = []
            for tr in results:
                entity_name = getattr(tr, "tool_name", "")
                for finding in _extract_findings(tr):
                    finding._entity_name = entity_name
                    finding._entity_type = "tool"
                    all_findings.append(finding)
            return all_findings
        finally:
            os.unlink(tmp_path)

    def _scan_remote(self, scanner: object, target: str,
                     analyzers: list | None) -> list[object]:
        """Scan a remote MCP server by URL."""
        cfg = self.config
        all_findings: list[object] = []

        tool_results = asyncio.run(
            scanner.scan_remote_server_tools(target, analyzers=analyzers)
        )
        for tr in tool_results:
            entity_name = getattr(tr, "tool_name", "")
            for finding in _extract_findings(tr):
                finding._entity_name = entity_name
                finding._entity_type = "tool"
                all_findings.append(finding)

        if cfg.scan_prompts:
            prompt_results = asyncio.run(
                scanner.scan_remote_server_prompts(target, analyzers=analyzers)
            )
            for pr in prompt_results:
                entity_name = getattr(pr, "prompt_name", "")
                for finding in _extract_findings(pr):
                    finding._entity_name = entity_name
                    finding._entity_type = "prompt"
                    all_findings.append(finding)

        if cfg.scan_resources:
            resource_results = asyncio.run(
                scanner.scan_remote_server_resources(target, analyzers=analyzers)
            )
            for rr in resource_results:
                entity_name = getattr(rr, "resource_name", "") or getattr(rr, "resource_uri", "")
                for finding in _extract_findings(rr):
                    finding._entity_name = entity_name
                    finding._entity_type = "resource"
                    all_findings.append(finding)

        if cfg.scan_instructions:
            try:
                instr_results = asyncio.run(
                    scanner.scan_remote_server_instructions(target, analyzers=analyzers)
                )
                items = instr_results if isinstance(instr_results, list) else [instr_results]
                for ir in items:
                    for finding in _extract_findings(ir):
                        finding._entity_name = "server-instructions"
                        finding._entity_type = "instructions"
                        all_findings.append(finding)
            except Exception as exc:
                print(f"warning: scan_remote_server_instructions failed: {exc}", file=sys.stderr)

        return all_findings

    def _convert(self, sdk_findings: list[object], target: str, elapsed: float) -> ScanResult:
        """Convert SDK SecurityFinding list → DefenseClaw ScanResult."""
        findings: list[Finding] = []
        for sf in sdk_findings:
            severity = getattr(sf, "severity", "UNKNOWN")
            if hasattr(severity, "name"):
                severity = severity.name
            severity = str(severity).upper()

            entity_name = getattr(sf, "_entity_name", "")
            entity_type = getattr(sf, "_entity_type", "")
            location = f"{entity_type}:{entity_name}" if entity_type and entity_name else entity_name

            tags: list[str] = []
            threat_cat = getattr(sf, "threat_category", None)
            if threat_cat:
                cat_str = threat_cat.name if hasattr(threat_cat, "name") else str(threat_cat)
                tags.append(cat_str)

            taxonomy = getattr(sf, "mcp_taxonomy", None) or {}
            if isinstance(taxonomy, dict):
                aisubtech = taxonomy.get("aisubtech_name", "")
                if aisubtech:
                    tags.append(aisubtech)

            description = ""
            if taxonomy and isinstance(taxonomy, dict):
                description = taxonomy.get("description", "")
            if not description:
                details = getattr(sf, "details", None)
                if isinstance(details, dict):
                    description = details.get("evidence", "") or details.get("reason", "")

            analyzer = getattr(sf, "analyzer", "")
            scanner_name = f"mcp-scanner/{analyzer}" if analyzer else "mcp-scanner"

            findings.append(Finding(
                id=f"mcp-{analyzer}-{len(findings)}" if analyzer else f"mcp-{len(findings)}",
                severity=severity,
                title=getattr(sf, "summary", ""),
                description=description,
                location=location,
                remediation="",
                scanner=scanner_name,
                tags=tags,
            ))

        return ScanResult(
            scanner="mcp-scanner",
            target=target,
            timestamp=datetime.now(timezone.utc),
            findings=findings,
            duration=timedelta(seconds=elapsed),
        )


def _extract_findings(tool_result: object) -> list[object]:
    """Extract flat list of SecurityFinding from a ToolScanResult.

    ToolScanResult stores findings in a dict keyed by analyzer name,
    or sometimes as a flat list.
    """
    findings_by_analyzer = getattr(tool_result, "findings_by_analyzer", None)
    if isinstance(findings_by_analyzer, dict):
        flat: list[object] = []
        for finding_list in findings_by_analyzer.values():
            if isinstance(finding_list, list):
                flat.extend(finding_list)
            else:
                findings = getattr(finding_list, "findings", [])
                flat.extend(findings)
        return flat

    direct = getattr(tool_result, "findings", None)
    if isinstance(direct, dict):
        flat = []
        for finding_list in direct.values():
            if isinstance(finding_list, list):
                flat.extend(finding_list)
            else:
                findings = getattr(finding_list, "findings", [])
                flat.extend(findings)
        return flat
    if isinstance(direct, list):
        return direct

    return []


# Substrings that mark an SDK ERROR log as originating in the LLM lane
# (the LLM analyzer or the LiteLLM call beneath it) rather than the MCP
# stdio transport. Used to keep an unreachable LLM backend from aborting
# a local scan whose YARA lane succeeded.
_LLM_ERROR_LOGGER_SIGNALS = ("llm", "litellm")
_LLM_ERROR_MESSAGE_SIGNALS = (
    "litellm", "llm analyzer", "llmanalyzer", "llm_analyzer",
    "ollama", "vllm", "lm studio", "lmstudio",
    "apiconnectionerror", "api_base", "chat/completions", "11434",
)


def _is_llm_backend_error(logger_name: str, message: str, llm: LLMConfig) -> bool:
    """Classify a captured SDK ERROR log as LLM-backend vs. MCP-server.

    Returns True when the error came from the LLM lane — recognised by
    the originating logger name, by LLM-specific text in the message, or
    by the configured model / endpoint host appearing in the message.
    Errs toward *False* (treat as an MCP-server error → fatal) for
    ambiguous lines so a genuine unreachable MCP server is never silently
    swallowed.
    """
    name = (logger_name or "").lower()
    if any(sig in name for sig in _LLM_ERROR_LOGGER_SIGNALS):
        return True
    msg = (message or "").lower()
    if any(sig in msg for sig in _LLM_ERROR_MESSAGE_SIGNALS):
        return True
    # The configured model / endpoint host showing up in the error is a
    # strong signal it came from the LLM call, not the MCP transport.
    model = litellm_model(llm).lower()
    if model and model in msg:
        return True
    base = (llm.base_url or "").lower()
    if base:
        host = base.split("://")[-1].split("/")[0]
        if host and host in msg:
            return True
    return False


class _ErrorCapture(logging.Handler):
    """Captures ERROR-level log messages from the SDK.

    Stores ``(logger_name, message)`` pairs so callers can tell *which*
    SDK component logged the error — the LLM analyzer's logger vs. the
    MCP transport's — which is how a degraded LLM backend is told apart
    from an unreachable MCP server.
    """

    def __init__(self, errors: list[tuple[str, str]]) -> None:
        super().__init__(level=logging.ERROR)
        self._errors = errors

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
        except Exception:  # pragma: no cover - formatting must never raise here
            msg = record.getMessage()
        self._errors.append((record.name, msg))


def _attach_error_handler(handler: logging.Handler) -> list[logging.Logger]:
    """Attach *handler* to mcpscanner loggers at every level.

    Some SDK versions set ``propagate=False`` on child loggers, so
    attaching only to the parent ``mcpscanner`` logger misses errors. The
    LLM analyzer's own logger is included so an unreachable LLM backend is
    captured (and surfaced as a skip notice) even when it doesn't
    propagate. Returns the list of loggers so the caller can remove the
    handler.
    """
    names = [
        "mcpscanner",
        "mcpscanner.core",
        "mcpscanner.core.scanner",
        "mcpscanner.core.analyzers",
        "mcpscanner.core.analyzers.llm_analyzer",
    ]
    loggers = [logging.getLogger(n) for n in names]
    for lgr in loggers:
        lgr.addHandler(handler)
    return loggers
