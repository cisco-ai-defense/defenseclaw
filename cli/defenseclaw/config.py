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

"""Configuration loader — reads/writes ~/.defenseclaw/config.yaml.

Mirrors internal/config/config.go + defaults.go + claw.go + actions.go
so that the Go orchestrator and Python CLI share the same config file.
"""

from __future__ import annotations

import logging
import os
import platform
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

from defenseclaw import connector_paths

# Back-compat re-exports — internal-but-imported-by-tests helpers that
# moved to connector_paths in S4.1. Tests in cli/tests/test_config.py
# and runtime call sites in cmd_init.py still import them from
# defenseclaw.config; keeping the aliases avoids touching unrelated test
# files (and avoids breaking the public surface that other plugins
# already depend on).
#
# noqa: F401 alone is not enough — ruff's import-sort autofix (I001) will
# silently drop aliased imports that aren't referenced inside the
# module body (because UI-level "imported but unused" rules treat the
# alias as the dead name). We expose every alias as a module-level
# attribute below so the autofix can no longer prune them, and we list
# them in __all__ for explicit re-export semantics.
from defenseclaw.connector_paths import MCPServerEntry  # noqa: F401
from defenseclaw.connector_paths import (
    _dedup as _dedup,
)
from defenseclaw.connector_paths import (
    _parse_mcp_servers_dict as _parse_mcp_servers_dict,
)
from defenseclaw.connector_paths import (  # noqa: F401
    _read_mcp_servers_from_openclaw_json as _read_mcp_servers_from_file,
)
from defenseclaw.connector_paths import (  # noqa: F401
    _read_openclaw_json as _read_openclaw_config,
)

_log = logging.getLogger(__name__)
_privacy_disable_redaction_warned = False
_llm_migration_warned_keys: set[tuple[str, ...]] = set()
_untrusted_managed_config_warned_paths: set[str] = set()

DATA_DIR_NAME = ".defenseclaw"
AUDIT_DB_NAME = "audit.db"
CONFIG_FILE_NAME = "config.yaml"
CONFIG_PATH_ENV = "DEFENSECLAW_CONFIG"
DEPLOYMENT_MODE_ENV = "DEFENSECLAW_DEPLOYMENT_MODE"
VALID_DEPLOYMENT_MODES = {
    "managed_enterprise",
    "unmanaged_byod",
    "ci_cd",
    "sandboxed",
    "server",
    "saas",
}
LEGACY_DEPLOYMENT_MODE_ALIASES = {
    "managed": "managed_enterprise",
    "standalone": "unmanaged_byod",
    "ci": "ci_cd",
    "edge": "server",
}

if os.name == "nt":
    import msvcrt

    # msvcrt.locking() locks a byte range starting at the file pointer's
    # CURRENT position. To get mutual exclusion we must lock the SAME byte
    # (offset 0) on every acquisition, so we seek(0) immediately before each
    # lock/unlock call and we never write to the lock file. Writing (in any
    # mode) can advance the pointer or grow the file, which would make
    # concurrent holders lock disjoint ranges and silently defeat the lock.
    def _lock_file_exclusive(file_obj) -> None:
        while True:
            file_obj.seek(0)
            try:
                # LK_LOCK blocks for ~10s then raises; retry so this behaves
                # like a blocking exclusive lock (fcntl.flock(LOCK_EX)).
                msvcrt.locking(file_obj.fileno(), msvcrt.LK_LOCK, 1)
                return
            except OSError:
                time.sleep(0.05)

    def _unlock_file(file_obj) -> None:
        file_obj.seek(0)
        try:
            msvcrt.locking(file_obj.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            # Lock already released (e.g. handle closed); don't crash
            # teardown/save paths.
            pass

else:
    import fcntl

    def _lock_file_exclusive(file_obj) -> None:
        fcntl.flock(file_obj.fileno(), fcntl.LOCK_EX)

    def _unlock_file(file_obj) -> None:
        fcntl.flock(file_obj.fileno(), fcntl.LOCK_UN)


def _coerce_bool(value: Any, *, default: bool = False) -> bool:
    """Robustly coerce a YAML/JSON config scalar into a real boolean.

    Plain ``bool`` values pass through unchanged. Strings are matched
    case-insensitively against well-known truthy/falsey tokens so a
    quoted ``"false"`` loaded from ``config.yaml`` resolves to ``False``
    instead of collapsing to ``True`` via Python's ``bool("false")``
    (every non-empty string is truthy). This is the security-relevant
    case for TLS skip-verify flags: ``insecure_skip_verify: "false"``
    must NOT disable certificate verification. Unknown / unparseable
    values fall back to ``default``.
    """
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        token = value.strip().lower()
        if token in ("1", "true", "yes", "on"):
            return True
        if token in ("0", "false", "no", "off", ""):
            return False
        return default
    return default


def _as_int(value: Any, default: int) -> int:
    """Coerce a config scalar without letting malformed YAML brick the CLI."""

    if isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _home() -> Path:
    return Path.home()


def default_data_path() -> Path:
    """Return the DefenseClaw data directory.

    When running under ``sudo``, checks the invoking user's home first
    so that ``sudo defenseclaw sandbox init`` finds the config created
    by the unprivileged user.  Falls back to the current user's home.
    """
    env_override = os.environ.get("DEFENSECLAW_HOME")
    if env_override:
        return Path(env_override)

    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and os.getuid() == 0:
        try:
            import pwd

            pw = pwd.getpwnam(sudo_user)
            candidate = Path(pw.pw_dir) / DATA_DIR_NAME
            if (candidate / CONFIG_FILE_NAME).is_file():
                return candidate
        except KeyError:
            pass

    return _home() / DATA_DIR_NAME


def config_path() -> Path:
    override = os.environ.get(CONFIG_PATH_ENV)
    if override:
        return Path(override)
    return Path(default_data_path()) / CONFIG_FILE_NAME


def config_path_for_data_dir(data_dir: str | os.PathLike[str] | None = None) -> Path:
    """Return the active config path for a caller-scoped data directory."""
    if os.environ.get(CONFIG_PATH_ENV):
        return config_path()
    if data_dir:
        return Path(data_dir) / CONFIG_FILE_NAME
    return config_path()


def _expand(p: str) -> str:
    if p.startswith("~/"):
        return str(_home() / p[2:])
    return p


# ---------------------------------------------------------------------------
# Environment detection (mirrors config.DetectEnvironment)
# ---------------------------------------------------------------------------


def detect_environment() -> str:
    system = platform.system()
    if system == "Windows":
        return "windows"
    if system == "Darwin":
        return "macos"
    if Path("/etc/dgx-release").exists():
        return "dgx-spark"
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "-L"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        if "DGX" in out:
            return "dgx-spark"
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass
    return "linux"


def _validate_deployment_mode(mode: str) -> str:
    mode = (mode or "").strip()
    if not mode:
        return ""
    mode = LEGACY_DEPLOYMENT_MODE_ALIASES.get(mode, mode)
    if mode not in VALID_DEPLOYMENT_MODES:
        raise ValueError(
            f"config: deployment_mode={mode!r} is invalid "
            "(allowed: managed_enterprise, unmanaged_byod, "
            "ci_cd, sandboxed, server, saas)"
        )
    return mode


def _is_admin_process() -> bool:
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    if os.name == "nt":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return False


def _is_managed_enterprise_doc(data: dict[str, Any] | None) -> bool:
    if not isinstance(data, dict):
        return False
    try:
        return _validate_deployment_mode(str(data.get("deployment_mode", "") or "")) == "managed_enterprise"
    except ValueError:
        return False


def _is_managed_enterprise_mode(value: str | None) -> bool:
    try:
        return _validate_deployment_mode(str(value or "")) == "managed_enterprise"
    except ValueError:
        return False


def _assert_config_write_allowed(path: str, data: dict[str, Any] | None = None) -> None:
    managed = _is_managed_enterprise_mode(os.environ.get(DEPLOYMENT_MODE_ENV)) or _is_managed_enterprise_doc(data)
    if not managed:
        try:
            managed = _is_managed_enterprise_doc(_load_existing_config_yaml(path))
        except Exception:
            managed = False
    if managed and not _is_admin_process():
        raise PermissionError(
            "managed_enterprise config changes require operating-system "
            "administrator privileges; use the enterprise managed config path "
            "or rerun this command with admin elevation"
        )


def _managed_config_trust_problem(path: str) -> str | None:
    """Return why a managed config path would fail the Unix gateway trust check.

    This is diagnostic only: the Go gateway remains the enforcement boundary.
    Keep the Unix checks aligned with ``internal/managed/trust_unix.go`` so the
    Python CLI does not report a managed posture from a config the gateway will
    refuse to load. Windows uses ACL-based trust validation in the gateway and
    is intentionally not approximated with POSIX metadata here.
    """
    if os.name == "nt":
        return None

    current = os.path.abspath(path)
    is_config = True
    while True:
        try:
            info = os.lstat(current)
        except OSError as exc:
            return f"{current}: cannot inspect path metadata: {exc}"

        mode = info.st_mode
        if stat.S_ISLNK(mode):
            return f"{current}: symlinks are not allowed in managed config paths"
        if is_config:
            if not stat.S_ISREG(mode):
                return f"{current}: expected a regular managed config file"
        elif not stat.S_ISDIR(mode):
            return f"{current}: expected a directory in the managed config path"
        if stat.S_IMODE(mode) & 0o022:
            return (
                f"{current}: group/other writable permissions "
                f"{stat.S_IMODE(mode):04o} are not trusted"
            )

        acl_problem = _macos_write_acl_problem(current)
        if acl_problem is not None:
            return acl_problem

        owner_uid = getattr(info, "st_uid", None)
        if owner_uid is None:
            return f"{current}: cannot inspect path owner"
        if owner_uid != 0:
            return (
                f"{current}: owner uid {owner_uid} is not trusted; "
                "expected root/admin uid 0"
            )

        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent
        is_config = False


def _macos_write_acl_problem(path: str) -> str | None:
    """Return a fail-closed diagnostic for write-capable macOS ACL entries."""
    if platform.system() != "Darwin":
        return None
    try:
        proc = subprocess.run(
            ["/bin/ls", "-lde", "--", path],
            check=False,
            capture_output=True,
            text=True,
            env={"LANG": "C", "LC_ALL": "C"},
        )
    except OSError as exc:
        return f"{path}: cannot inspect macOS ACL: {exc}"
    if proc.returncode != 0:
        detail = proc.stderr.strip() or f"exit {proc.returncode}"
        return f"{path}: cannot inspect macOS ACL: {detail}"

    write_permissions = {
        "write",
        "add_file",
        "append",
        "add_subdirectory",
        "delete",
        "delete_child",
        "writeattr",
        "writeextattr",
        "writesecurity",
        "chown",
    }
    for line in proc.stdout.splitlines():
        normalized = line.strip().lower()
        prefix, separator, _ = normalized.partition(":")
        if not separator or not prefix.isdigit() or " allow " not in normalized:
            continue
        permissions = normalized.split(" allow ", 1)[1].split(None, 1)
        if not permissions:
            return f"{path}: cannot parse macOS allow ACL"
        if write_permissions.intersection(permissions[0].split(",")):
            return f"{path}: write-capable macOS ACL entry is not trusted"
    return None


def _warn_untrusted_managed_config(path: str, data: dict[str, Any]) -> None:
    """Warn once when CLI state came from a gateway-untrusted managed config."""
    if not _is_managed_enterprise_doc(data):
        return
    normalized = os.path.abspath(path)
    if normalized in _untrusted_managed_config_warned_paths:
        return
    problem = _managed_config_trust_problem(normalized)
    if problem is None:
        return
    _untrusted_managed_config_warned_paths.add(normalized)
    print(
        "warning: managed_enterprise config trust check failed: "
        f"{problem}. The gateway will reject this config; CLI-reported state is "
        "not authoritative. Provision it with the macOS enterprise installer "
        "or another administrator-owned deployment mechanism.",
        file=sys.stderr,
    )


_sandbox_mode_cache: bool | None = None


def openclaw_cmd_prefix() -> list[str]:
    """Return ``["sudo", "-u", "sandbox"]`` when in standalone sandbox mode.

    Used by any code that shells out to the ``openclaw`` CLI so that
    config writes target the sandbox-owned OpenClaw home.  The prefix
    does NOT include the ``openclaw`` binary itself — callers append it.
    When in sandbox mode, ``sudo -u sandbox`` won't inherit the invoking
    user's PATH, so callers should use :func:`openclaw_bin` for the
    binary path.
    """
    global _sandbox_mode_cache
    if _sandbox_mode_cache is None:
        try:
            cp = config_path()
            if cp.is_file():
                import yaml

                with open(cp) as f:
                    raw = yaml.safe_load(f) or {}
                mode = raw.get("openshell", {}).get("mode", "")
                _sandbox_mode_cache = mode == "standalone"
            else:
                _sandbox_mode_cache = False
        except Exception:
            _sandbox_mode_cache = False
    if _sandbox_mode_cache:
        return ["sudo", "-u", "sandbox"]
    return []


_openclaw_bin_cache: str | None = None


def openclaw_bin() -> str:
    """Return the absolute path to the ``openclaw`` binary.

    Resolves via ``shutil.which`` first, then checks common npm install
    locations.  Falls back to the bare name ``"openclaw"`` if it cannot
    be found (letting the caller's subprocess raise a clear error).
    """
    global _openclaw_bin_cache
    if _openclaw_bin_cache is None:
        import shutil

        found = shutil.which("openclaw")
        if not found:
            from pathlib import Path

            candidates = [
                Path.home() / ".npm-global" / "bin" / "openclaw",
                Path("/usr/local/bin/openclaw"),
                Path.home() / ".local" / "bin" / "openclaw",
            ]
            for c in candidates:
                if c.is_file():
                    found = str(c)
                    break
        _openclaw_bin_cache = found or "openclaw"
    return _openclaw_bin_cache


# ---------------------------------------------------------------------------
# Dataclasses — same YAML keys as Go structs
# ---------------------------------------------------------------------------

# MCPServerEntry now lives in defenseclaw.connector_paths so any caller
# that imported it from defenseclaw.config keeps working — see the
# `from defenseclaw.connector_paths import MCPServerEntry` re-export
# at the top of this module. Keeping the dataclass next to the
# connector-aware MCP readers means there's exactly one schema across
# the four supported agent frameworks.


@dataclass
class ClawConfig:
    mode: str = "openclaw"
    home_dir: str = "~/.openclaw"
    config_file: str = "~/.openclaw/openclaw.json"
    workspace_dir: str = ""
    openclaw_home_original: str = ""


# Canonical LLM environment variables. Mirrors internal/config/config.go.
#
# DEFENSECLAW_LLM_KEY is THE single env var users set to supply a shared
# API key across the guardrail upstream, LLM judge, MCP scanner, skill
# scanner, and plugin scanner. Per-component `llm:` blocks can override
# the key with a different env var, but the default is this one.
#
# DEFENSECLAW_LLM_MODEL is the env-based default for llm.model when
# config.yaml doesn't pin one (e.g. first-run after ``defenseclaw
# setup``).
DEFENSECLAW_LLM_KEY_ENV = "DEFENSECLAW_LLM_KEY"
DEFENSECLAW_LLM_MODEL_ENV = "DEFENSECLAW_LLM_MODEL"

_DEFAULT_LLM_TIMEOUT = 30
_DEFAULT_LLM_MAX_RETRIES = 2

# Recognized "provider/" prefixes understood by both the Go gateway
# (Bifrost routes by the provider prefix) and by the Python scanners
# (LiteLLM accepts the same "provider/model" shape). Anything outside
# this set triggers a one-shot warning so typos surface early. Keep in
# lockstep with recognizedLLMProviders in internal/config/config.go.
_RECOGNIZED_LLM_PROVIDERS = frozenset(
    {
        "openai",
        "anthropic",
        "azure",
        "gemini",
        "gemini-openai",
        "vertex_ai",
        "bedrock",
        "groq",
        "mistral",
        "cohere",
        "ollama",
        "vllm",
        "deepseek",
        "xai",
        "fireworks_ai",
        "perplexity",
        "huggingface",
        "replicate",
        "openrouter",
        "together_ai",
        "cerebras",
        "lm_studio",
        "lmstudio",
        "local",
    }
)

_LOCAL_LLM_PROVIDERS = frozenset({"ollama", "vllm", "lm_studio", "lmstudio", "local"})

_warned_llm_prefixes: set[tuple[str, str]] = set()


def _maybe_warn_unknown_provider(prefix: str, component_path: str) -> None:
    if not prefix or prefix in _RECOGNIZED_LLM_PROVIDERS:
        return
    key = (component_path, prefix)
    if key in _warned_llm_prefixes:
        return
    _warned_llm_prefixes.add(key)
    _log.warning(
        "config: unknown LLM provider prefix %r for %s — expected one of "
        "openai/anthropic/azure/gemini/gemini-openai/vertex_ai/bedrock/"
        "groq/mistral/cohere/ollama/vllm/deepseek/xai/fireworks_ai/"
        "perplexity/huggingface/replicate/openrouter/together_ai/cerebras/"
        "lm_studio/local. Gateway (Bifrost) and scanners (LiteLLM) may "
        "disagree on how to route this model",
        prefix,
        component_path,
    )


# --- Provider-typed config blocks ---------------------------------------
#
# Bedrock / Vertex / Azure each carry provider-specific configuration
# the generic ``LLMConfig`` cannot express (region, auth mode, project
# id, endpoint, api version, deployment aliases). Modelling them as
# small typed dataclasses keeps the YAML self-describing and lets
# ``Config.resolve_llm`` surface a single object that downstream callers
# (gateway provider builder, doctor, credentials registry) can inspect
# without sniffing magic env vars.
#
# All sub-blocks are optional — omitting them keeps the legacy "set
# region via AWS_REGION env var" path working unchanged.


@dataclass
class BedrockKeyConfig:
    """Bedrock-specific configuration. Mirrors the Go-side BedrockKeyConfig."""

    region: str = ""
    # auth_mode is one of:
    #   * "api_key"        — single ABSK... bearer token (default, simplest)
    #   * "iam_credentials" — explicit access + secret (+ optional session)
    #   * "profile"         — read from ~/.aws/credentials
    #   * "instance_role"   — no credentials, region from IMDS (EC2/ECS/EKS)
    auth_mode: str = "api_key"
    access_key_env: str = ""
    secret_key_env: str = ""
    session_token_env: str = ""
    profile_name: str = ""
    # Inference profile prefix hints (e.g. "us." / "eu." / "apac.") —
    # purely informational; the model string already carries the prefix.
    inference_profile: str = ""
    # Maps a friendly model alias (the value the operator types in
    # ``llm.model``) to the full Bedrock inference-profile model id.
    # Parity with :attr:`AzureKeyConfig.deployment_aliases`; lets
    # operators say ``--model sonnet-4`` instead of pasting the full
    # ``us.anthropic.claude-sonnet-4-6`` every time.
    deployment_aliases: dict[str, str] = field(default_factory=dict)


@dataclass
class VertexKeyConfig:
    """Vertex / Google Cloud LLM configuration."""

    project_id: str = ""
    region: str = ""
    # auth_mode is one of:
    #   * "service_account" — path to JSON key file via env var
    #   * "adc"             — application default credentials
    auth_mode: str = "service_account"
    service_account_json_env: str = "GOOGLE_APPLICATION_CREDENTIALS"


@dataclass
class AzureKeyConfig:
    """Azure OpenAI configuration."""

    endpoint: str = ""
    api_version: str = "2024-10-21"
    # auth_mode is one of:
    #   * "api_key"  — bearer key from the Azure portal
    #   * "entra_id" — managed identity / service principal (Bifrost handles)
    auth_mode: str = "api_key"
    # Maps a friendly model name (the value the operator types in
    # ``llm.model``) to the on-disk Azure deployment name. Required
    # because Azure deployments are named per-tenant and almost never
    # match the upstream model id.
    deployment_aliases: dict[str, str] = field(default_factory=dict)


@dataclass
class LLMTLSConfig:
    """TLS overrides for self-hosted / on-prem custom-provider instances.

    Mutually exclusive: setting both ``ca_cert_pem`` and
    ``insecure_skip_verify`` is rejected by the validator. Used when an
    operator points at an internal LLM endpoint behind a self-signed
    or private-CA-issued certificate.
    """

    ca_cert_pem: str = ""
    insecure_skip_verify: bool = False


@dataclass
class LLMConfig:
    """Unified LLM configuration block.

    Mirrors internal/config/config.go::LLMConfig. Used both at the top
    level (``config.llm``) and as a per-component override under
    ``scanners.*``, ``guardrail``, and ``guardrail.judge``. The resolver
    ``Config.resolve_llm(path)`` merges the top-level defaults with the
    per-component override and returns the effective settings.

    Model string convention:

    * Use ``"provider/model-id"`` — e.g. ``"openai/gpt-4o"``,
      ``"anthropic/claude-3-5-sonnet-20241022"``,
      ``"ollama/llama3.1"``, ``"azure/<deployment-name>"``,
      ``"bedrock/anthropic.claude-3-5-sonnet-20240620-v1:0"``.
    * The prefix is shared by the Go gateway (Bifrost routes by the
      ``provider/`` prefix) AND by the Python scanners (LiteLLM accepts
      the same ``provider/model`` shape). A bare model id (no slash) is
      allowed but emits an unknown-prefix warning.

    ``api_key`` vs ``api_key_env``: prefer ``api_key_env`` so the secret
    stays out of ``config.yaml``. An empty ``api_key_env`` falls back to
    ``DEFENSECLAW_LLM_KEY`` — the canonical env var for the whole
    product. Local providers (``ollama/``, ``vllm/``, ``lm_studio/``)
    don't need a key; an empty resolved value is allowed.

    ``instance_name`` selects a named entry from
    ``~/.defenseclaw/custom-providers.json``. When set, the resolver
    folds in the overlay's ``base_url``, ``tls``, and provider-typed
    sub-block (bedrock/vertex/azure) before returning the effective
    config. Only ``model`` then needs to be set on the role itself.
    """

    model: str = ""
    provider: str = ""
    api_key: str = ""
    api_key_env: str = ""
    base_url: str = ""
    timeout: int = 0
    max_retries: int = 0
    # Generic provider-typed knobs. Empty / None means "fall back to the
    # next layer" — env vars, then upstream defaults.
    region: str = ""
    instance_name: str = ""
    bedrock: BedrockKeyConfig | None = None
    vertex: VertexKeyConfig | None = None
    azure: AzureKeyConfig | None = None
    tls: LLMTLSConfig | None = None

    def resolved_api_key(self) -> str:
        """Return the API key from env var first, then inline value.

        Resolution order:

        1. If ``api_key_env`` is explicitly set, read from that env var
           and return it if non-empty.
        2. Otherwise, if ``api_key`` is explicitly set inline, return
           it — users who hard-code a key in config.yaml expect it to
           win over the unified-key fallback.
        3. Finally, fall back to the canonical ``DEFENSECLAW_LLM_KEY``
           env var so operators can set exactly one env var and have
           every LLM-using component inherit it.

        Mirrors ``internal/config/config.go::LLMConfig.ResolvedAPIKey``
        after its v5 refinement — keeping these in sync is required by
        ``cli/tests/test_llm_env.py::ParityTests``.
        """
        if self.api_key_env:
            val = os.environ.get(self.api_key_env, "").strip()
            if val:
                return val
        if self.api_key:
            return self.api_key
        return os.environ.get(DEFENSECLAW_LLM_KEY_ENV, "").strip()

    def effective_timeout(self) -> int:
        return self.timeout if self.timeout > 0 else _DEFAULT_LLM_TIMEOUT

    def effective_max_retries(self) -> int:
        return self.max_retries if self.max_retries > 0 else _DEFAULT_LLM_MAX_RETRIES

    def provider_prefix(self) -> str:
        if self.provider:
            return self.provider.strip().lower()
        if "/" in self.model:
            return self.model.split("/", 1)[0].strip().lower()
        return ""

    def is_local_provider(self) -> bool:
        """Return True when the resolved provider runs on-box and
        doesn't need an API key (ollama, vllm, lm_studio) or when the
        base_url points at a loopback address."""
        if self.provider_prefix() in _LOCAL_LLM_PROVIDERS:
            return True
        if self.base_url:
            host = self.base_url.lower()
            if "127.0.0.1" in host or "localhost" in host or "[::1]" in host or host.startswith("unix:"):
                return True
        return False


@dataclass
class InspectLLMConfig:
    """DEPRECATED: pre-v5 Shared LLM configuration used by both
    skill-scanner and mcp-scanner. The v5 replacement is :class:`LLMConfig`
    at ``config.llm``; prefer ``Config.resolve_llm("scanners.skill")``
    or ``Config.resolve_llm("scanners.mcp")`` over reading this.

    This class remains for back-compat round-tripping and is populated
    from the legacy ``inspect_llm:`` block. ``load()`` migrates the
    values into ``config.llm`` so every new caller can go through
    :meth:`Config.resolve_llm`.
    """

    provider: str = ""
    model: str = ""
    api_key: str = ""
    api_key_env: str = ""
    base_url: str = ""
    timeout: int = 30
    max_retries: int = 3

    def resolved_api_key(self) -> str:
        """Return api_key from env var (if set) or direct value."""
        if self.api_key_env:
            val = os.environ.get(self.api_key_env, "")
            if val:
                return val
        return self.api_key


@dataclass
class CiscoAIDefenseConfig:
    """Shared Cisco AI Defense configuration used by scanners and guardrail."""

    endpoint: str = "https://us.api.inspect.aidefense.security.cisco.com"
    api_key: str = ""
    api_key_env: str = ""
    timeout_ms: int = 3000
    enabled_rules: list[str] = field(default_factory=list)

    def resolved_api_key(self) -> str:
        """Return api_key from env var (if set) or direct value."""
        if self.api_key_env:
            import os

            val = os.environ.get(self.api_key_env, "")
            if val:
                return val
        return self.api_key


@dataclass
class SkillScannerConfig:
    binary: str = "skill-scanner"
    use_llm: bool = False
    use_behavioral: bool = False
    enable_meta: bool = False
    use_trigger: bool = False
    use_virustotal: bool = False
    use_aidefense: bool = False
    llm_consensus_runs: int = 0
    policy: str = "permissive"
    lenient: bool = True
    # LLM overrides the top-level ``llm:`` block for the skill scanner.
    # Unset fields inherit from ``Config.llm`` via
    # ``Config.resolve_llm("scanners.skill")``.
    llm: LLMConfig = field(default_factory=LLMConfig)
    virustotal_api_key: str = ""
    virustotal_api_key_env: str = ""

    def resolved_virustotal_api_key(self) -> str:
        """Return VirusTotal key from env var (if set) or direct value."""
        if self.virustotal_api_key_env:
            val = os.environ.get(self.virustotal_api_key_env, "")
            if val:
                return val
        return self.virustotal_api_key


@dataclass
class MCPScannerConfig:
    binary: str = "mcp-scanner"
    analyzers: str = "auto"
    scan_prompts: bool = False
    scan_resources: bool = False
    scan_instructions: bool = False
    # LLM overrides the top-level ``llm:`` block for the MCP scanner.
    llm: LLMConfig = field(default_factory=LLMConfig)


@dataclass
class ScannersConfig:
    skill_scanner: SkillScannerConfig = field(default_factory=SkillScannerConfig)
    mcp_scanner: MCPScannerConfig = field(default_factory=MCPScannerConfig)
    # plugin_llm overrides the top-level ``llm:`` block for the plugin
    # scanner, which uses LiteLLM directly (not Bifrost). Per the plan,
    # plugin-scanner LLM calls intentionally bypass the guardrail to
    # avoid burning tokens on 3rd-party plugin analysis.
    plugin_llm: LLMConfig = field(default_factory=LLMConfig)
    codeguard: str = ""


DEFAULT_OPENSHELL_VERSION = "0.6.2"
DEFAULT_SANDBOX_HOME = "/home/sandbox"


@dataclass
class OpenShellConfig:
    binary: str = "openshell"
    policy_dir: str = "/etc/openshell/policies"
    mode: str = ""
    version: str = DEFAULT_OPENSHELL_VERSION
    sandbox_home: str = DEFAULT_SANDBOX_HOME
    auto_pair: bool | None = None
    host_networking: bool = True

    def is_standalone(self) -> bool:
        return self.mode == "standalone"

    def effective_version(self) -> str:
        return self.version or DEFAULT_OPENSHELL_VERSION

    def effective_sandbox_home(self) -> str:
        return self.sandbox_home or DEFAULT_SANDBOX_HOME

    def should_auto_pair(self) -> bool:
        if self.auto_pair is not None:
            return self.auto_pair
        return True


@dataclass
class WatchConfig:
    debounce_ms: int = 500
    auto_block: bool = True
    allow_list_bypass_scan: bool = True
    rescan_enabled: bool = True
    rescan_interval_min: int = 60


@dataclass
class SplunkConfig:
    hec_endpoint: str = "https://localhost:8088/services/collector/event"
    hec_token: str = ""
    hec_token_env: str = ""
    index: str = "defenseclaw"
    source: str = "defenseclaw"
    sourcetype: str = "_json"
    # (and parity with Go ): TLS verification is now ON by
    # default. ``verify_tls`` is the LEGACY opt-in-to-security flag and
    # is honoured when explicitly true (no-op against the new secure
    # default); explicit false is silently IGNORED. Operators that
    # genuinely need to bypass certificate validation (dev environments
    # with self-signed HEC) must set ``insecure_skip_verify=True``.
    verify_tls: bool = True
    insecure_skip_verify: bool = False
    enabled: bool = False
    batch_size: int = 50
    flush_interval_s: int = 5

    def tls_verify_enabled(self) -> bool:
        """Resolve effective TLS verification posture.

        returns False only when ``insecure_skip_verify`` is
        explicitly true. ``verify_tls=False`` no longer downgrades the
        sink — operators must move the explicit opt-out to the new
        ``insecure_skip_verify`` flag. Any other combination yields a
        secure default of True so omitting the field never silently
        leaks the HEC token to a MITM peer.

        The flag is run through :func:`_coerce_bool` so a quoted
        ``"false"`` persisted in ``config.yaml`` (a truthy non-empty
        string under bare ``bool()``) cannot silently disable TLS
        verification.
        """
        return not _coerce_bool(self.insecure_skip_verify)

    def resolved_hec_token(self) -> str:
        """Return HEC token from env var (if set) or direct value."""
        if self.hec_token_env:
            val = os.environ.get(self.hec_token_env, "")
            if val:
                return val
        return self.hec_token


@dataclass
class OTelTLSConfig:
    insecure: bool = False
    ca_cert: str = ""


@dataclass
class OTelTracesConfig:
    enabled: bool = True
    sampler: str = "always_on"
    sampler_arg: str = "1.0"
    endpoint: str = ""
    protocol: str = ""
    url_path: str = ""


@dataclass
class OTelLogsConfig:
    enabled: bool = True
    emit_individual_findings: bool = False
    endpoint: str = ""
    protocol: str = ""
    url_path: str = ""


@dataclass
class OTelMetricsConfig:
    enabled: bool = True
    export_interval_s: int = 60
    temporality: str = "delta"
    endpoint: str = ""
    protocol: str = ""
    url_path: str = ""


@dataclass
class OTelBatchConfig:
    max_export_batch_size: int = 512
    scheduled_delay_ms: int = 5000
    max_queue_size: int = 2048


@dataclass
class OTelResourceConfig:
    attributes: dict[str, str] = field(default_factory=dict)


@dataclass
class OTelSpanFilterOperationConfig:
    name: str = ""
    require_attributes: list[str] = field(default_factory=list)


@dataclass
class OTelSpanFilterConfig:
    require_operation: str = ""
    require_attributes: list[str] = field(default_factory=list)
    operations: list[OTelSpanFilterOperationConfig] = field(default_factory=list)


@dataclass
class OTelDestinationConfig:
    """One named OTLP fan-out destination.

    Process-wide resource attributes and trace sampling remain on
    :class:`OTelConfig`; transport, credentials, signal selection, and queue
    settings are isolated per destination.
    """

    name: str = ""
    preset: str = ""
    enabled: bool = True
    protocol: str = "grpc"
    endpoint: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    tls: OTelTLSConfig = field(default_factory=OTelTLSConfig)
    traces: OTelTracesConfig = field(default_factory=OTelTracesConfig)
    logs: OTelLogsConfig = field(default_factory=OTelLogsConfig)
    metrics: OTelMetricsConfig = field(default_factory=OTelMetricsConfig)
    batch: OTelBatchConfig = field(default_factory=OTelBatchConfig)
    span_filter: OTelSpanFilterConfig = field(default_factory=OTelSpanFilterConfig)


@dataclass
class OTelTracePolicyConfig:
    sampler: str = "always_on"
    sampler_arg: str = "1.0"


@dataclass
class OTelLogPolicyConfig:
    emit_individual_findings: bool = False


@dataclass
class OTelMetricPolicyConfig:
    export_interval_s: int = 60
    temporality: str = "delta"


@dataclass
class OTelConfig:
    enabled: bool = False
    traces: OTelTracePolicyConfig = field(default_factory=OTelTracePolicyConfig)
    logs: OTelLogPolicyConfig = field(default_factory=OTelLogPolicyConfig)
    metrics: OTelMetricPolicyConfig = field(default_factory=OTelMetricPolicyConfig)
    batch: OTelBatchConfig = field(default_factory=OTelBatchConfig)
    resource: OTelResourceConfig = field(default_factory=OTelResourceConfig)
    destinations: list[OTelDestinationConfig] = field(default_factory=list)


@dataclass
class GatewayWatcherSkillConfig:
    enabled: bool = True
    take_action: bool = False
    dirs: list[str] = field(default_factory=list)


@dataclass
class GatewayWatcherPluginConfig:
    enabled: bool = True
    take_action: bool = False
    dirs: list[str] = field(default_factory=list)


@dataclass
class GatewayWatcherConfig:
    enabled: bool = True
    skill: GatewayWatcherSkillConfig = field(default_factory=GatewayWatcherSkillConfig)
    plugin: GatewayWatcherPluginConfig = field(default_factory=GatewayWatcherPluginConfig)


@dataclass
class GatewayConfigReloadConfig:
    mode: str = "hot"


@dataclass
class GatewayConfig:
    host: str = "127.0.0.1"
    port: int = 18789
    api_bind: str = ""
    token: str = ""
    token_env: str = ""
    device_key_file: str = ""
    auto_approve_safe: bool = False
    reconnect_ms: int = 800
    max_reconnect_ms: int = 15000
    approval_timeout_s: int = 30
    api_port: int = 18970
    config_reload: GatewayConfigReloadConfig = field(default_factory=GatewayConfigReloadConfig)
    watcher: GatewayWatcherConfig = field(default_factory=GatewayWatcherConfig)

    def resolved_token(self) -> str:
        """Return the gateway auth token, walking the precedence ladder.

        Resolution order:

        1. ``self.token_env`` — operator-supplied override, ALWAYS wins.
           This lets ``defenseclaw setup`` / ops tooling pin the var
           name explicitly without us guessing.
        2. ``DEFENSECLAW_GATEWAY_TOKEN`` — the canonical name the Go
           gateway (`internal/gateway/firstboot.go::EnsureGatewayToken`)
           writes to ``~/.defenseclaw/.env`` on first boot.
        3. ``OPENCLAW_GATEWAY_TOKEN`` — back-compat shim for installs
           that bootstrapped before the defenseclaw rename. The Go
           gateway also reads this for the same reason; honouring it
           here keeps the two sides symmetric.
        4. ``self.token`` — literal value from ``config.yaml``. Last
           resort because plaintext secrets in YAML are discouraged
           (and ``_warn_plaintext_secrets`` already nags about it).

        Returns the empty string when no token is reachable; callers
        gate on the truthiness, so empty == "unauthenticated".
        """
        if self.token_env:
            val = os.environ.get(self.token_env, "")
            if val:
                return val
        val = os.environ.get("DEFENSECLAW_GATEWAY_TOKEN", "")
        if val:
            return val
        val = os.environ.get("OPENCLAW_GATEWAY_TOKEN", "")
        if val:
            return val
        return self.token


@dataclass
class SeverityAction:
    file: str = "none"
    runtime: str = "enable"
    install: str = "none"


@dataclass
class SkillActionsConfig:
    critical: SeverityAction = field(default_factory=SeverityAction)
    high: SeverityAction = field(default_factory=SeverityAction)
    medium: SeverityAction = field(default_factory=SeverityAction)
    low: SeverityAction = field(default_factory=SeverityAction)
    info: SeverityAction = field(default_factory=SeverityAction)

    def for_severity(self, severity: str) -> SeverityAction:
        return {
            "CRITICAL": self.critical,
            "HIGH": self.high,
            "MEDIUM": self.medium,
            "LOW": self.low,
        }.get(severity.upper(), self.info)

    def should_disable(self, severity: str) -> bool:
        return self.for_severity(severity).runtime == "disable"

    def should_quarantine(self, severity: str) -> bool:
        return self.for_severity(severity).file == "quarantine"

    def should_install_block(self, severity: str) -> bool:
        return self.for_severity(severity).install == "block"


@dataclass
class MCPActionsConfig:
    critical: SeverityAction = field(
        default_factory=lambda: SeverityAction(file="none", runtime="enable", install="block"),
    )
    high: SeverityAction = field(
        default_factory=lambda: SeverityAction(file="none", runtime="enable", install="block"),
    )
    medium: SeverityAction = field(default_factory=SeverityAction)
    low: SeverityAction = field(default_factory=SeverityAction)
    info: SeverityAction = field(default_factory=SeverityAction)

    def for_severity(self, severity: str) -> SeverityAction:
        return {
            "CRITICAL": self.critical,
            "HIGH": self.high,
            "MEDIUM": self.medium,
            "LOW": self.low,
        }.get(severity.upper(), self.info)

    def should_install_block(self, severity: str) -> bool:
        return self.for_severity(severity).install == "block"


@dataclass
class PluginActionsConfig:
    critical: SeverityAction = field(default_factory=SeverityAction)
    high: SeverityAction = field(default_factory=SeverityAction)
    medium: SeverityAction = field(default_factory=SeverityAction)
    low: SeverityAction = field(default_factory=SeverityAction)
    info: SeverityAction = field(default_factory=SeverityAction)

    def for_severity(self, severity: str) -> SeverityAction:
        return {
            "CRITICAL": self.critical,
            "HIGH": self.high,
            "MEDIUM": self.medium,
            "LOW": self.low,
        }.get(severity.upper(), self.info)

    def should_disable(self, severity: str) -> bool:
        return self.for_severity(severity).runtime == "disable"

    def should_quarantine(self, severity: str) -> bool:
        return self.for_severity(severity).file == "quarantine"

    def should_install_block(self, severity: str) -> bool:
        return self.for_severity(severity).install == "block"


@dataclass
class AssetRuntimeDetectionConfig:
    enabled: bool = True
    terminal_commands: bool = True
    unknown_terminal_mcp: str = "observe"


@dataclass
class AssetPolicyRule:
    name: str = ""
    connector: str = ""
    reason: str = ""
    url: str = ""
    command: str = ""
    args_prefix: list[str] = field(default_factory=list)
    transport: str = ""
    source_path_contains: list[str] = field(default_factory=list)


@dataclass
class AssetTypePolicy:
    default: str = "allow"
    registry_required: bool = False
    registry: list[AssetPolicyRule] = field(default_factory=list)
    allowed: list[AssetPolicyRule] = field(default_factory=list)
    denied: list[AssetPolicyRule] = field(default_factory=list)
    runtime_detection: AssetRuntimeDetectionConfig = field(default_factory=AssetRuntimeDetectionConfig)
    # registry_empty_action mirrors the Go-side
    # AssetTypePolicy.RegistryEmptyAction. When `registry_required`
    # is on AND `registry` is empty, this controls admission:
    # "deny" (default, fail-closed) / "warn" / "allow". The Python
    # CLI doesn't make admission decisions but surfaces the field
    # in `registry require` so operators see the implication of an
    # empty list before the gateway starts denying traffic.
    registry_empty_action: str = "deny"


def _default_runtime_asset_type_policy() -> AssetTypePolicy:
    return AssetTypePolicy()


def _default_nonruntime_asset_type_policy() -> AssetTypePolicy:
    return AssetTypePolicy(
        runtime_detection=AssetRuntimeDetectionConfig(
            enabled=False,
            terminal_commands=False,
            unknown_terminal_mcp="observe",
        ),
    )


@dataclass
class PerConnectorAssetTypePolicy:
    """Per-connector scalar overrides for one asset type (OTHER-7).

    Scalars-only, mirroring :class:`PerConnectorGuardrailConfig`: an empty
    ``default`` / ``registry_empty_action`` or a ``None``
    ``registry_required`` inherits the global :class:`AssetTypePolicy`
    value (the ``None`` pointer mirrors the Go ``*bool`` inherit-on-nil
    semantics). Rule lists (``registry`` / ``allowed`` / ``denied``) and
    ``runtime_detection`` are deliberately NOT per-connector — they stay on
    the global per-type policy and are filtered by ``rule.connector`` at
    match time. Mirrors ``PerConnectorAssetTypePolicy`` in
    ``internal/config/asset_policy.go``.
    """

    default: str = ""
    registry_required: bool | None = None
    registry_empty_action: str = ""


@dataclass
class PerConnectorAssetPolicy:
    """Per-connector ``asset_policy`` overrides keyed by connector name.

    Mirrors ``PerConnectorAssetPolicy`` in
    ``internal/config/asset_policy.go``. ``mode`` empty inherits the global
    ``asset_policy.mode``; each per-type block, when present, overrides only
    the scalars it sets and inherits the rest. A ``None`` per-type block
    means "inherit the global per-type policy entirely".
    """

    mode: str = ""
    mcp: PerConnectorAssetTypePolicy | None = None
    skill: PerConnectorAssetTypePolicy | None = None
    plugin: PerConnectorAssetTypePolicy | None = None


@dataclass
class AssetPolicyConfig:
    enabled: bool = False
    mode: str = "observe"
    mcp: AssetTypePolicy = field(default_factory=_default_runtime_asset_type_policy)
    skill: AssetTypePolicy = field(default_factory=_default_nonruntime_asset_type_policy)
    plugin: AssetTypePolicy = field(default_factory=_default_nonruntime_asset_type_policy)
    # Per-connector overrides keyed by connector name (OTHER-7). Empty/absent
    # preserves the legacy global-only behavior. Only the scalar settings are
    # per-connector; rule lists + runtime_detection stay on the global per-type
    # policy. Resolution goes through the ``effective_*`` methods, never by
    # reading the map directly. Mirrors ``AssetPolicyConfig.Connectors`` in
    # ``internal/config/asset_policy.go`` and the ``guardrail.connectors`` shape.
    connectors: dict[str, PerConnectorAssetPolicy] = field(default_factory=dict)

    def _connector_override(self, connector: str) -> PerConnectorAssetPolicy | None:
        """Return the override block for ``connector`` if configured.

        An empty connector name or empty map yields ``None`` so callers fall
        through to the global value. Lookup is connector-name-insensitive
        (exact key first, then via ``connector_paths.normalize``), mirroring
        :meth:`GuardrailConfig._connector_override` and the Go
        ``connectorOverride``.
        """
        if not connector or not self.connectors:
            return None
        pc = self.connectors.get(connector)
        if pc is not None:
            return pc
        want = connector_paths.normalize(connector)
        for name, entry in self.connectors.items():
            if connector_paths.normalize(name) == want:
                return entry
        return None

    def effective_mode(self, connector: str = "") -> str:
        """Per-connector override > global mode > ``"observe"``."""
        pc = self._connector_override(connector)
        if pc is not None and pc.mode.strip():
            return pc.mode.strip()
        if self.mode.strip():
            return self.mode.strip()
        return "observe"

    def effective_asset_type_policy(self, connector: str, target_type: str) -> AssetTypePolicy | None:
        """Resolve the effective per-type policy for a connector.

        Returns a copy of the global per-type :class:`AssetTypePolicy` with
        only the three scalars (``default`` / ``registry_required`` /
        ``registry_empty_action``) overridden where the per-connector entry
        sets them; the rule lists and ``runtime_detection`` stay the global
        policy's. Returns ``None`` for an unsupported target type so the
        caller can fall through to its allow-unsupported path. Mirrors the Go
        ``assetPolicyFor(connector, targetType)`` overlay.
        """
        if target_type not in ("mcp", "skill", "plugin"):
            return None
        base: AssetTypePolicy = getattr(self, target_type)
        pc = self._connector_override(connector)
        override = getattr(pc, target_type, None) if pc is not None else None
        if override is None:
            return base
        changes: dict[str, Any] = {}
        if override.default.strip():
            changes["default"] = override.default.strip()
        if override.registry_required is not None:
            changes["registry_required"] = override.registry_required
        if override.registry_empty_action.strip():
            changes["registry_empty_action"] = override.registry_empty_action.strip().lower()
        if not changes:
            return base
        return replace(base, **changes)

    def validate(self) -> None:
        """Validate per-connector asset_policy VALUE invariants only.

        Mirrors :meth:`GuardrailConfig.validate` over the NEW
        ``asset_policy.connectors`` map: rejects empty / alias-duplicate
        connector names and checks each override's enum values (``mode`` and
        the per-type ``default`` / ``registry_empty_action`` scalars). It
        deliberately does NOT re-validate the global asset_policy fields
        (those predate per-connector support and were never gated by
        ``load()``) and never touches the connector registry — unknown
        connector identity is left to the gateway boot loop, exactly like
        guardrail. Raises :class:`ValueError` on the first violation.
        """
        seen: dict[str, str] = {}
        for name in sorted(self.connectors):
            if not name.strip():
                raise ValueError("asset_policy.connectors: empty connector name is not allowed")
            norm = connector_paths.normalize(name)
            if norm in seen:
                raise ValueError(
                    f"asset_policy.connectors: {seen[norm]!r} and {name!r} refer "
                    f"to the same connector {norm!r}; keep only one"
                )
            seen[norm] = name
            pc = self.connectors[name]
            try:
                _validate_asset_policy_mode(pc.mode)
                for ttype in ("mcp", "skill", "plugin"):
                    block = getattr(pc, ttype, None)
                    if block is not None:
                        _validate_asset_type_default(block.default)
                        _validate_registry_empty_action(block.registry_empty_action)
            except ValueError as exc:
                raise ValueError(f"asset_policy.connectors[{name!r}]: {exc}") from exc


def _validate_asset_policy_mode(mode: str) -> None:
    if (mode or "").strip().lower() not in {"", "observe", "action"}:
        raise ValueError(f'invalid asset_policy mode {mode!r} (want "observe" or "action")')


def _validate_asset_type_default(value: str) -> None:
    if (value or "").strip().lower() not in {"", "allow", "deny", "block"}:
        raise ValueError(f'invalid asset_policy default {value!r} (want "allow" or "deny")')


def _validate_registry_empty_action(value: str) -> None:
    if (value or "").strip().lower() not in {"", "deny", "warn", "allow", "block"}:
        raise ValueError(f'invalid registry_empty_action {value!r} (want "deny", "warn", or "allow")')


# ---------------------------------------------------------------------------
# Registries — external skill / MCP catalog sources that feed
# ``asset_policy.{skill,mcp}.registry`` via the `defenseclaw registry sync`
# pipeline. The block is round-tripped through load/save so operator-added
# sources survive process restarts; the on-disk index lives separately
# under ``~/.defenseclaw/registries/<id>/index.json`` (see
# defenseclaw.registries.cache).
# ---------------------------------------------------------------------------

REGISTRY_KINDS: tuple[str, ...] = (
    "clawhub",
    "smithery",
    "skills_sh",
    "http_yaml",
    "http_json",
    "git",
    "file",
)
"""Allow-list of recognised registry source kinds.

Anything outside this set is rejected at validation time by both the
CLI (``registry add --kind ...``) and the loader. Adding a new kind
requires a matching adapter under ``cli/defenseclaw/registries/`` and a
corresponding match in :func:`registries.adapters.dispatch`.
"""

REGISTRY_CONTENT_TYPES: tuple[str, ...] = ("skill", "mcp", "both")


@dataclass
class RegistrySource:
    """One registry source entry inside ``registries.sources[]``.

    Mirrors the Go-side ``internal/config.RegistrySource``. Field
    semantics:

    * ``id``                  — operator-chosen identifier (unique,
                                kebab-case recommended). Used as the
                                ``Reason: "registry:<id>"`` provenance
                                tag on every promoted ``AssetPolicyRule``
                                and as the cache directory name.
    * ``kind``                — one of :data:`REGISTRY_KINDS`. Selects
                                which adapter handles ``fetch()``.
    * ``url``                 — manifest URL / git URL / local path.
                                Empty for ``kind="clawhub"`` (uses the
                                npm openclaw package by convention).
    * ``content``             — declared content type — must be one of
                                :data:`REGISTRY_CONTENT_TYPES`. Adapters
                                that publish only one type (clawhub /
                                smithery) ignore this field.
    * ``auth_env``            — env var holding a bearer token, never
                                the literal token. Empty disables auth.
    * ``enabled``             — when False the source is preserved in
                                config but skipped by ``sync --all``.
    * ``auto_sync``           — RESERVED. Scheduled sync is not yet
                                implemented; setting this to True today
                                does NOT cause periodic ingest.
                                Persisted so a v1 -> v2 operator config
                                doesn't lose the bit. Run
                                ``defenseclaw registry sync --all`` (or
                                schedule it via cron) until the v2
                                scheduler ships.
    * ``sync_interval_hours`` — RESERVED. Paired with ``auto_sync``;
                                ignored at runtime today.
    * ``last_sync``           — ISO-8601 UTC timestamp; populated by
                                the sync command on success.
    * ``last_status``         — ``ok`` or ``error: <reason>``.
    """

    id: str = ""
    kind: str = "http_yaml"
    url: str = ""
    content: str = "skill"
    auth_env: str = ""
    enabled: bool = True
    auto_sync: bool = False
    sync_interval_hours: int = 24
    last_sync: str = ""
    last_status: str = ""


@dataclass
class RegistriesConfig:
    sources: list[RegistrySource] = field(default_factory=list)


@dataclass
class FirewallConfig:
    config_file: str = ""
    rules_file: str = ""
    anchor_name: str = "com.defenseclaw"


@dataclass
class JudgeConfig:
    enabled: bool = False
    injection: bool = True
    pii: bool = True
    pii_prompt: bool = True
    pii_completion: bool = True
    tool_injection: bool = True
    # ``exfil`` runs a dedicated data-exfiltration judge that asks the
    # LLM whether a prompt is trying to read or exfiltrate sensitive
    # files / credentials / secrets. Distinct from the injection judge
    # (which asks "are you overriding my instructions?") and the PII
    # judge (which only fires on substring PII). Mirrors the Go-side
    # ``JudgeConfig.Exfil`` field — round-tripped through ``config.yaml``
    # so the operator's choice survives a process restart.
    exfil: bool = True
    timeout: float = 30.0
    # ``hook_connectors`` gates the hook-lane judge per connector
    # (mirrors Go ``JudgeConfig.HookConnectors``): hook connectors
    # listed here forward prompts / tool results to the LLM judge in
    # addition to the regex + Cisco AID lanes. Empty = hook lane off
    # (the proxy lane is unaffected); ``"*"`` enables every connector.
    hook_connectors: list[str] = field(default_factory=list)
    # Hook-lane judge timeout in seconds (Go ``JudgeConfig.HookTimeout``).
    # 0 means the gateway default (5s, sized under the hook scripts'
    # ``curl --max-time 10`` budget — the proxy lane's 30s would let the
    # client hang up before a verdict lands).
    hook_timeout: float = 0.0
    # LLM overrides the top-level ``llm:`` block for the LLM judge.
    # Prefer ``Config.resolve_llm("guardrail.judge")`` over reading this
    # directly; the legacy ``model``/``api_key_env``/``api_base`` fields
    # below are kept only for pre-v5 round-tripping.
    llm: LLMConfig = field(default_factory=LLMConfig)
    # DEPRECATED (v<5): migrated into ``llm`` at load time.
    model: str = ""
    api_key_env: str = ""
    api_base: str = ""
    fallbacks: list[str] = field(default_factory=list)
    adjudication_timeout: float = 5.0


@dataclass
class WebhookConfig:
    # Mirrors ``internal/config.WebhookConfig`` (notifier webhook, not an
    # audit sink — see docs/OBSERVABILITY.md §7).
    #
    # ``name`` is the CLI-visible identifier used by
    # ``defenseclaw setup webhook {enable,disable,remove,show,test}``.
    # It is round-tripped through load/save so that ``config.save()``
    # doesn't silently drop the operator's chosen name. Empty values
    # are stripped in ``_config_to_dict`` to mirror Go's ``omitempty``.
    #
    # ``cooldown_seconds`` is tri-state to match the Go pointer
    # (``*int``) — see ``internal/gateway/webhook.go``
    # ``webhookDefaultCooldown = 300s``:
    #   * ``None``  → YAML key absent / null; dispatcher applies its
    #                 default cooldown (currently 300s).
    #   * ``0``     → explicit "dispatch every matching event"; kept
    #                 verbatim on round-trip so the YAML ``0`` doesn't
    #                 silently collapse back to "default 300s".
    #   * ``> 0``   → explicit minimum seconds between dispatches per
    #                 (webhook, event_category) pair.
    name: str = ""
    url: str = ""
    type: str = "generic"
    secret_env: str = ""
    room_id: str = ""
    min_severity: str = "HIGH"
    events: list[str] = field(default_factory=list)
    timeout_seconds: int = 10
    cooldown_seconds: int | None = None
    enabled: bool = False

    def resolved_secret(self) -> str:
        """Return the webhook secret/token from the env var."""
        if self.secret_env:
            return os.environ.get(self.secret_env, "")
        return ""


@dataclass
class PerConnectorObservability:
    """Per-connector observability override (D5b) keyed by connector name.

    A connector's events route to *its* configured sinks/webhooks,
    falling back to the GLOBAL list (top-level ``audit_sinks:`` /
    ``webhooks:``) when a dimension is unset. Each dimension is
    independently tri-state, mirroring the Go ``*[]T`` / nil-vs-empty
    pointer semantics used elsewhere in this file:

    * ``None``       — key absent; INHERIT the global list. This is the
                       default and the safety fallback: a connector with
                       no per-connector config still emits to the global
                       sinks (no silent drop).
    * present list   — OVERRIDE: route this connector's events to exactly
                       these entries. An explicit empty list ``[]``
                       suppresses the global list for that connector.

    ``audit_sinks`` is kept as raw mappings rather than a typed dataclass
    so it round-trips verbatim alongside the unmodelled top-level
    ``audit_sinks:`` list (whose schema is owned by the Go gateway and
    ``defenseclaw.observability.writer``). ``webhooks`` reuses the modeled
    :class:`WebhookConfig`, parity with the top-level ``webhooks:`` list.
    """

    audit_sinks: list[dict[str, Any]] | None = None
    webhooks: list[WebhookConfig] | None = None


@dataclass
class ObservabilityConfig:
    """Per-connector observability routing (D5b).

    ``connectors`` maps a connector name to its
    :class:`PerConnectorObservability` override. Empty/absent preserves the
    legacy global-only behavior. Resolution goes through
    :meth:`effective_audit_sinks` / :meth:`effective_webhooks` (which take
    the global list and fall back to it), never by reading the map
    directly — mirroring :class:`AssetPolicyConfig` and
    ``guardrail.connectors``.

    NOTE (lane boundary): the runtime event-emit dispatch lives in the Go
    gateway (``internal/gateway/webhook.go`` for webhooks,
    ``internal/audit/sinks`` for audit sinks). This Python structure is the
    config + resolution surface so ``Config.save()`` round-trips the block
    and Python consumers can resolve it; HONORING the resolution at emit
    time additionally requires the matching Go change (flagged separately —
    those files are outside this lane).
    """

    connectors: dict[str, PerConnectorObservability] = field(default_factory=dict)

    def _connector_override(self, connector: str) -> PerConnectorObservability | None:
        """Return the override block for ``connector`` if configured.

        Lookup is connector-name-insensitive (exact key first, then via
        ``connector_paths.normalize``), mirroring
        :meth:`AssetPolicyConfig._connector_override`.
        """
        if not connector or not self.connectors:
            return None
        pc = self.connectors.get(connector)
        if pc is not None:
            return pc
        want = connector_paths.normalize(connector)
        for name, entry in self.connectors.items():
            if connector_paths.normalize(name) == want:
                return entry
        return None

    def effective_audit_sinks(
        self,
        connector: str,
        global_sinks: list[dict[str, Any]] | None,
    ) -> list[dict[str, Any]]:
        """Resolve the audit sinks a connector's events route to.

        Per-connector override (when the ``audit_sinks`` dimension is set)
        wins; otherwise inherit ``global_sinks``. ``global_sinks`` is passed
        in because the global ``audit_sinks:`` list is unmodelled (read from
        raw YAML), not a :class:`Config` field.
        """
        pc = self._connector_override(connector)
        if pc is not None and pc.audit_sinks is not None:
            return list(pc.audit_sinks)
        return list(global_sinks or [])

    def effective_webhooks(
        self,
        connector: str,
        global_webhooks: list[WebhookConfig] | None,
    ) -> list[WebhookConfig]:
        """Resolve the webhooks a connector's events route to.

        Per-connector override (when the ``webhooks`` dimension is set)
        wins; otherwise inherit ``global_webhooks`` (``cfg.webhooks``).
        """
        pc = self._connector_override(connector)
        if pc is not None and pc.webhooks is not None:
            return list(pc.webhooks)
        return list(global_webhooks or [])

    def validate(self) -> None:
        """Reject empty / alias-duplicate connector names.

        Value-only check mirroring :meth:`AssetPolicyConfig.validate` —
        never touches the connector registry. Raises :class:`ValueError`
        on the first violation.
        """
        seen: dict[str, str] = {}
        for name in sorted(self.connectors):
            if not name.strip():
                raise ValueError("observability.connectors: empty connector name is not allowed")
            norm = connector_paths.normalize(name)
            if norm in seen:
                raise ValueError(
                    f"observability.connectors: {seen[norm]!r} and {name!r} refer "
                    f"to the same connector {norm!r}; keep only one"
                )
            seen[norm] = name


@dataclass
class HILTConfig:
    enabled: bool = False
    min_severity: str = "HIGH"


@dataclass
class PerConnectorGuardrailConfig:
    """Per-connector guardrail overrides (hook-based connectors only).

    Mirrors ``config.PerConnectorGuardrailConfig`` in
    ``internal/config/config.go``. Every field is optional: an unset
    (empty / ``None``) field inherits the global :class:`GuardrailConfig`
    value via the ``effective_*`` resolvers. ``hilt`` is ``None`` to mean
    "inherit the global HILT block"; a present block (even an empty one)
    explicitly overrides it.
    """

    mode: str = ""
    hilt: HILTConfig | None = None
    hook_fail_mode: str = ""
    block_message: str = ""
    rule_pack_dir: str = ""
    # Per-connector on/off switch toggled by
    # ``defenseclaw guardrail {enable,disable} --connector X``. ``None``
    # (the default) means "inherit the default (enabled)" — the connector
    # stays active exactly as before. ``False`` means the operator
    # explicitly disabled this one connector: the Go boot loop drops it
    # from the active set so its hooks are torn down (per-connector analog
    # of the global ``guardrail disable``), while its other policy fields
    # are retained so re-enable restores it with no re-prompt. Resolved via
    # :meth:`GuardrailConfig.effective_enabled`; never read directly.
    enabled: bool | None = None


@dataclass
class GuardrailConfig:
    enabled: bool = False
    mode: str = "observe"  # observe | action
    scanner_mode: str = "both"  # local | remote | both
    host: str = "localhost"  # host where guardrail proxy is reachable (bridge IP in sandbox mode)
    port: int = 4000
    # LLM overrides the top-level ``llm:`` block for the guardrail
    # upstream (the model DefenseClaw proxies client traffic to).
    # Prefer ``Config.resolve_llm("guardrail")``.
    llm: LLMConfig = field(default_factory=LLMConfig)
    # DEPRECATED (v<5): migrated into ``llm`` at load time. Kept for
    # pre-v5 round-tripping only — new writers should emit ``llm:``.
    model: str = ""  # upstream model, e.g. "anthropic/claude-opus-4-5"
    model_name: str = ""  # alias exposed to OpenClaw, e.g. "claude-opus"
    api_key_env: str = ""  # env var holding the API key, e.g. "ANTHROPIC_API_KEY"
    api_base: str = ""  # base URL override for Azure, custom endpoints
    # OriginalModel is NOT a secret-bearing LLM config field — it just
    # records the upstream model name the client sees rewritten onto
    # outgoing requests (Bifrost model-routing). Orthogonal to ``llm``.
    original_model: str = ""  # original OpenClaw model (for revert)
    block_message: str = ""  # custom message shown when a request is blocked (empty = default)
    judge: JudgeConfig = field(default_factory=JudgeConfig)
    detection_strategy: str = "regex_judge"  # regex_only | regex_judge | judge_first
    detection_strategy_prompt: str = ""  # per-direction override
    detection_strategy_completion: str = ""  # per-direction override
    detection_strategy_tool_call: str = ""  # per-direction override
    # Run full judge classification on content with no regex signal
    # (regex_judge mode). Flipped from False to True in the
    # multi-provider-adapters PR: pure-regex triage misses enough
    # semantic jailbreaks (e.g. "/ etc / passwd" whitespace evasion,
    # "passswd" typo variants) that judge_sweep defaulting off was
    # the dominant false-negative source in internal red-team runs.
    # Operators who care about latency over recall can still set
    # `judge_sweep: false` explicitly and the loader will honor it
    # (the YAML parser below uses .get(key, <default>) so the presence
    # of the key wins, and an explicit `false` round-trips as False).
    judge_sweep: bool = True
    rule_pack_dir: str = ""  # path to guardrail rule-pack profile directory
    connector: str = ""  # empty => fall back to claw.mode; otherwise a registered connector name
    hilt: HILTConfig = field(default_factory=HILTConfig)
    # ``hook_fail_mode`` is the operator-chosen response-layer fail
    # mode for every generated hook (codex-hook, claude-code-hook,
    # inspect-*). Two values are supported:
    #
    #   - ``"closed"`` (default, safer): when the gateway answers
    #     with a 4xx, malformed JSON, or a missing action field,
    #     hooks BLOCK the tool/prompt at the response-layer boundary.
    #     CodeGuard rule codeguard-0-authorization-access-control:
    #     deny by default.
    #
    #   - ``"open"``: the same response-layer failures ALLOW the
    #     tool/prompt with a stderr warning and a record in
    #     ``$DEFENSECLAW_HOME/logs/hook-failures.jsonl``. Choose when
    #     a brief observability gap is preferable to bricking the
    #     agent on a gateway hiccup.
    #
    # Backwards compat: existing v3 installs are pinned to ``"open"``
    # by ``_migrate_0_4_0_seed_hook_fail_mode`` so the flip is a
    # NEW-INSTALL-ONLY behavior change.
    #
    # Transport-layer failures (gateway unreachable / 5xx) are
    # handled separately by each hook's ``fail_unreachable`` helper
    # and ALWAYS allow unless the operator opts into strict
    # availability via ``DEFENSECLAW_STRICT_AVAILABILITY=1`` —
    # regardless of this field's value. Mirrors
    # ``GuardrailConfig.HookFailMode`` in internal/config/config.go.
    hook_fail_mode: str = "closed"
    # ``llm_role`` is the operator's answer to "should DefenseClaw's
    # LLM be used only as a judge, or also as the agent's upstream?".
    # One of:
    #   * ""               — legacy / unset; treat like ``judge_only``
    #                        on hook connectors and like
    #                        ``judge_and_agent`` on proxy connectors
    #                        based on the resolved connector kind.
    #   * "judge_only"     — DefenseClaw's LLM is used only by the
    #                        judge; the agent keeps its own LLM
    #                        config. Mandatory shape for hook
    #                        connectors (codex/claudecode/hermes/...);
    #                        opt-in for proxy connectors.
    #   * "judge_and_agent" — Proxy connectors only. DefenseClaw is
    #                        the agent's LLM router AND runs the
    #                        judge with the same key.
    # Used by the wizard to remember the operator's choice across
    # reruns so reconfigure flows don't re-prompt.
    llm_role: str = ""
    # Per-connector guardrail overrides keyed by connector name
    # (hook-based connectors only). Empty/absent preserves the legacy
    # single-connector behavior driven by the singular ``connector``
    # field. Mirrors ``GuardrailConfig.Connectors`` in
    # ``internal/config/config.go``; resolution goes through the
    # ``effective_*`` methods, never by reading the map directly.
    connectors: dict[str, PerConnectorGuardrailConfig] = field(default_factory=dict)

    def _connector_override(self, connector: str) -> PerConnectorGuardrailConfig | None:
        """Return the override block for ``connector`` if configured.

        An empty connector name or empty map yields ``None`` so callers
        uniformly fall through to the global value. Lookup is
        connector-name-insensitive: an exact key hit is the fast path,
        otherwise keys are compared after ``connector_paths.normalize`` so
        a request for the canonical name (e.g. ``"openhands"``) resolves an
        override written with different case or a hyphen/underscore alias
        (e.g. ``"OpenHands"``, ``"open-hands"``). Mirrors
        ``GuardrailConfig.connectorOverride`` in Go.
        """
        if not connector or not self.connectors:
            return None
        pc = self.connectors.get(connector)
        if pc is not None:
            return pc
        want = connector_paths.normalize(connector)
        for name, entry in self.connectors.items():
            if connector_paths.normalize(name) == want:
                return entry
        return None

    def effective_mode(self, connector: str = "") -> str:
        """Per-connector override > global mode > ``"observe"``."""
        pc = self._connector_override(connector)
        if pc is not None and pc.mode.strip():
            return pc.mode.strip()
        if self.mode.strip():
            return self.mode.strip()
        return "observe"

    def effective_enabled(self, connector: str = "") -> bool:
        """Per-connector on/off resolver — mirrors Go ``EffectiveEnabled``.

        Defaults to ``True``: an absent override, or an override whose
        ``enabled`` field is ``None`` (unset), resolves to enabled, so
        single-connector installs and any connector never explicitly
        disabled keep running. Only an explicit ``enabled: false`` returns
        ``False`` — the signal the Go boot loop uses to drop the connector
        from the active set (triggering teardown) and the hook gates use to
        short-circuit it to allow-without-scan.
        """
        pc = self._connector_override(connector)
        if pc is not None and pc.enabled is not None:
            return pc.enabled
        return True

    def effective_hilt(self, connector: str = "") -> HILTConfig:
        """Per-connector hilt block (when present) fully replaces global."""
        pc = self._connector_override(connector)
        if pc is not None and pc.hilt is not None:
            return pc.hilt
        return self.hilt

    def effective_hook_fail_mode(self, connector: str = "") -> str:
        """Per-connector override > global > ``"open"`` (non-"closed")."""
        pc = self._connector_override(connector)
        if pc is not None and pc.hook_fail_mode.strip():
            if pc.hook_fail_mode.strip().lower() == "closed":
                return "closed"
            return "open"
        if self.hook_fail_mode.strip().lower() == "closed":
            return "closed"
        return "open"

    def effective_block_message(self, connector: str = "") -> str:
        """Per-connector block message when set, else the global one."""
        pc = self._connector_override(connector)
        if pc is not None and pc.block_message != "":
            return pc.block_message
        return self.block_message

    def effective_rule_pack_dir(self, connector: str = "") -> str:
        """Per-connector rule-pack dir when set, else the global one."""
        pc = self._connector_override(connector)
        if pc is not None and pc.rule_pack_dir.strip():
            return pc.rule_pack_dir
        return self.rule_pack_dir

    def validate(self) -> None:
        """Validate per-connector guardrail VALUE invariants only.

        Leaf check mirroring ``GuardrailConfig.Validate`` in Go over the
        NEW ``guardrail.connectors`` map: inspects each override's enum
        values (mode, hook_fail_mode, hilt.min_severity) and rejects empty
        connector names. It deliberately does NOT re-validate the global
        guardrail fields — those predate multi-connector support and were
        never gated by ``load()``, so checking them here could reject
        configs that load fine today. Never touches the connector
        registry; the hook-membership guard lives in the gateway boot
        loop. Raises :class:`ValueError` with a named message on the
        first violation.
        """
        seen: dict[str, str] = {}
        for name in sorted(self.connectors):
            if not name.strip():
                raise ValueError("guardrail.connectors: empty connector name is not allowed")
            # Reject two distinct keys that canonicalize to the same connector
            # (e.g. "claude-code" + "claudecode", or "OpenHands" + "openhands").
            # connector_override()/active_connectors() resolve keys through
            # connector_paths.normalize, so a duplicate would make per-connector
            # lookups and the active-connector roster ambiguous. Mirrors the Go
            # GuardrailConfig.Validate duplicate-key guard.
            norm = connector_paths.normalize(name)
            if norm in seen:
                raise ValueError(
                    f"guardrail.connectors: {seen[norm]!r} and {name!r} refer to "
                    f"the same connector {norm!r}; keep only one"
                )
            seen[norm] = name
            pc = self.connectors[name]
            try:
                _validate_guardrail_mode(pc.mode)
                _validate_guardrail_hook_fail_mode(pc.hook_fail_mode)
                if pc.hilt is not None:
                    _validate_guardrail_min_severity(pc.hilt.min_severity)
            except ValueError as exc:
                raise ValueError(f"guardrail.connectors[{name!r}]: {exc}") from exc


def _validate_guardrail_mode(mode: str) -> None:
    if (mode or "").strip() not in {"", "observe", "action"}:
        raise ValueError(f'invalid guardrail mode {mode!r} (want "observe" or "action")')


def _validate_guardrail_hook_fail_mode(mode: str) -> None:
    if (mode or "").strip().lower() not in {"", "open", "closed"}:
        raise ValueError(f'invalid hook_fail_mode {mode!r} (want "open" or "closed")')


def _validate_guardrail_min_severity(sev: str) -> None:
    if (sev or "").strip().upper() not in {"", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise ValueError(f"invalid hilt.min_severity {sev!r} (want LOW, MEDIUM, HIGH, or CRITICAL)")


@dataclass
class NotificationSourceFilter:
    """Per-source toggles for the user-session notifier dispatcher.

    Mirrors :class:`config.NotificationSourceFilter` in
    ``internal/config/notifications.go``. Defaults are all True so a
    fresh ``notifications.enabled: true`` install reports every
    block surface; operators dial down by flipping individual
    sub-fields off.
    """

    hook: bool = True
    guardrail: bool = True
    asset_policy: bool = True


def _default_notifications_enabled() -> bool:
    """Mirror Go's ``config.DefaultNotificationsEnabled``.

    Darwin is the only platform with a consumer-grade desktop
    notification surface that every user already has running, so it
    opts in by default. Every other OS waits for an explicit
    ``defenseclaw setup notifications on`` opt-in. Implemented as a
    free function (not a literal default) so the platform check is
    evaluated at config-construction time, not module-import time —
    important for unit tests that monkey-patch ``platform.system``.
    """
    return platform.system() == "Darwin"


@dataclass
class NotificationsConfig:
    """User-session OS notifications. Mirrors internal/config.NotificationsConfig.

    Master switch ``enabled`` defaults to ``True`` on darwin and
    ``False`` elsewhere — same matrix as Go's
    ``DefaultNotificationsEnabled``. ``defenseclaw setup
    notifications`` (the single-prompt onboarding wizard) is still
    the canonical opt-in path; operators dialing noise back down can
    flip individual category / source / throttle fields.

    Category defaults favor signal over noise: ``block_enforced``
    and ``hitl_approval`` are on so users see real blocks and real
    chat-side asks, while ``block_would_block`` is OFF so the
    observe-mode "would have blocked / would have asked" toasts
    stay quiet by default. Keep these defaults in lockstep with
    ``internal/config/notifications.go``'s
    ``DefaultNotificationsConfig`` and the viper SetDefault calls
    in ``internal/config/config.go``.

    Throttle defaults match the Go side
    (``dedup_window=30s``, ``max_per_minute=12``); zero values are
    interpreted as "use the default" rather than "no throttle".
    """

    enabled: bool = field(default_factory=_default_notifications_enabled)
    block_enforced: bool = True
    block_would_block: bool = False
    hitl_approval: bool = True
    sources: NotificationSourceFilter = field(default_factory=NotificationSourceFilter)
    # Stored as the same string viper accepts on the Go side so the
    # YAML round-trips through both ends without translation.
    dedup_window: str = "30s"
    max_per_minute: int = 12


@dataclass
class RoutingConfig:
    """Semantic model routing configuration."""

    enabled: bool = False
    version: str = ""
    port: int = 0
    algorithm: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"enabled": self.enabled}
        if self.version:
            d["version"] = self.version
        if self.port:
            d["port"] = self.port
        if self.algorithm:
            d["algorithm"] = self.algorithm
        return d


@dataclass
class PrivacyConfig:
    """Privacy / redaction toggles. Mirrors internal/config.PrivacyConfig.

    ``disable_redaction`` is the persistent kill-switch documented in
    the Go redaction package: when True the sidecar bypasses every
    ForSink* helper at startup, including persistent sinks (audit DB,
    OTel logs, Splunk HEC, webhooks). It violates the
    unconditional-redaction contract documented in OBSERVABILITY.md
    by design — only enable on single-tenant installs where every
    downstream sink lives inside the same trust boundary.
    The CLI emits a warning on flip, and config loaders emit a
    once-per-process warning when they observe it.
    """

    disable_redaction: bool = False


@dataclass
class AIDiscoveryConfig:
    enabled: bool = False
    mode: str = "enhanced"
    scan_interval_min: int = 5
    process_interval_s: int = 60
    scan_roots: list[str] = field(default_factory=lambda: ["~"])
    signature_packs: list[str] = field(default_factory=list)
    allow_workspace_signatures: bool = False
    disabled_signature_ids: list[str] = field(default_factory=list)
    include_shell_history: bool = True
    include_package_manifests: bool = True
    include_env_var_names: bool = True
    include_network_domains: bool = True
    max_files_per_scan: int = 1000
    max_file_bytes: int = 512 * 1024
    emit_otel: bool = True
    store_raw_local_paths: bool = False
    confidence_policy_path: str = ""
    require_trusted_binary_paths: bool = False
    trusted_binary_prefixes: list[str] = field(default_factory=list)


@dataclass
class ApplicationProtectionAssetPolicyConfig:
    mode: str = ""


@dataclass
class ApplicationProtectionConnectorConfig:
    enabled: bool | None = None
    min_confidence: float | None = None
    guardrail: PerConnectorGuardrailConfig = field(default_factory=PerConnectorGuardrailConfig)
    asset_policy: ApplicationProtectionAssetPolicyConfig = field(
        default_factory=ApplicationProtectionAssetPolicyConfig,
    )


@dataclass
class ApplicationProtectionConfig:
    # Automatic activation writes into third-party agent configuration. Keep
    # it opt-in so upgrades preserve the pre-feature unmanaged behavior.
    enabled: bool = False
    min_confidence: float = 0.80
    remove_when_gone: bool = False
    gone_after_min: int = 60
    include_connectors: list[str] = field(default_factory=list)
    exclude_connectors: list[str] = field(default_factory=list)
    guardrail: PerConnectorGuardrailConfig = field(
        default_factory=lambda: PerConnectorGuardrailConfig(mode="observe"),
    )
    asset_policy: ApplicationProtectionAssetPolicyConfig = field(
        default_factory=lambda: ApplicationProtectionAssetPolicyConfig(mode="observe"),
    )
    connectors: dict[str, ApplicationProtectionConnectorConfig] = field(default_factory=dict)

    def effective_enabled(self, connector: str) -> bool:
        if not self.enabled:
            return False
        pc = self._connector_override(connector)
        if pc is not None and pc.enabled is not None:
            return pc.enabled
        return True

    def effective_min_confidence(self, connector: str) -> float:
        pc = self._connector_override(connector)
        if pc is not None and pc.min_confidence is not None:
            return pc.min_confidence
        return self.min_confidence or 0.80

    def effective_guardrail_mode(self, connector: str) -> str:
        pc = self._connector_override(connector)
        if pc is not None and pc.guardrail.mode.strip():
            return pc.guardrail.mode.strip()
        if self.guardrail.mode.strip():
            return self.guardrail.mode.strip()
        return "observe"

    def effective_asset_policy_mode(self, connector: str) -> str:
        pc = self._connector_override(connector)
        if pc is not None and pc.asset_policy.mode.strip():
            return pc.asset_policy.mode.strip()
        if self.asset_policy.mode.strip():
            return self.asset_policy.mode.strip()
        return "observe"

    def allows_connector(self, connector: str) -> bool:
        name = _normalize_connector_key(connector)
        if not name:
            return False
        if any(_normalize_connector_key(c) == name for c in self.exclude_connectors):
            return False
        if not self.include_connectors:
            return True
        return any(_normalize_connector_key(c) == name for c in self.include_connectors)

    def _connector_override(self, connector: str) -> ApplicationProtectionConnectorConfig | None:
        if not connector or not self.connectors:
            return None
        pc = self.connectors.get(connector)
        if pc is not None:
            return pc
        want = _normalize_connector_key(connector)
        for name, entry in self.connectors.items():
            if _normalize_connector_key(name) == want:
                return entry
        return None

    def validate(self) -> None:
        _validate_confidence("application_protection.min_confidence", self.min_confidence)
        if self.gone_after_min < 0:
            raise ValueError("application_protection.gone_after_min must be >= 0")
        _validate_connector_name_list(
            "application_protection.include_connectors",
            self.include_connectors,
        )
        _validate_connector_name_list(
            "application_protection.exclude_connectors",
            self.exclude_connectors,
        )
        try:
            _validate_guardrail_mode(self.guardrail.mode)
            _validate_guardrail_hook_fail_mode(self.guardrail.hook_fail_mode)
            if self.guardrail.hilt is not None:
                _validate_guardrail_min_severity(self.guardrail.hilt.min_severity)
            _validate_asset_policy_mode(self.asset_policy.mode)
        except ValueError as exc:
            raise ValueError(f"application_protection: {exc}") from exc
        seen: dict[str, str] = {}
        for name in sorted(self.connectors):
            if not name.strip():
                raise ValueError("application_protection.connectors: empty connector name is not allowed")
            norm = _normalize_connector_key(name)
            if norm in seen:
                raise ValueError(
                    f"application_protection.connectors: {seen[norm]!r} and "
                    f"{name!r} refer to the same connector {norm!r}; keep only one"
                )
            seen[norm] = name
            pc = self.connectors[name]
            if pc.min_confidence is not None:
                _validate_confidence(
                    f"application_protection.connectors[{name!r}].min_confidence",
                    pc.min_confidence,
                )
            try:
                _validate_guardrail_mode(pc.guardrail.mode)
                _validate_guardrail_hook_fail_mode(pc.guardrail.hook_fail_mode)
                if pc.guardrail.hilt is not None:
                    _validate_guardrail_min_severity(pc.guardrail.hilt.min_severity)
                _validate_asset_policy_mode(pc.asset_policy.mode)
            except ValueError as exc:
                raise ValueError(f"application_protection.connectors[{name!r}]: {exc}") from exc


def _validate_confidence(path: str, value: float) -> None:
    if value < 0 or value > 1:
        raise ValueError(f"{path} must be between 0 and 1")


def _validate_connector_name_list(path: str, names: list[str]) -> None:
    seen: dict[str, str] = {}
    for name in names:
        if not str(name).strip():
            raise ValueError(f"{path}: empty connector name is not allowed")
        norm = _normalize_connector_key(str(name))
        if norm in seen:
            raise ValueError(f"{path}: {seen[norm]!r} and {name!r} refer to the same connector {norm!r}; keep only one")
        seen[norm] = str(name)


def _normalize_connector_key(name: str | None) -> str:
    n = (name or "").strip().lower()
    if n in {"open-hands", "open_hands"}:
        return "openhands"
    if n in {"claude-code", "claude_code"}:
        return "claudecode"
    if n in {"gemini-cli", "gemini_cli", "gemini"}:
        return "geminicli"
    return n


@dataclass
class Config:
    data_dir: str = ""
    # Unified v5 LLM configuration. Every LLM-using component resolves
    # its effective settings via :meth:`resolve_llm`. See
    # :class:`LLMConfig` for the model-string conventions.
    llm: LLMConfig = field(default_factory=LLMConfig)
    # DEPRECATED (v<5): migrated into ``llm`` at load time. Kept for
    # back-compat round-tripping only.
    default_llm_api_key_env: str = ""
    default_llm_model: str = ""
    audit_db: str = ""
    quarantine_dir: str = ""
    plugin_dir: str = ""
    policy_dir: str = ""
    environment: str = ""
    tenant_id: str = ""
    workspace_id: str = ""
    deployment_mode: str = ""
    discovery_source: str = ""
    claw: ClawConfig = field(default_factory=ClawConfig)
    inspect_llm: InspectLLMConfig = field(default_factory=InspectLLMConfig)
    cisco_ai_defense: CiscoAIDefenseConfig = field(default_factory=CiscoAIDefenseConfig)
    scanners: ScannersConfig = field(default_factory=ScannersConfig)
    openshell: OpenShellConfig = field(default_factory=OpenShellConfig)
    watch: WatchConfig = field(default_factory=WatchConfig)
    firewall: FirewallConfig = field(default_factory=FirewallConfig)
    guardrail: GuardrailConfig = field(default_factory=GuardrailConfig)
    splunk: SplunkConfig = field(default_factory=SplunkConfig)
    otel: OTelConfig = field(default_factory=OTelConfig)
    gateway: GatewayConfig = field(default_factory=GatewayConfig)
    skill_actions: SkillActionsConfig = field(default_factory=SkillActionsConfig)
    mcp_actions: MCPActionsConfig = field(default_factory=MCPActionsConfig)
    plugin_actions: PluginActionsConfig = field(default_factory=PluginActionsConfig)
    asset_policy: AssetPolicyConfig = field(default_factory=AssetPolicyConfig)
    registries: RegistriesConfig = field(default_factory=RegistriesConfig)
    webhooks: list[WebhookConfig] = field(default_factory=list)
    # Per-connector observability routing (D5b). Empty/absent preserves the
    # legacy global-only behavior; resolution goes through
    # :class:`ObservabilityConfig` resolvers, never by reading the map directly.
    observability: ObservabilityConfig = field(default_factory=ObservabilityConfig)
    privacy: PrivacyConfig = field(default_factory=lambda: PrivacyConfig())
    _loaded_authoritative_dicts: dict[str, dict[str, Any]] = field(default_factory=dict, repr=False, compare=False)
    # Loaded raw values of _OWNED_NESTED_KEYS paths (absent = key not in
    # the file at load). Lets the merge distinguish "this process loaded
    # a value and deliberately cleared it" (drop the on-disk key) from
    # "this process never saw a value" (a concurrent writer added one —
    # preserve it). Parity with _loaded_authoritative_dicts for the
    # dict-shaped authoritative paths.
    _loaded_owned_nested_values: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)
    ai_discovery: AIDiscoveryConfig = field(default_factory=AIDiscoveryConfig)
    application_protection: ApplicationProtectionConfig = field(default_factory=ApplicationProtectionConfig)
    notifications: NotificationsConfig = field(default_factory=lambda: NotificationsConfig())
    routing: RoutingConfig = field(default_factory=RoutingConfig)

    # -- Claw-mode path resolution (mirrors claw.go) --

    def claw_home_dir(self) -> str:
        return connector_paths.connector_home(
            self.active_connector(),
            openclaw_home=self.claw.home_dir,
            workspace_dir=self.connector_workspace_dir(),
        ) or _expand(self.claw.home_dir)

    def connector_workspace_dir(self) -> str:
        """Return the explicitly pinned connector workspace, if any."""
        raw = (self.claw.workspace_dir or "").strip()
        if not raw:
            return ""
        raw = _expand(raw)
        try:
            return str(Path(raw).expanduser().resolve(strict=False))
        except OSError:
            return os.path.abspath(raw)

    def active_connector(self) -> str:
        """Return the canonical connector name for this config.

        Mirrors ``Config.activeConnector`` in claw.go: precedence is
        ``guardrail.connector`` → ``claw.mode`` → ``"openclaw"``,
        whitespace-trimmed and lowercased. Public so cmd_doctor /
        cmd_uninstall can answer "which framework is this install
        running against?" without recomputing the rule.
        """
        if self.guardrail.connector.strip():
            return connector_paths.normalize(self.guardrail.connector)
        if self.claw.mode.strip():
            return connector_paths.normalize(self.claw.mode)
        return "openclaw"

    def effective_webhooks(self, connector: str = "") -> list[WebhookConfig]:
        """Resolve which webhooks ``connector``'s events route to (D5b).

        Per-connector override (``observability.connectors[connector].webhooks``)
        wins; otherwise inherit the global ``webhooks:`` list. Convenience
        wrapper around :meth:`ObservabilityConfig.effective_webhooks` that
        supplies ``self.webhooks`` as the global fallback. The matching audit
        sink resolver lives on :class:`ObservabilityConfig` because the global
        ``audit_sinks:`` list is unmodelled (raw YAML), not a Config field.
        """
        return self.observability.effective_webhooks(connector, self.webhooks)

    def has_connector_configured(self) -> bool:
        """Return True when the operator has explicitly configured a connector.

        Distinguishes a genuinely unconfigured install — every connector
        marker empty, e.g. after ``setup remove`` clears the last one
        (which persists ``claw.mode: ''``) — from a real single-connector
        openclaw install, which pins ``claw.mode``/``guardrail.connector``
        to ``openclaw`` (see ``cmd_setup``). :meth:`active_connectors` and
        the shared list/scan resolver use this to avoid fabricating a
        phantom ``openclaw`` when nothing is set up.

        NOTE: a *missing* config file still loads ``claw.mode`` as the
        ``"openclaw"`` default (``config.load``), so this reports True
        there — the unconfigured signal is the explicit empty marker
        written on removal, not file absence.
        """
        return bool(self.guardrail.connectors or self.guardrail.connector.strip() or self.claw.mode.strip())

    def active_connectors(self) -> list[str]:
        """Return the full resolved set of connector names, sorted.

        Mirrors ``Config.activeConnectors`` in claw.go and is additive
        over :meth:`active_connector`: when the multi-connector
        ``guardrail.connectors`` map is populated its (normalized) keys
        drive the set; otherwise it is the single :meth:`active_connector`
        value, so the legacy single-connector behavior is preserved. The
        multi-connector boot loop iterates this list while existing
        single-connector callers keep using :meth:`active_connector`.

        When nothing is configured (:meth:`has_connector_configured` is
        False) this returns an empty list rather than flooring to
        ``["openclaw"]`` — callers that fan out over connectors (``status``,
        ``aibom``, the shared list/scan resolver) then render an explicit
        "no connector configured" empty state instead of a phantom
        openclaw. :meth:`active_connector` keeps its singular ``"openclaw"``
        default untouched, so path resolution and other single-connector
        callers are unaffected.
        """
        if self.guardrail.connectors:
            # Dedupe after normalization so two alias keys (e.g. "claude-code"
            # and "claudecode") can never make the boot loop iterate the same
            # connector twice. validate() rejects such configs at load, but
            # this stays robust for any caller that bypasses validation.
            names = sorted({connector_paths.normalize(name) for name in self.guardrail.connectors if name.strip()})
            if names:
                return names
        if not self.has_connector_configured():
            return []
        return [self.active_connector()]

    def skill_dirs(self, connector: str | None = None) -> list[str]:
        """Return skill directories for a connector.

        Polymorphic — when ``guardrail.connector`` is set, the
        connector-specific layout (e.g. ``~/.codex/skills``) is
        returned; otherwise falls back to OpenClaw paths derived
        from ``claw.home_dir`` and ``claw.config_file``.

        ``connector`` overrides the resolved connector so multi-connector
        callers (e.g. the TUI catalog focus selector via
        ``skill list --connector <name>``) can list a non-primary
        connector's directories. Defaults to :meth:`active_connector`.
        """
        return connector_paths.skill_dirs(
            connector or self.active_connector(),
            openclaw_home=self.claw.home_dir,
            openclaw_config=self.claw.config_file,
            workspace_dir=self.connector_workspace_dir(),
        )

    def plugin_dirs(self, connector: str | None = None) -> list[str]:
        """Return plugin/extension directories for a connector.

        See :meth:`skill_dirs` for dispatch semantics and the
        ``connector`` override used by multi-connector callers.
        """
        return connector_paths.plugin_dirs(
            connector or self.active_connector(),
            openclaw_home=self.claw.home_dir,
            workspace_dir=self.connector_workspace_dir(),
        )

    def mcp_servers(self, connector: str | None = None) -> list[MCPServerEntry]:
        """Return MCP server registrations for a connector.

        For OpenClaw the lookup prefers ``openclaw config get
        mcp.servers`` and falls back to a direct
        ``openclaw.json`` parse (with ``sudo -u sandbox`` prefix when
        running standalone-sandbox mode).

        ``connector`` overrides the resolved connector (used by
        ``mcp list --connector <name>`` for multi-connector focus);
        defaults to :meth:`active_connector`.
        """
        return connector_paths.mcp_servers(
            connector or self.active_connector(),
            openclaw_config=self.claw.config_file,
            workspace_dir=self.connector_workspace_dir(),
            openclaw_bin_resolver=openclaw_bin,
            openclaw_cmd_prefix=openclaw_cmd_prefix(),
        )

    def installed_skill_candidates(self, skill_name: str) -> list[str]:
        name = skill_name
        if "/" in name:
            name = name.rsplit("/", 1)[-1]
        name = name.lstrip("@")
        return [os.path.join(d, name) for d in self.skill_dirs()]

    def resolve_llm(self, path: str = "") -> LLMConfig:
        """Return the effective LLMConfig for the given component path.

        Mirrors ``Config.ResolveLLM`` in internal/config/config.go. The
        ``path`` selects which per-component override block to layer on
        top of ``self.llm``. Supported paths:

        * ``""``                 — the top-level block as-is
        * ``"scanners.mcp"``     — ``scanners.mcp_scanner.llm``
        * ``"scanners.skill"``   — ``scanners.skill_scanner.llm``
        * ``"scanners.plugin"``  — ``scanners.plugin_llm``
        * ``"guardrail"``        — ``guardrail.llm``
        * ``"guardrail.judge"``  — ``guardrail.judge.llm``

        Merge rules: every non-empty scalar on the override wins. An
        empty ``model`` inherits from the top level, then from the
        ``DEFENSECLAW_LLM_MODEL`` environment variable, then from the
        legacy ``default_llm_model`` field. The returned
        :class:`LLMConfig` is the single source of truth for LLM
        settings — callers MUST NOT read the deprecated
        ``inspect_llm``, ``default_llm_*``, or legacy
        ``guardrail.model``/``guardrail.api_key_env`` directly.
        """
        out = replace(self.llm)
        override: LLMConfig
        if path == "":
            override = LLMConfig()
        elif path == "scanners.mcp":
            override = self.scanners.mcp_scanner.llm
        elif path == "scanners.skill":
            override = self.scanners.skill_scanner.llm
        elif path == "scanners.plugin":
            override = self.scanners.plugin_llm
        elif path == "guardrail":
            override = self.guardrail.llm
        elif path == "guardrail.judge":
            override = self.guardrail.judge.llm
        else:
            _log.warning("config: resolve_llm called with unknown path %r", path)
            override = LLMConfig()

        if override.model:
            out.model = override.model
        if override.provider:
            out.provider = override.provider
        if override.api_key:
            out.api_key = override.api_key
        if override.api_key_env:
            out.api_key_env = override.api_key_env
        if override.base_url:
            out.base_url = override.base_url
        if override.timeout > 0:
            out.timeout = override.timeout
        if override.max_retries > 0:
            out.max_retries = override.max_retries
        if override.region:
            out.region = override.region
        if override.instance_name:
            out.instance_name = override.instance_name
        if override.bedrock is not None:
            out.bedrock = override.bedrock
        if override.vertex is not None:
            out.vertex = override.vertex
        if override.azure is not None:
            out.azure = override.azure
        if override.tls is not None:
            out.tls = override.tls

        if not out.model:
            env_model = os.environ.get(DEFENSECLAW_LLM_MODEL_ENV, "").strip()
            if env_model:
                out.model = env_model

        # Pre-v5 fallbacks (migration residue).
        if not out.model and self.default_llm_model:
            out.model = self.default_llm_model
        if not out.api_key_env and self.default_llm_api_key_env:
            out.api_key_env = self.default_llm_api_key_env

        # If the resolved config references a named custom-provider
        # instance, layer the overlay's defaults UNDER what the role
        # already set. Operator-level overrides on the role always
        # win — instance overlays only fill in blanks. Imported lazily
        # so the loader stays cheap when no custom providers are in
        # play (the common case).
        if out.instance_name:
            try:
                _apply_instance_overlay(out, self.data_dir)
            except Exception:  # pragma: no cover - defensive
                # Overlay merge must never take config loading offline.
                _log.warning(
                    "config: failed to apply custom-provider overlay for %r",
                    out.instance_name,
                )

        _maybe_warn_unknown_provider(out.provider_prefix(), path)
        return out

    def resolved_default_llm_api_key(self) -> str:
        """DEPRECATED. Use ``Config.resolve_llm(path).resolved_api_key()``.

        Retained for back-compat with pre-v5 callers; delegates to
        :meth:`resolve_llm` so behavior stays in sync.
        """
        return self.resolve_llm("").resolved_api_key()

    def effective_inspect_llm(self) -> InspectLLMConfig:
        """DEPRECATED. Use ``Config.resolve_llm(path)`` directly.

        Returns an :class:`InspectLLMConfig`-shaped object for legacy
        callers that haven't migrated to :class:`LLMConfig` yet.
        """
        base = self.resolve_llm("")
        llm = replace(self.inspect_llm)
        if not llm.model:
            llm.model = base.model
        if not llm.provider:
            llm.provider = base.provider
        if not llm.api_key:
            llm.api_key = base.api_key
        if not llm.api_key_env:
            llm.api_key_env = base.api_key_env
        if not llm.base_url:
            llm.base_url = base.base_url
        if llm.timeout == 0 or llm.timeout == 30:
            llm.timeout = base.effective_timeout()
        if llm.max_retries == 0 or llm.max_retries == 3:
            llm.max_retries = base.effective_max_retries()
        return llm

    def save(self) -> None:
        """Persist this :class:`Config` to ``~/.defenseclaw/config.yaml``.

        Round-trips through the existing file so that YAML keys the
        Python dataclass does NOT model survive the save. The two known
        callers that depend on this contract today are:

        * ``audit_sinks:`` — written by ``defenseclaw setup splunk``
          (see ``cli/defenseclaw/observability/writer.py``). Operators
          configure local-Splunk HEC, remote Splunk Enterprise, OTLP
          logs, and webhook forwarding here.
        * ``otel.resource.attributes:`` — stamped by the same writer
          to attribute exporters back to the preset that configured
          them.

        Before this round-trip, every connector-setup call site that
        invoked ``cfg.save()`` (``setup codex``, ``setup claude-code``,
        ``execute_guardrail_setup``, etc.) would silently strip those
        blocks because ``dataclasses.asdict(self)`` only emits the
        fields the dataclass declares — turning Splunk dashboards dark
        without any warning. The two workaround "no cfg.save() here"
        comments in ``cmd_setup.py`` documented this foot-gun; this
        method removes the need for them.

        Modeled keys still win — including the v4-migration strip of
        the legacy ``splunk:`` top-level key and the byte-stability
        strips of empty ``notifications``/``privacy``/``asset_policy``
        blocks — so that operators who programmatically reset a value
        through the dataclass still see the file updated.

        Write is atomic via ``tmp + os.replace`` (matches the
        observability writer pattern) so a crash mid-write cannot
        leave a half-written ``config.yaml`` that the Go gateway
        refuses to reload.
        """
        path = str(config_path_for_data_dir(self.data_dir))
        dataclass_data = _config_to_dict(self)
        owned_keys = _owned_top_level_keys(self)
        with locked_config_yaml(path):
            existing = _load_existing_config_yaml(path)
            merged = _merge_preserving_unmodeled(
                existing,
                dataclass_data,
                owned_keys,
                authoritative_base=self._loaded_authoritative_dicts,
                owned_base=self._loaded_owned_nested_values,
            )
            write_config_yaml_secure(path, merged)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@contextmanager
def locked_config_yaml(path: str):
    """Hold an exclusive per-config lock for a read/merge/write cycle."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    lock_path = path + ".lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(lock_path, flags, 0o600)
    try:
        # "r+" (not "a+"): the lock file is a pure sentinel we never write to,
        # and append mode would force the file pointer to EOF, breaking the
        # offset-0 byte-range lock used on Windows (see _lock_file_exclusive).
        lock = os.fdopen(fd, "r+")
    except BaseException:
        os.close(fd)
        raise
    try:
        _lock_file_exclusive(lock)
        try:
            yield
        finally:
            _unlock_file(lock)
    finally:
        lock.close()


def write_config_yaml_secure(path: str, data: dict[str, Any]) -> None:
    """Atomically write YAML without widening config.yaml permissions."""
    _assert_config_write_allowed(path, data)
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    existing_mode: int | None = None
    try:
        existing_mode = stat.S_IMODE(os.stat(path).st_mode)
    except FileNotFoundError:
        pass
    except OSError:
        existing_mode = None

    fd, tmp = tempfile.mkstemp(
        prefix=f".{os.path.basename(path)}.",
        suffix=".tmp",
        dir=directory,
    )
    descriptor_chmod = getattr(os, "fchmod", None)
    if descriptor_chmod is not None:
        descriptor_chmod(fd, 0o600)
    else:
        os.chmod(tmp, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

    if existing_mode is not None and existing_mode != 0o600:
        target_mode = existing_mode & 0o600
        if target_mode == 0o600 and existing_mode & 0o077 == 0o040:
            target_mode = 0o640
        elif target_mode == 0:
            target_mode = 0o600
        try:
            os.chmod(tmp, target_mode)
        except OSError as exc:
            _log.warning(
                "config.save: cannot mirror %o mode onto %s (%s); writing as 0600",
                existing_mode,
                tmp,
                exc,
            )
    os.replace(tmp, path)
    try:
        dir_fd = os.open(os.path.dirname(path) or ".", os.O_RDONLY)
    except OSError:
        return
    try:
        try:
            os.fsync(dir_fd)
        except OSError as exc:
            _log.warning("config.save: directory fsync failed after atomic replace of %s: %s", path, exc)
    finally:
        os.close(dir_fd)


def _llm_is_empty(d: dict[str, Any] | None) -> bool:
    if not d:
        return True
    return not any(
        (
            d.get("model"),
            d.get("provider"),
            d.get("api_key"),
            d.get("api_key_env"),
            d.get("base_url"),
            d.get("timeout", 0),
            d.get("max_retries", 0),
            d.get("region"),
            d.get("instance_name"),
            d.get("bedrock"),
            d.get("vertex"),
            d.get("azure"),
            d.get("tls"),
        )
    )


def _strip_empty_llm(parent: dict[str, Any] | None, key: str = "llm") -> None:
    """Drop an empty ``llm:`` sub-block so YAML stays minimal. Mirrors
    Go's ``yaml:"llm,omitempty"`` for nested LLMConfig structs.

    Also prunes provider-typed sub-blocks (``bedrock`` / ``vertex`` /
    ``azure`` / ``tls``) that carry only default/empty values so a
    freshly initialised but unused regional config does not bloat the
    YAML.
    """
    if not parent:
        return
    llm = parent.get(key)
    if isinstance(llm, dict):
        # First sweep: drop sub-blocks that are None or all-default.
        if llm.get("bedrock") is None or _is_default_bedrock(llm.get("bedrock")):
            llm.pop("bedrock", None)
        if llm.get("vertex") is None or _is_default_vertex(llm.get("vertex")):
            llm.pop("vertex", None)
        if llm.get("azure") is None or _is_default_azure(llm.get("azure")):
            llm.pop("azure", None)
        if llm.get("tls") is None or _is_default_tls(llm.get("tls")):
            llm.pop("tls", None)
    if _llm_is_empty(llm):
        parent.pop(key, None)


def _is_default_bedrock(d: Any) -> bool:
    if not isinstance(d, dict):
        return True
    if d.get("auth_mode", "api_key") != "api_key":
        return False
    for field_name in (
        "region",
        "access_key_env",
        "secret_key_env",
        "session_token_env",
        "profile_name",
        "inference_profile",
    ):
        if d.get(field_name):
            return False
    aliases = d.get("deployment_aliases") or {}
    if isinstance(aliases, dict) and aliases:
        return False
    return True


def _is_default_vertex(d: Any) -> bool:
    if not isinstance(d, dict):
        return True
    if d.get("auth_mode", "service_account") != "service_account":
        return False
    if (d.get("service_account_json_env") or "GOOGLE_APPLICATION_CREDENTIALS") != "GOOGLE_APPLICATION_CREDENTIALS":
        return False
    for field_name in ("project_id", "region"):
        if d.get(field_name):
            return False
    return True


def _is_default_azure(d: Any) -> bool:
    if not isinstance(d, dict):
        return True
    if d.get("auth_mode", "api_key") != "api_key":
        return False
    if (d.get("api_version") or "2024-10-21") != "2024-10-21":
        return False
    if d.get("endpoint"):
        return False
    aliases = d.get("deployment_aliases") or {}
    if isinstance(aliases, dict) and aliases:
        return False
    return True


def _is_default_tls(d: Any) -> bool:
    if not isinstance(d, dict):
        return True
    return not d.get("ca_cert_pem") and not d.get("insecure_skip_verify")


def _config_to_dict(cfg: Config) -> dict[str, Any]:
    """Serialize Config to a dict suitable for YAML."""
    from dataclasses import asdict

    d = asdict(cfg)
    d.pop("_loaded_authoritative_dicts", None)
    d.pop("_loaded_owned_nested_values", None)
    otel = d.get("otel") or {}
    destinations = otel.get("destinations") or []
    for destination in destinations:
        if not isinstance(destination, dict):
            continue
        span_filter = destination.get("span_filter")
        if not isinstance(span_filter, dict):
            continue
        if span_filter.get("operations"):
            span_filter.pop("require_operation", None)
            span_filter.pop("require_attributes", None)
        else:
            span_filter.pop("operations", None)
            if not span_filter.get("require_operation"):
                span_filter.pop("require_operation", None)
            if not span_filter.get("require_attributes"):
                span_filter.pop("require_attributes", None)
        if not span_filter:
            destination.pop("span_filter", None)
    # Named destinations are the only transport/signal source of truth.
    # Serialize only process-wide policy outside destinations.
    traces = otel.get("traces") or {}
    otel["traces"] = {key: value for key, value in traces.items() if key in {"sampler", "sampler_arg"}}
    logs = otel.get("logs") or {}
    otel["logs"] = {key: value for key, value in logs.items() if key == "emit_individual_findings"}
    metrics = otel.get("metrics") or {}
    otel["metrics"] = {key: value for key, value in metrics.items() if key in {"export_interval_s", "temporality"}}
    gw = d.get("gateway")
    if gw and not gw.get("token"):
        gw.pop("token", None)
    if gw:
        config_reload = gw.get("config_reload")
        if isinstance(config_reload, dict):
            mode = _normalize_gateway_config_reload_mode(config_reload.get("mode"))
            if mode == "hot":
                gw.pop("config_reload", None)
            else:
                config_reload["mode"] = mode
    _strip_empty_llm(d, "llm")
    scanners = d.get("scanners") or {}
    _strip_empty_llm(scanners.get("skill_scanner"), "llm")
    _strip_empty_llm(scanners.get("mcp_scanner"), "llm")
    _strip_empty_llm(scanners, "plugin_llm")
    guardrail = d.get("guardrail") or {}
    _strip_empty_llm(guardrail, "llm")
    _strip_empty_llm(guardrail.get("judge"), "llm")
    # Mirror Go's ``yaml:",omitempty"`` on the hook-lane judge keys so a
    # config that never opted into the hook-lane judge stays
    # byte-identical after a load/save round-trip.
    judge = guardrail.get("judge")
    if isinstance(judge, dict):
        if not judge.get("hook_connectors"):
            judge.pop("hook_connectors", None)
        if not judge.get("hook_timeout"):
            judge.pop("hook_timeout", None)
    # Mirror Go's ``yaml:"connectors,omitempty"`` — drop the empty
    # per-connector overrides map so existing single-connector configs
    # stay byte-identical after a load/save round-trip. The block
    # reappears the moment an operator adds a connector override (e.g.
    # ``setup migrate-connectors``).
    #
    # Exception: if the map WAS populated at load and the caller has now
    # cleared it (e.g. ``setup remove`` collapsing the final
    # multi-connector entry back to the legacy singular shape), we must
    # emit an explicit empty ``connectors: {}`` so the authoritative
    # atomic-replace in ``_deep_merge_nested`` clears the on-disk block.
    # Popping the key here would instead let the parent (non-authoritative)
    # guardrail merge rescue the stale connectors from disk, so the
    # removal would silently fail to persist.
    if isinstance(guardrail, dict) and not guardrail.get("connectors"):
        had_connectors = bool((getattr(cfg, "_loaded_authoritative_dicts", None) or {}).get("guardrail.connectors"))
        if had_connectors:
            guardrail["connectors"] = {}
        else:
            guardrail.pop("connectors", None)
    else:
        # Mirror Go's ``yaml:"enabled,omitempty"`` on the *bool: an unset
        # (None) per-connector enabled flag must not serialize as
        # ``enabled: null``. Drop it so a connector that was never
        # explicitly disabled stays byte-identical; an explicit
        # True/False round-trips verbatim.
        conns = guardrail.get("connectors")
        if isinstance(conns, dict):
            for entry in conns.values():
                if isinstance(entry, dict) and entry.get("enabled") is None:
                    entry.pop("enabled", None)
    # v4: the legacy top-level `splunk:` block is rejected by the Go
    # gateway at startup (see internal/config/config.go::detectLegacySplunk).
    # The Python dataclass retains a SplunkConfig for backwards-compatible
    # reads, but we must never *write* the key to disk — even with
    # default values — or the sidecar will refuse to start with a v4
    # migration error. Splunk forwarding lives under audit_sinks now.
    d.pop("splunk", None)
    # Mirror the Go `yaml:"cooldown_seconds,omitempty"` tag: when the
    # operator hasn't set a cooldown (tri-state None), drop the key so
    # the YAML stays minimal and the gateway falls back to
    # ``webhookDefaultCooldown``. An explicit ``0`` or positive int is
    # kept verbatim.
    for wh in d.get("webhooks") or []:
        _strip_webhook_omitempty(wh)
    # Mirror Go's ``yaml:"privacy,omitempty"`` — drop the block
    # entirely when it carries only defaults so existing configs
    # without a ``privacy:`` block stay byte-identical after a
    # load/save round-trip. The block reappears the moment any
    # field flips off-default (e.g. ``disable_redaction: true``).
    privacy = d.get("privacy")
    if isinstance(privacy, dict) and not any(privacy.values()):
        d.pop("privacy", None)
    if d.get("ai_discovery") == _disabled_ai_discovery_dict():
        d.pop("ai_discovery", None)
    if d.get("application_protection") == _default_application_protection_dict():
        d.pop("application_protection", None)
    else:
        _serialize_application_protection(cfg, d.get("application_protection"))
    # Mirror Go's ``yaml:"notifications,omitempty"`` — when the
    # block is at full defaults (master switch off, every category /
    # source still on, default throttles) drop it so legacy configs
    # that never opted in stay byte-identical after a load/save
    # round-trip. The block reappears the moment any field is
    # touched (e.g. ``setup notifications`` flipping ``enabled:
    # true``).
    notifications = d.get("notifications")
    if isinstance(notifications, dict) and notifications == _default_notifications_dict():
        d.pop("notifications", None)
    if d.get("asset_policy") == _default_asset_policy_dict():
        d.pop("asset_policy", None)
    else:
        _serialize_asset_policy_connectors(cfg, d.get("asset_policy"))
    # Per-connector observability (D5b): drop the empty block (omitempty),
    # or serialize it with inherited (None) dimensions + webhook omitempty
    # stripped. Mirrors the asset_policy.connectors handling.
    _serialize_observability(cfg, d.get("observability"), d)
    # Drop the registries: block when no sources are configured so an
    # operator-untouched config stays byte-identical after a load/save
    # round-trip. The block reappears the moment any source is added.
    registries = d.get("registries")
    if isinstance(registries, dict):
        sources = registries.get("sources") or []
        if not sources:
            d.pop("registries", None)
    return d


def _owned_top_level_keys(cfg: Config) -> frozenset[str]:
    """Return the set of TOP-LEVEL YAML keys the dataclass declares.

    Used by :meth:`Config.save` to distinguish "dataclass intentionally
    omitted this key" (e.g. ``notifications:`` was at full defaults so
    ``_config_to_dict`` stripped it) from "the dataclass doesn't model
    this key at all" (e.g. ``audit_sinks:``, written by
    :mod:`defenseclaw.observability.writer`). The first case should drop
    the key from the on-disk file; the second case should preserve it.

    Implementation note: we read the field names off ``Config`` itself
    via ``dataclasses.fields`` rather than calling ``asdict(cfg)`` so
    this stays O(fields) instead of O(full config tree) and so it is
    safe to call from inside ``save()`` without triggering side effects
    on lazily-populated nested dataclasses.
    """
    from dataclasses import fields

    return frozenset(f.name for f in fields(cfg) if not f.name.startswith("_"))


def _load_existing_config_yaml(path: str) -> dict[str, Any]:
    """Best-effort read of an existing ``config.yaml`` for round-trip save.

    Returns ``{}`` when the file is missing (first save), unreadable, or
    malformed. On parse failure we log a warning but do NOT raise — the
    operator's previous file may be partially corrupt and we still want
    ``cfg.save()`` to succeed so the next setup wizard can rewrite it
    cleanly. Worst-case the on-disk file is replaced with the
    dataclass-only view, which is exactly the pre-fix behaviour, so we
    cannot regress relative to the old serializer.
    """
    try:
        with open(path) as f:
            raw = yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}
    except OSError as exc:
        _log.warning(
            "config.save: cannot read existing %s (%s); writing dataclass-only view (any unmodelled keys will be lost)",
            path,
            exc,
        )
        return {}
    except yaml.YAMLError as exc:
        backup = _backup_unparseable_config(path)
        _log.warning(
            "config.save: existing %s failed to parse (%s); writing dataclass-only view (backup=%s)",
            path,
            exc,
            backup or "unavailable",
        )
        return {}
    if not isinstance(raw, dict):
        _log.warning(
            "config.save: existing %s is not a YAML mapping (got %s); writing dataclass-only view",
            path,
            type(raw).__name__,
        )
        return {}
    return raw


def _backup_unparseable_config(path: str) -> str:
    try:
        with open(path, "rb") as src:
            data = src.read()
    except OSError:
        return ""
    backup = f"{path}.bak"
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(backup, flags, 0o600)
    except FileExistsError:
        backup = f"{path}.bak.{os.getpid()}"
        try:
            fd = os.open(backup, flags, 0o600)
        except OSError:
            return ""
    except OSError:
        return ""
    try:
        with os.fdopen(fd, "wb") as dst:
            dst.write(data)
            dst.flush()
            os.fsync(dst.fileno())
    except OSError:
        return ""
    return backup


# Dotted YAML paths whose VALUE is a dict[str, str]-style modeled
# collection — i.e. the dataclass is the SINGLE SOURCE OF TRUTH for
# the contents of the dict. When the caller clears one of these
# (sets it to ``{}``), the on-disk file MUST be cleared too;
# preserving the previous keys would leak stale secrets across rotations.
#
# The list is intentionally explicit (not auto-derived from
# dataclass introspection) because not every nested dataclass field
# typed as ``dict[str, str]`` is dataclass-authoritative — some
# carry user-supplied free-form keys we want to preserve. Any new
# secret-bearing modeled dict added to ``OTelConfig`` (or
# elsewhere) MUST be added here so a clear-on-save honours the
# operator's intent.
#
# Format: dotted YAML path from the top-level config dict.
_AUTHORITATIVE_MODELED_DICT_PATHS: frozenset[str] = frozenset(
    {
        # OpenTelemetry resource attributes (service.name,
        # deployment.environment, custom operator labels). Some
        # operators use this for tenant identifiers, so leftover keys
        # after a clear leak prior tenant identity into the new
        # session.
        "otel.resource.attributes",
        # Per-connector guardrail overrides map. This is fully modeled by
        # the dataclass (``guardrail.connectors``) and is the single source
        # of truth for the configured connector set. Without atomic replace,
        # the non-authoritative merge rescues keys that exist only on disk —
        # so ``setup remove <connector>`` would delete the key in-memory,
        # save, and then have it resurrected from the prior file on reload
        # (the removal never persists). Marking it authoritative makes a
        # deleted/cleared connector propagate to disk, which is the whole
        # point of the removal.
        "guardrail.connectors",
        # Per-connector asset_policy overrides map (OTHER-7). Same rationale as
        # guardrail.connectors: the dataclass is the single source of truth for
        # the configured per-connector set, so clearing an override in-memory and
        # saving must propagate to disk rather than being rescued by the
        # non-authoritative merge from the prior file.
        "asset_policy.connectors",
        # Per-connector automatic application-protection overrides map. Same
        # authoritative-merge rationale as guardrail.connectors: the dataclass is
        # the modeled source of truth, so cleared connector overrides must not be
        # resurrected from the prior file.
        "application_protection.connectors",
        # Per-connector observability overrides map (D5b). Same rationale: the
        # dataclass is the single source of truth for the configured per-connector
        # routing set, so clearing a connector's sinks/webhooks override in-memory
        # and saving must propagate to disk rather than being rescued by the
        # non-authoritative merge from the prior file.
        "observability.connectors",
    }
)

# Nested NON-dict keys the dataclass owns and may intentionally omit.
#
# ``_config_to_dict`` strips these when they hold their zero value
# (omitempty parity with the Go side, so configs that never opted in
# stay byte-identical across load/save). At the TOP level the merge
# already handles this ("dataclass owns the key and chose to omit it →
# drop"), but the nested merge preserves unknown keys by default — so
# without this list, clearing an opted-in value pops the key from the
# new dict and the merge resurrects the stale on-disk value forever
# (observed live: ``guardrail judge remove all`` reported success while
# ``hook_connectors: ['*']`` survived every save). These are list /
# scalar keys, so the dict-shaped
# ``_AUTHORITATIVE_MODELED_DICT_PATHS`` mechanism above cannot cover
# them.
#
# Format: dotted YAML path of the KEY (not the containing dict).
_OWNED_NESTED_KEYS: frozenset[str] = frozenset(
    {
        # Hook-lane judge gate: empty list = lane off, stripped on save.
        "guardrail.judge.hook_connectors",
        # Hook-lane judge timeout: 0 = gateway default, stripped on save.
        "guardrail.judge.hook_timeout",
    }
)


def _merge_preserving_unmodeled(
    existing: dict[str, Any],
    new: dict[str, Any],
    owned_top_level: frozenset[str],
    authoritative_base: dict[str, dict[str, Any]] | None = None,
    owned_base: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Deep-merge ``new`` over ``existing`` while preserving unmodelled keys.

    Top-level rules (the layer where ``audit_sinks:`` lives):

    * Key in ``new``: dataclass wins (with a recursive deep-merge when
      both sides are dicts so nested unmodelled keys like operator
      additions survive).
    * Key only in ``existing``:
        - If the key IS owned by the dataclass (``owned_top_level``) →
          the dataclass intentionally chose to omit it (e.g.
          ``_config_to_dict`` stripped ``notifications:`` because it
          was at full defaults, or stripped the legacy ``splunk:``
          v4-migration block). Drop it.
        - Otherwise → unmodelled extension key (``audit_sinks:``,
          operator-added comments-as-keys, future Go-side additions).
          Preserve it unchanged.
    * Key only in ``new`` → emit it.

    Nested rules (any depth below top level):

    * Both dicts → recurse via :func:`_deep_merge_nested`. The
      recursion preserves unmodelled subkeys by default (so an
      operator-added ``otel.custom_extension.foo`` survives a save
      that doesn't touch it) BUT atomically replaces dicts whose
      dotted path appears in
      :data:`_AUTHORITATIVE_MODELED_DICT_PATHS`. The latter
      includes ``otel.resource.attributes``. A caller that clears a
      modeled collection gets the on-disk block cleared, which is the
      whole point of clearing it.
    * Lists → atomic replacement (the dataclass list is authoritative;
      partial list merges would mis-handle operator deletions of list
      elements modelled by the dataclass).
    * Scalars / type mismatch → new wins.
    """
    out: dict[str, Any] = {}
    # Pass 1: walk existing keys so file order is preserved when the
    # dataclass output omits a key. yaml.safe_dump with sort_keys=False
    # honours dict iteration order on CPython 3.7+, which keeps
    # operator-edited files visually stable across saves.
    for k, ev in existing.items():
        if k in new:
            nv = new[k]
            if isinstance(ev, dict) and isinstance(nv, dict):
                out[k] = _deep_merge_nested(
                    ev,
                    nv,
                    path=k,
                    authoritative_base=authoritative_base,
                    owned_base=owned_base,
                )
            else:
                out[k] = nv
        elif k in owned_top_level:
            # Dataclass owns this key and chose to omit it (default-strip
            # or legacy-drop). Honour that decision.
            continue
        else:
            # Unmodelled key — rescue it from the file. This is the
            # whole point of the round-trip save.
            out[k] = ev
    # Pass 2: append keys present only in the dataclass output.
    for k, nv in new.items():
        if k not in existing:
            out[k] = nv
    return out


def _deep_merge_nested(
    existing: dict[str, Any],
    new: dict[str, Any],
    path: str = "",
    authoritative_base: dict[str, dict[str, Any]] | None = None,
    owned_base: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Recursive deep-merge for nested dicts.

    Behaviour:

    * If the dotted path of the recursing dict is in
      :data:`_AUTHORITATIVE_MODELED_DICT_PATHS` (e.g.
      ``otel.resource.attributes``), the dataclass dict is the
      single source of truth. ``new`` wins atomically — no per-key
      rescue from ``existing``. Setting the modeled map to ``{}``
      therefore CLEARS the on-disk block, which is what callers
      expect when they change tenant identifiers.

    * Otherwise, keys only in ``existing`` are preserved (the
      operator-added free-form rescue path) and keys in ``new``
      win on overlap.
    """
    if path in _AUTHORITATIVE_MODELED_DICT_PATHS:
        base = (authoritative_base or {}).get(path)
        if base is not None and dict(new) == dict(base) and dict(existing) != dict(base):
            return dict(existing)
        # Atomic replace: dataclass dict wins. We deliberately keep
        # the path in the recursion signature so future authoritative
        # paths nested deeper still match without a separate flag.
        return dict(new)
    out: dict[str, Any] = {}
    for k, ev in existing.items():
        child = f"{path}.{k}" if path else k
        if k in new:
            nv = new[k]
            if isinstance(ev, dict) and isinstance(nv, dict):
                out[k] = _deep_merge_nested(
                    ev,
                    nv,
                    path=child,
                    authoritative_base=authoritative_base,
                    owned_base=owned_base,
                )
            else:
                out[k] = nv
        elif "." not in k and child in _OWNED_NESTED_KEYS:
            # Dataclass owns this nested key and chose to omit it (the
            # omitempty strip in ``_config_to_dict`` removed its zero
            # value). Drop it ONLY when this process actually loaded a
            # value and cleared it — that is what makes `guardrail judge
            # remove` persist. When the loaded snapshot has no value,
            # this process never owned a change and the on-disk value
            # came from a concurrent writer (e.g. `judge add` in another
            # terminal while a TUI/wizard session was open): preserve
            # it, mirroring the stale-writer rescue the authoritative
            # dict paths get via ``authoritative_base``. The `"." not in
            # k` guard keeps a literal YAML key that merely contains
            # dots (e.g. an unmodeled `judge.hook_connectors` directly
            # under `guardrail:`) from colliding with the dotted path of
            # a modeled key — those stay on the preserve path below.
            if (owned_base or {}).get(child):
                continue
            out[k] = ev
        else:
            out[k] = ev
    for k, nv in new.items():
        if k not in existing:
            out[k] = nv
    return out


def _default_notifications_dict() -> dict[str, Any]:
    from dataclasses import asdict

    return asdict(NotificationsConfig())


def _default_asset_policy_dict() -> dict[str, Any]:
    from dataclasses import asdict

    return asdict(AssetPolicyConfig())


def _serialize_asset_policy_connectors(cfg: Config, asset_policy: Any) -> None:
    """In-place YAML cleanup for ``asset_policy.connectors`` (OTHER-7).

    Mirrors Go's ``yaml:",omitempty"`` tags and the ``guardrail.connectors``
    serialization handling:

    * Empty map + never loaded with connectors → drop the key so a
      global-only config stays byte-identical after a load/save round-trip.
    * Empty map + WAS loaded with connectors → emit an explicit
      ``connectors: {}`` so the authoritative atomic-replace in
      :func:`_deep_merge_nested` clears the on-disk block (the map is in
      :data:`_AUTHORITATIVE_MODELED_DICT_PATHS`).
    * Non-empty map → drop ``None`` per-type blocks, an unset (``None``)
      ``registry_required``, and empty-string scalars so a populated map
      round-trips without ``mcp: null`` / ``registry_required: null`` noise.

    This runs only on a non-default ``asset_policy`` block (the all-default
    strip already removed the default case, which still carries the
    ``connectors: {}`` key needed for that equality check).
    """
    if not isinstance(asset_policy, dict):
        return
    connectors = asset_policy.get("connectors")
    if not connectors:
        had_connectors = bool((getattr(cfg, "_loaded_authoritative_dicts", None) or {}).get("asset_policy.connectors"))
        if had_connectors:
            asset_policy["connectors"] = {}
        else:
            asset_policy.pop("connectors", None)
        return
    if not isinstance(connectors, dict):
        asset_policy.pop("connectors", None)
        return
    for entry in connectors.values():
        if not isinstance(entry, dict):
            continue
        if not entry.get("mode"):
            entry.pop("mode", None)
        for ttype in ("mcp", "skill", "plugin"):
            block = entry.get(ttype)
            if block is None:
                entry.pop(ttype, None)
                continue
            if isinstance(block, dict):
                if not block.get("default"):
                    block.pop("default", None)
                if block.get("registry_required") is None:
                    block.pop("registry_required", None)
                if not block.get("registry_empty_action"):
                    block.pop("registry_empty_action", None)


def _strip_webhook_omitempty(wh: Any) -> None:
    """Drop omitempty webhook keys in place (cooldown_seconds None, name "").

    Mirrors Go's ``yaml:"cooldown_seconds,omitempty"`` / ``yaml:"name,omitempty"``
    so a webhook that never set those stays byte-identical after a load/save
    cycle. Shared by the top-level ``webhooks:`` serialization and the
    per-connector ``observability.connectors[*].webhooks`` serialization.
    """
    if not isinstance(wh, dict):
        return
    # Tri-state cooldown_seconds: None means "use the Go dispatcher default";
    # drop the key so the YAML stays minimal. An explicit 0 / positive int is
    # kept verbatim.
    if wh.get("cooldown_seconds", None) is None:
        wh.pop("cooldown_seconds", None)
    if wh.get("name", "") == "":
        wh.pop("name", None)


def _serialize_observability(cfg: Config, observability: Any, d: dict[str, Any]) -> None:
    """In-place YAML cleanup for the ``observability:`` block (D5b).

    Mirrors the ``asset_policy.connectors`` serialization handling:

    * Empty/absent connectors + never loaded with connectors → drop the
      whole ``observability:`` key so a global-only config stays
      byte-identical after a load/save round-trip.
    * Empty connectors + WAS loaded with connectors → emit an explicit
      ``observability: {connectors: {}}`` so the authoritative atomic-replace
      in :func:`_deep_merge_nested` clears the on-disk block (the map is in
      :data:`_AUTHORITATIVE_MODELED_DICT_PATHS`).
    * Non-empty connectors → drop the ``None`` (inherit-global) dimensions and
      strip webhook omitempty keys so a populated map round-trips without
      ``audit_sinks: null`` / ``webhooks: null`` noise.
    """
    if not isinstance(observability, dict):
        d.pop("observability", None)
        return
    connectors = observability.get("connectors")
    if not connectors:
        had_connectors = bool((getattr(cfg, "_loaded_authoritative_dicts", None) or {}).get("observability.connectors"))
        if had_connectors:
            d["observability"] = {"connectors": {}}
        else:
            d.pop("observability", None)
        return
    if not isinstance(connectors, dict):
        d.pop("observability", None)
        return
    for entry in connectors.values():
        if not isinstance(entry, dict):
            continue
        # None dimension = "inherit global"; drop the key (a present list,
        # including [], is an explicit override and is kept).
        if entry.get("audit_sinks") is None:
            entry.pop("audit_sinks", None)
        webhooks = entry.get("webhooks")
        if webhooks is None:
            entry.pop("webhooks", None)
        elif isinstance(webhooks, list):
            for wh in webhooks:
                _strip_webhook_omitempty(wh)


def _disabled_ai_discovery_dict() -> dict[str, Any]:
    from dataclasses import asdict

    return asdict(AIDiscoveryConfig(enabled=False))


def _default_application_protection_dict() -> dict[str, Any]:
    from dataclasses import asdict

    return asdict(ApplicationProtectionConfig())


def _serialize_application_protection(cfg: Config, block: Any) -> None:
    if not isinstance(block, dict):
        return
    guard = block.get("guardrail")
    if isinstance(guard, dict):
        if guard.get("enabled") is None:
            guard.pop("enabled", None)
        if guard.get("hilt") is None:
            guard.pop("hilt", None)
        if guard == {"mode": "observe"}:
            block.pop("guardrail", None)
        elif not any(guard.values()):
            block.pop("guardrail", None)
    asset = block.get("asset_policy")
    if isinstance(asset, dict):
        if asset == {"mode": "observe"}:
            block.pop("asset_policy", None)
        elif not any(asset.values()):
            block.pop("asset_policy", None)
    conns = block.get("connectors")
    if not conns:
        had_connectors = bool(
            (getattr(cfg, "_loaded_authoritative_dicts", None) or {}).get("application_protection.connectors")
        )
        if had_connectors:
            block["connectors"] = {}
        else:
            block.pop("connectors", None)
        return
    if isinstance(conns, dict):
        for entry in conns.values():
            if not isinstance(entry, dict):
                continue
            if entry.get("enabled") is None:
                entry.pop("enabled", None)
            if entry.get("min_confidence") is None:
                entry.pop("min_confidence", None)
            guard = entry.get("guardrail")
            if isinstance(guard, dict):
                if guard.get("enabled") is None:
                    guard.pop("enabled", None)
                if guard.get("hilt") is None:
                    guard.pop("hilt", None)
                if not any(guard.values()):
                    entry.pop("guardrail", None)
            asset = entry.get("asset_policy")
            if isinstance(asset, dict) and not any(asset.values()):
                entry.pop("asset_policy", None)


def _merge_severity_action(raw: dict[str, Any] | None) -> SeverityAction:
    if not raw:
        return SeverityAction()
    return SeverityAction(
        file=raw.get("file", "none"),
        runtime=raw.get("runtime", "enable"),
        install=raw.get("install", "none"),
    )


def _merge_skill_actions(raw: dict[str, Any] | None) -> SkillActionsConfig:
    defaults = SkillActionsConfig()
    if not raw:
        return defaults
    return SkillActionsConfig(
        critical=_merge_severity_action(raw.get("critical")) if "critical" in raw else defaults.critical,
        high=_merge_severity_action(raw.get("high")) if "high" in raw else defaults.high,
        medium=_merge_severity_action(raw.get("medium")) if "medium" in raw else defaults.medium,
        low=_merge_severity_action(raw.get("low")) if "low" in raw else defaults.low,
        info=_merge_severity_action(raw.get("info")) if "info" in raw else defaults.info,
    )


def _merge_mcp_actions(raw: dict[str, Any] | None) -> MCPActionsConfig:
    defaults = MCPActionsConfig()
    if not raw:
        return defaults
    return MCPActionsConfig(
        critical=_merge_severity_action(raw.get("critical")) if "critical" in raw else defaults.critical,
        high=_merge_severity_action(raw.get("high")) if "high" in raw else defaults.high,
        medium=_merge_severity_action(raw.get("medium")) if "medium" in raw else defaults.medium,
        low=_merge_severity_action(raw.get("low")) if "low" in raw else defaults.low,
        info=_merge_severity_action(raw.get("info")) if "info" in raw else defaults.info,
    )


def _merge_inspect_llm(raw: dict[str, Any] | None) -> InspectLLMConfig:
    if not raw:
        return InspectLLMConfig()
    return InspectLLMConfig(
        provider=raw.get("provider", ""),
        model=raw.get("model", ""),
        api_key=raw.get("api_key", ""),
        api_key_env=raw.get("api_key_env", ""),
        base_url=raw.get("base_url", ""),
        timeout=raw.get("timeout", 30),
        max_retries=raw.get("max_retries", 3),
    )


def _merge_bedrock(raw: Any) -> BedrockKeyConfig | None:
    if not isinstance(raw, dict):
        return None
    aliases_raw = raw.get("deployment_aliases", {})
    aliases: dict[str, str] = {}
    if isinstance(aliases_raw, dict):
        for k, v in aliases_raw.items():
            if k and v:
                aliases[str(k)] = str(v)
    return BedrockKeyConfig(
        region=str(raw.get("region", "") or ""),
        auth_mode=str(raw.get("auth_mode", "api_key") or "api_key").strip().lower(),
        access_key_env=str(raw.get("access_key_env", "") or ""),
        secret_key_env=str(raw.get("secret_key_env", "") or ""),
        session_token_env=str(raw.get("session_token_env", "") or ""),
        profile_name=str(raw.get("profile_name", "") or ""),
        inference_profile=str(raw.get("inference_profile", "") or ""),
        deployment_aliases=aliases,
    )


def _merge_vertex(raw: Any) -> VertexKeyConfig | None:
    if not isinstance(raw, dict):
        return None
    return VertexKeyConfig(
        project_id=str(raw.get("project_id", "") or ""),
        region=str(raw.get("region", "") or ""),
        auth_mode=str(raw.get("auth_mode", "service_account") or "service_account"),
        service_account_json_env=str(
            raw.get("service_account_json_env", "GOOGLE_APPLICATION_CREDENTIALS") or "GOOGLE_APPLICATION_CREDENTIALS"
        ),
    )


def _merge_azure(raw: Any) -> AzureKeyConfig | None:
    if not isinstance(raw, dict):
        return None
    aliases_raw = raw.get("deployment_aliases", {})
    aliases: dict[str, str] = {}
    if isinstance(aliases_raw, dict):
        for k, v in aliases_raw.items():
            if k and v:
                aliases[str(k)] = str(v)
    return AzureKeyConfig(
        endpoint=str(raw.get("endpoint", "") or ""),
        api_version=str(raw.get("api_version", "2024-10-21") or "2024-10-21"),
        auth_mode=str(raw.get("auth_mode", "api_key") or "api_key"),
        deployment_aliases=aliases,
    )


def _merge_tls(raw: Any) -> LLMTLSConfig | None:
    if not isinstance(raw, dict):
        return None
    ca_cert_pem = str(raw.get("ca_cert_pem", "") or "")
    insecure_skip_verify = _coerce_bool(raw.get("insecure_skip_verify", False))
    # CA pinning and skip-verify are mutually exclusive; prefer the CA when
    # both appear in persisted config (F-0141).
    if ca_cert_pem.strip():
        insecure_skip_verify = False
    return LLMTLSConfig(
        ca_cert_pem=ca_cert_pem,
        insecure_skip_verify=insecure_skip_verify,
    )


def _merge_llm(raw: dict[str, Any] | None) -> LLMConfig:
    """Parse a unified llm: block. Mirrors Go's mapstructure decode.

    Empty / missing blocks return a zero-value LLMConfig; per-component
    overrides inherit from the top level via Config.resolve_llm.
    """
    if not raw:
        return LLMConfig()
    return LLMConfig(
        model=str(raw.get("model", "") or ""),
        provider=str(raw.get("provider", "") or ""),
        api_key=str(raw.get("api_key", "") or ""),
        api_key_env=str(raw.get("api_key_env", "") or ""),
        base_url=str(raw.get("base_url", "") or ""),
        timeout=int(raw.get("timeout", 0) or 0),
        max_retries=int(raw.get("max_retries", 0) or 0),
        region=str(raw.get("region", "") or ""),
        instance_name=str(raw.get("instance_name", "") or ""),
        bedrock=_merge_bedrock(raw.get("bedrock")),
        vertex=_merge_vertex(raw.get("vertex")),
        azure=_merge_azure(raw.get("azure")),
        tls=_merge_tls(raw.get("tls")),
    )


def _migrate_llm_fields(cfg: Config) -> None:
    """v4→v5 migration: copy legacy LLM fields into the unified
    :class:`LLMConfig` slots so :meth:`Config.resolve_llm` returns the
    same answers as the pre-v5 functions.

    Idempotent: already-populated v5 slots are left untouched. The
    legacy fields are NOT cleared in-place — ``defenseclaw setup
    migrate-llm`` is the tool that rewrites the on-disk YAML.

    Emits a one-shot deprecation warning (via the standard ``logging``
    module, which is wired up to stderr + audit pipeline in
    cli/defenseclaw/__init__.py) when legacy LLM fields are detected
    so operators notice the drift before v6 removes the fallbacks.
    The warning is emitted at most once per process for the same legacy
    field set so command-level config reloads don't spam.
    """
    legacy_fields: list[str] = []
    if cfg.inspect_llm.model or cfg.inspect_llm.provider or cfg.inspect_llm.api_key_env:
        legacy_fields.append("inspect_llm")
    if cfg.default_llm_model:
        legacy_fields.append("default_llm_model")
    if cfg.default_llm_api_key_env:
        legacy_fields.append("default_llm_api_key_env")
    if cfg.guardrail.model or cfg.guardrail.api_key_env or cfg.guardrail.api_base:
        legacy_fields.append("guardrail.{model,api_key_env,api_base}")
    if cfg.guardrail.judge.model or cfg.guardrail.judge.api_key_env or cfg.guardrail.judge.api_base:
        legacy_fields.append("guardrail.judge.{model,api_key_env,api_base}")

    legacy_key = tuple(legacy_fields)
    if legacy_key and legacy_key not in _llm_migration_warned_keys:
        _log.warning(
            "config: deprecated v4 LLM fields detected (%s); values are still honored "
            "but will be removed in a future release. Run `defenseclaw setup migrate-llm` "
            "to rewrite config.yaml to the unified llm: block.",
            ", ".join(legacy_fields),
        )
        _llm_migration_warned_keys.add(legacy_key)
    # Top-level.
    if not cfg.llm.api_key_env:
        if cfg.default_llm_api_key_env:
            cfg.llm.api_key_env = cfg.default_llm_api_key_env
        elif cfg.inspect_llm.api_key_env:
            cfg.llm.api_key_env = cfg.inspect_llm.api_key_env
    if not cfg.llm.api_key and cfg.inspect_llm.api_key:
        cfg.llm.api_key = cfg.inspect_llm.api_key
    if not cfg.llm.model:
        if cfg.default_llm_model:
            cfg.llm.model = cfg.default_llm_model
        elif cfg.inspect_llm.model:
            cfg.llm.model = cfg.inspect_llm.model
    if not cfg.llm.provider and cfg.inspect_llm.provider:
        cfg.llm.provider = cfg.inspect_llm.provider
    if not cfg.llm.base_url and cfg.inspect_llm.base_url:
        cfg.llm.base_url = cfg.inspect_llm.base_url
    if cfg.llm.timeout == 0 and cfg.inspect_llm.timeout > 0:
        cfg.llm.timeout = cfg.inspect_llm.timeout
    if cfg.llm.max_retries == 0 and cfg.inspect_llm.max_retries > 0:
        cfg.llm.max_retries = cfg.inspect_llm.max_retries

    # Guardrail upstream.
    if not cfg.guardrail.llm.model and cfg.guardrail.model:
        cfg.guardrail.llm.model = cfg.guardrail.model
    if not cfg.guardrail.llm.api_key_env and cfg.guardrail.api_key_env:
        cfg.guardrail.llm.api_key_env = cfg.guardrail.api_key_env
    if not cfg.guardrail.llm.base_url and cfg.guardrail.api_base:
        cfg.guardrail.llm.base_url = cfg.guardrail.api_base

    # Judge.
    if not cfg.guardrail.judge.llm.model and cfg.guardrail.judge.model:
        cfg.guardrail.judge.llm.model = cfg.guardrail.judge.model
    if not cfg.guardrail.judge.llm.api_key_env and cfg.guardrail.judge.api_key_env:
        cfg.guardrail.judge.llm.api_key_env = cfg.guardrail.judge.api_key_env
    if not cfg.guardrail.judge.llm.base_url and cfg.guardrail.judge.api_base:
        cfg.guardrail.judge.llm.base_url = cfg.guardrail.judge.api_base

    # v5→v6: auto-derive `llm.instance_name` from a legacy `base_url`
    # that matches a custom-providers.json overlay entry. Keeps the
    # overlay as the single source of truth for self-hosted endpoints
    # (so rotating the TLS bundle or base URL in one place is enough).
    _derive_instance_name_from_base_url(cfg)


def _derive_instance_name_from_base_url(cfg: Config) -> None:
    """Set ``llm.instance_name`` for any LLMConfig whose ``base_url``
    matches an entry in ``~/.defenseclaw/custom-providers.json``.

    Idempotent: a config that already pins ``instance_name`` is left
    untouched. The legacy ``base_url`` is cleared on the migrated
    block(s) so the overlay's value (with its TLS settings) is the
    only thing the gateway resolves at runtime.
    """
    data_dir = getattr(cfg, "data_dir", "") or os.path.expanduser("~/.defenseclaw")
    overlay_path = os.path.join(data_dir, "custom-providers.json")
    try:
        with open(overlay_path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except (FileNotFoundError, PermissionError, OSError):
        return
    if not isinstance(raw, dict):
        return
    providers = raw.get("providers") or []
    if not isinstance(providers, list):
        return
    by_url: dict[str, str] = {}
    for p in providers:
        if not isinstance(p, dict):
            continue
        name = str(p.get("name") or "").strip()
        url = str(p.get("base_url") or "").strip()
        if name and url:
            by_url[url.rstrip("/")] = name

    if not by_url:
        return

    def _maybe_apply(llm: LLMConfig) -> None:
        if (llm.instance_name or "").strip():
            return
        url = (llm.base_url or "").strip().rstrip("/")
        if not url:
            return
        match = by_url.get(url)
        if match:
            llm.instance_name = match
            llm.base_url = ""

    _maybe_apply(cfg.llm)
    _maybe_apply(cfg.guardrail.llm)
    _maybe_apply(cfg.guardrail.judge.llm)
    _maybe_apply(cfg.scanners.skill_scanner.llm)
    _maybe_apply(cfg.scanners.mcp_scanner.llm)
    _maybe_apply(cfg.scanners.plugin_llm)


def _merge_plugin_actions(raw: dict[str, Any] | None) -> PluginActionsConfig:
    defaults = PluginActionsConfig()
    if not raw:
        return defaults
    return PluginActionsConfig(
        critical=_merge_severity_action(raw.get("critical")) if "critical" in raw else defaults.critical,
        high=_merge_severity_action(raw.get("high")) if "high" in raw else defaults.high,
        medium=_merge_severity_action(raw.get("medium")) if "medium" in raw else defaults.medium,
        low=_merge_severity_action(raw.get("low")) if "low" in raw else defaults.low,
        info=_merge_severity_action(raw.get("info")) if "info" in raw else defaults.info,
    )


def _merge_asset_policy(raw: dict[str, Any] | None) -> AssetPolicyConfig:
    if not isinstance(raw, dict):
        return AssetPolicyConfig()
    return AssetPolicyConfig(
        enabled=bool(raw.get("enabled", False)),
        mode=str(raw.get("mode", "observe") or "observe"),
        mcp=_merge_asset_type_policy(raw.get("mcp"), runtime=True),
        skill=_merge_asset_type_policy(raw.get("skill"), runtime=False),
        plugin=_merge_asset_type_policy(raw.get("plugin"), runtime=False),
        connectors=_merge_asset_policy_connectors(raw.get("connectors")),
    )


def _merge_asset_policy_connectors(
    raw: Any,
) -> dict[str, PerConnectorAssetPolicy]:
    """Parse the optional ``asset_policy.connectors`` map (OTHER-7).

    Mirrors the Go unmarshal of ``map[string]PerConnectorAssetPolicy`` and
    :func:`_merge_guardrail_connectors`. A non-mapping or empty value yields
    an empty dict (legacy global-only behavior). Per-type blocks are parsed
    only when present so ``None`` means "inherit the global per-type policy".
    """
    if not isinstance(raw, dict) or not raw:
        return {}
    out: dict[str, PerConnectorAssetPolicy] = {}
    for name, entry in raw.items():
        entry = entry if isinstance(entry, dict) else {}
        out[str(name)] = PerConnectorAssetPolicy(
            mode=str(entry.get("mode", "") or ""),
            mcp=_merge_per_connector_asset_type_policy(entry.get("mcp")),
            skill=_merge_per_connector_asset_type_policy(entry.get("skill")),
            plugin=_merge_per_connector_asset_type_policy(entry.get("plugin")),
        )
    return out


def _merge_per_connector_asset_type_policy(
    raw: Any,
) -> PerConnectorAssetTypePolicy | None:
    """Parse one per-connector per-type scalar block.

    Returns ``None`` for an absent / non-mapping / empty block so the
    resolver inherits the global per-type policy entirely.
    ``registry_required`` is parsed only when an explicit bool is present
    (mirrors the Go ``*bool`` inherit-on-nil); any non-bool value (including
    ``null``) is treated as unset.
    """
    if not isinstance(raw, dict) or not raw:
        return None
    rr = raw.get("registry_required")
    return PerConnectorAssetTypePolicy(
        default=str(raw.get("default", "") or ""),
        registry_required=rr if isinstance(rr, bool) else None,
        registry_empty_action=str(raw.get("registry_empty_action", "") or ""),
    )


def _merge_asset_type_policy(raw: dict[str, Any] | None, *, runtime: bool) -> AssetTypePolicy:
    if not isinstance(raw, dict):
        base = AssetTypePolicy()
    else:
        base = AssetTypePolicy(
            default=str(raw.get("default", "allow") or "allow"),
            registry_required=bool(raw.get("registry_required", False)),
            registry=_merge_asset_rules(raw.get("registry")),
            allowed=_merge_asset_rules(raw.get("allowed")),
            denied=_merge_asset_rules(raw.get("denied")),
            runtime_detection=_merge_asset_runtime_detection(raw.get("runtime_detection")),
            registry_empty_action=str(
                raw.get("registry_empty_action", "deny") or "deny",
            )
            .strip()
            .lower(),
        )
    if not runtime:
        base.runtime_detection = AssetRuntimeDetectionConfig(
            enabled=False,
            terminal_commands=False,
            unknown_terminal_mcp="observe",
        )
    return base


def _merge_asset_runtime_detection(raw: dict[str, Any] | None) -> AssetRuntimeDetectionConfig:
    if not isinstance(raw, dict):
        return AssetRuntimeDetectionConfig()
    return AssetRuntimeDetectionConfig(
        enabled=bool(raw.get("enabled", False)),
        terminal_commands=bool(raw.get("terminal_commands", True)),
        unknown_terminal_mcp=str(raw.get("unknown_terminal_mcp", "observe") or "observe"),
    )


def _merge_registries(raw: Any) -> RegistriesConfig:
    """Build a :class:`RegistriesConfig` from the YAML ``registries:`` block.

    Unknown ``kind`` / ``content`` values are coerced to safe defaults
    (``http_yaml`` / ``skill``) rather than raising — the loader has to
    survive on best-effort because corrupted config files are recoverable
    only if every other section still loads. The CLI's ``registry add``
    flow validates strictly so user-driven entries always land in the
    canonical shape.

    Coercions are logged at WARNING via :mod:`logging` (also written
    to stderr at startup) so a typo in ``kind:`` doesn't sit hidden
    inside the loader; without the warning operators previously hit
    cryptic "no entries returned" failures during sync because the
    coerced ``http_yaml`` adapter would fetch the wrong URL shape.

    Sources with an empty ``id`` are silently skipped — they cannot be
    addressed by ``registry sync <id>`` anyway and would only confuse
    downstream code.
    """
    if not isinstance(raw, dict):
        return RegistriesConfig()
    raw_sources = raw.get("sources")
    if not isinstance(raw_sources, list):
        return RegistriesConfig()
    sources: list[RegistrySource] = []
    seen_ids: set[str] = set()
    for entry in raw_sources:
        if not isinstance(entry, dict):
            continue
        sid = str(entry.get("id", "") or "").strip()
        if not sid or sid in seen_ids:
            continue
        seen_ids.add(sid)
        raw_kind = str(entry.get("kind", "http_yaml") or "http_yaml").strip()
        kind = raw_kind.lower()
        if kind not in REGISTRY_KINDS:
            _log.warning(
                "registries.sources[id=%r]: unknown kind %r; coercing to 'http_yaml'. Valid kinds: %s",
                sid,
                raw_kind,
                ", ".join(REGISTRY_KINDS),
            )
            kind = "http_yaml"
        raw_content = str(entry.get("content", "skill") or "skill").strip()
        content = raw_content.lower()
        if content not in REGISTRY_CONTENT_TYPES:
            _log.warning(
                "registries.sources[id=%r]: unknown content %r; coercing to 'skill'. Valid content types: %s",
                sid,
                raw_content,
                ", ".join(REGISTRY_CONTENT_TYPES),
            )
            content = "skill"
        sync_interval = entry.get("sync_interval_hours", 24)
        try:
            sync_interval_int = max(0, int(sync_interval))
        except (TypeError, ValueError):
            sync_interval_int = 24
        sources.append(
            RegistrySource(
                id=sid,
                kind=kind,
                url=str(entry.get("url", "") or ""),
                content=content,
                auth_env=str(entry.get("auth_env", "") or ""),
                enabled=bool(entry.get("enabled", True)),
                auto_sync=bool(entry.get("auto_sync", False)),
                sync_interval_hours=sync_interval_int,
                last_sync=str(entry.get("last_sync", "") or ""),
                last_status=str(entry.get("last_status", "") or ""),
            )
        )
    return RegistriesConfig(sources=sources)


def _merge_asset_rules(raw: Any) -> list[AssetPolicyRule]:
    if not isinstance(raw, list):
        return []
    rules: list[AssetPolicyRule] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        args_prefix = entry.get("args_prefix", [])
        if not isinstance(args_prefix, list):
            args_prefix = []
        source_path_contains = entry.get("source_path_contains", [])
        if not isinstance(source_path_contains, list):
            source_path_contains = []
        rules.append(
            AssetPolicyRule(
                name=str(entry.get("name", "") or ""),
                connector=str(entry.get("connector", "") or ""),
                reason=str(entry.get("reason", "") or ""),
                url=str(entry.get("url", "") or ""),
                command=str(entry.get("command", "") or ""),
                args_prefix=[str(v) for v in args_prefix],
                transport=str(entry.get("transport", "") or ""),
                source_path_contains=[str(v) for v in source_path_contains],
            )
        )
    return rules


def _merge_cisco_ai_defense(raw: dict[str, Any] | None) -> CiscoAIDefenseConfig:
    if not raw:
        return CiscoAIDefenseConfig()
    return CiscoAIDefenseConfig(
        endpoint=raw.get("endpoint", "https://us.api.inspect.aidefense.security.cisco.com"),
        api_key=raw.get("api_key", ""),
        api_key_env=raw.get("api_key_env", ""),
        timeout_ms=raw.get("timeout_ms", 3000),
        enabled_rules=raw.get("enabled_rules", []),
    )


def _merge_judge(raw: dict[str, Any] | None) -> JudgeConfig:
    if not raw:
        return JudgeConfig()
    return JudgeConfig(
        enabled=raw.get("enabled", False),
        injection=raw.get("injection", True),
        pii=raw.get("pii", True),
        pii_prompt=raw.get("pii_prompt", True),
        pii_completion=raw.get("pii_completion", True),
        tool_injection=raw.get("tool_injection", True),
        exfil=raw.get("exfil", True),
        timeout=raw.get("timeout", 30.0),
        hook_connectors=raw.get("hook_connectors", []),
        hook_timeout=raw.get("hook_timeout", 0.0),
        llm=_merge_llm(raw.get("llm")),
        model=raw.get("model", ""),
        api_key_env=raw.get("api_key_env", ""),
        api_base=raw.get("api_base", ""),
        fallbacks=raw.get("fallbacks", []),
        adjudication_timeout=raw.get("adjudication_timeout", 5.0),
    )


def _merge_guardrail(raw: dict[str, Any] | None, data_dir: str) -> GuardrailConfig:
    if not raw:
        return GuardrailConfig()
    hilt_raw = raw.get("hilt")
    if hilt_raw is None:
        hilt_raw = raw.get("hitl")
    return GuardrailConfig(
        enabled=raw.get("enabled", False),
        mode=raw.get("mode", "observe"),
        scanner_mode=raw.get("scanner_mode", "both"),
        host=raw.get("host", "localhost"),
        port=raw.get("port", 4000),
        llm=_merge_llm(raw.get("llm")),
        model=raw.get("model", ""),
        model_name=raw.get("model_name", ""),
        api_key_env=raw.get("api_key_env", ""),
        api_base=raw.get("api_base", ""),
        original_model=raw.get("original_model", ""),
        block_message=raw.get("block_message", ""),
        judge=_merge_judge(raw.get("judge")),
        detection_strategy=raw.get("detection_strategy", "regex_judge"),
        detection_strategy_prompt=raw.get("detection_strategy_prompt", ""),
        detection_strategy_completion=raw.get("detection_strategy_completion", ""),
        detection_strategy_tool_call=raw.get("detection_strategy_tool_call", ""),
        judge_sweep=raw.get("judge_sweep", True),
        rule_pack_dir=raw.get("rule_pack_dir", ""),
        connector=raw.get("connector", ""),
        hilt=_merge_hilt(hilt_raw),
        hook_fail_mode=_normalize_hook_fail_mode(raw.get("hook_fail_mode", "")),
        llm_role=_normalize_llm_role(raw.get("llm_role", "")),
        connectors=_merge_guardrail_connectors(raw.get("connectors")),
    )


def _merge_guardrail_connectors(
    raw: Any,
) -> dict[str, PerConnectorGuardrailConfig]:
    """Parse the optional ``guardrail.connectors`` map.

    Mirrors the Go unmarshal of
    ``map[string]PerConnectorGuardrailConfig``. A non-mapping or empty
    value yields an empty dict (legacy single-connector behavior). The
    per-connector ``hilt`` block is parsed only when present so ``None``
    correctly means "inherit the global HILT".
    """
    if not isinstance(raw, dict) or not raw:
        return {}
    out: dict[str, PerConnectorGuardrailConfig] = {}
    for name, entry in raw.items():
        entry = entry if isinstance(entry, dict) else {}
        hilt_entry = entry.get("hilt")
        if hilt_entry is None:
            hilt_entry = entry.get("hitl")
        # ``enabled`` is parsed only when present so an absent key stays
        # ``None`` ("inherit default") rather than collapsing to a concrete
        # bool. A non-bool value is ignored (treated as unset) to match Go's
        # *bool nil semantics.
        enabled_raw = entry.get("enabled")
        enabled = enabled_raw if isinstance(enabled_raw, bool) else None
        out[str(name)] = PerConnectorGuardrailConfig(
            mode=entry.get("mode", ""),
            hilt=_merge_hilt(hilt_entry) if hilt_entry is not None else None,
            hook_fail_mode=entry.get("hook_fail_mode", ""),
            block_message=entry.get("block_message", ""),
            rule_pack_dir=entry.get("rule_pack_dir", ""),
            enabled=enabled,
        )
    return out


def _normalize_llm_role(value: Any) -> str:
    """Coerce a YAML-loaded value to one of "", "judge_only", or
    "judge_and_agent". Anything else collapses to "" so the wizard
    re-asks rather than silently honoring a typo.
    """
    if not isinstance(value, str):
        return ""
    v = value.strip().lower()
    if v in {"judge_only", "judge_and_agent"}:
        return v
    return ""


def _normalize_hook_fail_mode(value: Any) -> str:
    """Coerce a config-loaded value to one of the canonical hook fail-mode
    sentinels the gateway understands.

    Mirrors ``normalizeHookFailMode`` in
    ``internal/gateway/connector/subprocess.go``. Anything other than
    the explicit ``"open"`` sentinel collapses to ``"closed"`` so a
    typo in config.yaml never accidentally puts the agent into
    fail-OPEN mode at the response-layer boundary (CodeGuard rule
    codeguard-0-authorization-access-control: deny by default).
    """
    if isinstance(value, str) and value.strip().lower() == "open":
        return "open"
    return "closed"


def _merge_hilt(raw: dict[str, Any] | None) -> HILTConfig:
    if not raw:
        return HILTConfig()
    return HILTConfig(
        enabled=bool(raw.get("enabled", False)),
        min_severity=str(raw.get("min_severity", "HIGH") or "HIGH").upper(),
    )


def _merge_mcp_scanner(raw: Any) -> MCPScannerConfig:
    """Parse mcp_scanner config with backward compat for bare-string values."""
    if raw is None:
        return MCPScannerConfig()
    if isinstance(raw, str):
        return MCPScannerConfig(binary=raw)
    if isinstance(raw, dict):
        return MCPScannerConfig(
            binary=raw.get("binary", "mcp-scanner"),
            analyzers=raw.get("analyzers", "auto"),
            scan_prompts=raw.get("scan_prompts", False),
            scan_resources=raw.get("scan_resources", False),
            scan_instructions=raw.get("scan_instructions", False),
            llm=_merge_llm(raw.get("llm")),
        )
    return MCPScannerConfig()


def _merge_otel(raw: dict[str, Any] | None) -> OTelConfig:
    if not isinstance(raw, dict) or not raw:
        return OTelConfig()
    traces_raw = _as_mapping(raw.get("traces"))
    logs_raw = _as_mapping(raw.get("logs"))
    metrics_raw = _as_mapping(raw.get("metrics"))
    batch_raw = _as_mapping(raw.get("batch"))
    resource_raw = _as_mapping(raw.get("resource"))
    destinations: list[OTelDestinationConfig] = []
    for item in raw.get("destinations") or []:
        if not isinstance(item, dict):
            continue
        dest_traces = _as_mapping(item.get("traces"))
        dest_logs = _as_mapping(item.get("logs"))
        dest_metrics = _as_mapping(item.get("metrics"))
        dest_batch = _as_mapping(item.get("batch"))
        dest_tls = _as_mapping(item.get("tls"))
        dest_span_filter = _as_mapping(item.get("span_filter"))
        required_filter_attrs = dest_span_filter.get("require_attributes", [])
        if not isinstance(required_filter_attrs, (list, tuple)):
            required_filter_attrs = []
        filter_operations: list[OTelSpanFilterOperationConfig] = []
        for operation in dest_span_filter.get("operations") or []:
            if not isinstance(operation, dict):
                continue
            operation_attrs = operation.get("require_attributes", [])
            if not isinstance(operation_attrs, (list, tuple)):
                operation_attrs = []
            filter_operations.append(
                OTelSpanFilterOperationConfig(
                    name=str(operation.get("name", "") or ""),
                    require_attributes=[str(value) for value in operation_attrs if str(value).strip()],
                )
            )
        destinations.append(
            OTelDestinationConfig(
                name=str(item.get("name", "") or ""),
                preset=str(item.get("preset", "") or ""),
                enabled=_coerce_bool(item.get("enabled", True), default=True),
                protocol=str(item.get("protocol", "grpc") or "grpc"),
                endpoint=str(item.get("endpoint", "") or ""),
                headers={str(k): str(v) for k, v in _as_mapping(item.get("headers")).items()},
                tls=OTelTLSConfig(
                    insecure=_coerce_bool(dest_tls.get("insecure", False)),
                    ca_cert=str(dest_tls.get("ca_cert", "") or ""),
                ),
                traces=OTelTracesConfig(
                    enabled=_coerce_bool(dest_traces.get("enabled", False)),
                    endpoint=str(dest_traces.get("endpoint", "") or ""),
                    protocol=str(dest_traces.get("protocol", "") or ""),
                    url_path=str(dest_traces.get("url_path", "") or ""),
                ),
                logs=OTelLogsConfig(
                    enabled=_coerce_bool(dest_logs.get("enabled", False)),
                    endpoint=str(dest_logs.get("endpoint", "") or ""),
                    protocol=str(dest_logs.get("protocol", "") or ""),
                    url_path=str(dest_logs.get("url_path", "") or ""),
                ),
                metrics=OTelMetricsConfig(
                    enabled=_coerce_bool(dest_metrics.get("enabled", False)),
                    export_interval_s=_as_int(dest_metrics.get("export_interval_s", 60), 60),
                    temporality=str(dest_metrics.get("temporality", "delta") or "delta"),
                    endpoint=str(dest_metrics.get("endpoint", "") or ""),
                    protocol=str(dest_metrics.get("protocol", "") or ""),
                    url_path=str(dest_metrics.get("url_path", "") or ""),
                ),
                batch=OTelBatchConfig(
                    max_export_batch_size=_as_int(dest_batch.get("max_export_batch_size", 512), 512),
                    scheduled_delay_ms=_as_int(dest_batch.get("scheduled_delay_ms", 5000), 5000),
                    max_queue_size=_as_int(dest_batch.get("max_queue_size", 2048), 2048),
                ),
                span_filter=OTelSpanFilterConfig(
                    require_operation=str(dest_span_filter.get("require_operation", "") or ""),
                    require_attributes=[str(value) for value in required_filter_attrs if str(value).strip()],
                    operations=filter_operations,
                ),
            )
        )
    return OTelConfig(
        enabled=_coerce_bool(raw.get("enabled", False)),
        traces=OTelTracePolicyConfig(
            sampler=traces_raw.get("sampler", "always_on"),
            sampler_arg=traces_raw.get("sampler_arg", "1.0"),
        ),
        logs=OTelLogPolicyConfig(
            emit_individual_findings=_coerce_bool(logs_raw.get("emit_individual_findings", False)),
        ),
        metrics=OTelMetricPolicyConfig(
            export_interval_s=_as_int(metrics_raw.get("export_interval_s", 60), 60),
            temporality=metrics_raw.get("temporality", "delta"),
        ),
        batch=OTelBatchConfig(
            max_export_batch_size=_as_int(batch_raw.get("max_export_batch_size", 512), 512),
            scheduled_delay_ms=_as_int(batch_raw.get("scheduled_delay_ms", 5000), 5000),
            max_queue_size=_as_int(batch_raw.get("max_queue_size", 2048), 2048),
        ),
        resource=OTelResourceConfig(
            attributes=_as_mapping(resource_raw.get("attributes")),
        ),
        destinations=destinations,
    )


def _as_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _snapshot_authoritative_dicts(raw: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for path in _AUTHORITATIVE_MODELED_DICT_PATHS:
        cur: Any = raw
        for part in path.split("."):
            if not isinstance(cur, dict):
                cur = {}
                break
            cur = cur.get(part, {})
        out[path] = dict(cur) if isinstance(cur, dict) else {}
    return out


def _snapshot_owned_nested_values(raw: dict[str, Any]) -> dict[str, Any]:
    """Record the loaded raw value of each _OWNED_NESTED_KEYS path.

    Paths absent from the file are simply omitted from the snapshot —
    absence (vs an explicit zero value) is what lets the merge's
    stale-writer rescue tell "this process never saw a value" apart
    from "this process loaded one and cleared it". The walk is
    structural (one dict level per path segment), so a literal YAML key
    that merely *contains* dots never satisfies a path here.
    """
    out: dict[str, Any] = {}
    for path in _OWNED_NESTED_KEYS:
        cur: Any = raw
        found = True
        parts = path.split(".")
        for part in parts[:-1]:
            cur = cur.get(part) if isinstance(cur, dict) else None
            if cur is None:
                found = False
                break
        if found and isinstance(cur, dict) and parts[-1] in cur:
            out[path] = cur[parts[-1]]
    return out


def _merge_webhooks(raw: list[dict[str, Any]] | None) -> list[WebhookConfig]:
    if not raw:
        return []
    webhooks: list[WebhookConfig] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        # Preserve nil-vs-zero for cooldown_seconds so round-tripping the
        # YAML matches Go's ``*int`` semantics (see WebhookConfig
        # docstring above).
        cd_raw = entry.get("cooldown_seconds", None)
        if cd_raw is None:
            cooldown: int | None = None
        else:
            try:
                cooldown = int(cd_raw)
            except (TypeError, ValueError):
                cooldown = None
            if cooldown is not None and cooldown < 0:
                cooldown = None
        webhooks.append(
            WebhookConfig(
                name=str(entry.get("name", "") or ""),
                url=entry.get("url", ""),
                type=entry.get("type", "generic"),
                secret_env=entry.get("secret_env", ""),
                room_id=entry.get("room_id", ""),
                min_severity=entry.get("min_severity", "HIGH"),
                events=entry.get("events", []),
                timeout_seconds=entry.get("timeout_seconds", 10),
                cooldown_seconds=cooldown,
                enabled=entry.get("enabled", False),
            )
        )
    return webhooks


def _merge_observability(raw: Any) -> ObservabilityConfig:
    """Parse the optional ``observability:`` block (D5b)."""
    if not isinstance(raw, dict):
        return ObservabilityConfig()
    return ObservabilityConfig(
        connectors=_merge_observability_connectors(raw.get("connectors")),
    )


def _merge_observability_connectors(
    raw: Any,
) -> dict[str, PerConnectorObservability]:
    """Parse the optional ``observability.connectors`` map (D5b).

    Mirrors :func:`_merge_asset_policy_connectors`. A non-mapping / empty
    value yields an empty dict (legacy global-only behavior). For each
    dimension, an absent key parses to ``None`` ("inherit global"); a
    present list (including an explicit empty list) parses to a list
    ("override", and ``[]`` suppresses global for that connector).
    """
    if not isinstance(raw, dict) or not raw:
        return {}
    out: dict[str, PerConnectorObservability] = {}
    for name, entry in raw.items():
        entry = entry if isinstance(entry, dict) else {}
        sinks = entry.get("audit_sinks")
        webhooks_raw = entry.get("webhooks")
        out[str(name)] = PerConnectorObservability(
            audit_sinks=([dict(s) for s in sinks if isinstance(s, dict)] if isinstance(sinks, list) else None),
            webhooks=(_merge_webhooks(webhooks_raw) if isinstance(webhooks_raw, list) else None),
        )
    return out


def _merge_openshell(raw: dict[str, Any] | None) -> OpenShellConfig:
    if not raw:
        return OpenShellConfig()
    auto_pair = raw.get("auto_pair")
    if auto_pair is not None:
        auto_pair = bool(auto_pair)
    host_networking = raw.get("host_networking")
    if host_networking is not None:
        host_networking = bool(host_networking)
    else:
        host_networking = True
    return OpenShellConfig(
        binary=raw.get("binary", "openshell"),
        policy_dir=raw.get("policy_dir", "/etc/openshell/policies"),
        mode=raw.get("mode", ""),
        version=raw.get("version", DEFAULT_OPENSHELL_VERSION),
        sandbox_home=raw.get("sandbox_home", DEFAULT_SANDBOX_HOME),
        auto_pair=auto_pair,
        host_networking=host_networking,
    )


def _merge_gateway_watcher(raw: dict[str, Any] | None) -> GatewayWatcherConfig:
    if not raw:
        return GatewayWatcherConfig()
    skill_raw = raw.get("skill", {})
    plugin_raw = raw.get("plugin", {})
    return GatewayWatcherConfig(
        enabled=raw.get("enabled", True),
        skill=GatewayWatcherSkillConfig(
            enabled=skill_raw.get("enabled", True),
            take_action=skill_raw.get("take_action", False),
            dirs=skill_raw.get("dirs", []),
        ),
        plugin=GatewayWatcherPluginConfig(
            enabled=plugin_raw.get("enabled", True),
            take_action=plugin_raw.get("take_action", False),
            dirs=plugin_raw.get("dirs", []),
        ),
    )


def _merge_gateway_config_reload(raw: dict[str, Any] | None) -> GatewayConfigReloadConfig:
    if not raw:
        return GatewayConfigReloadConfig()
    return GatewayConfigReloadConfig(mode=_normalize_gateway_config_reload_mode(raw.get("mode")))


def _normalize_gateway_config_reload_mode(value: Any) -> str:
    mode = str(value or "hot").strip().lower()
    if mode not in {"hot", "restart"}:
        raise ValueError("gateway.config_reload.mode must be 'hot' or 'restart'")
    return mode


def _apply_instance_overlay(out: LLMConfig, data_dir: str) -> None:
    """Fold a custom-providers.json instance entry into a resolved LLMConfig.

    Reads the overlay at ``<data_dir>/custom-providers.json`` (the
    same file ``defenseclaw setup provider`` writes) and merges the
    matching instance's defaults UNDER ``out``. Only blanks are
    filled; explicit role-level values always win. Silent no-op when
    the overlay file is missing, malformed, or has no matching
    instance — the resolver's job is to be tolerant, not to validate
    overlay shape; ``defenseclaw doctor`` is responsible for surfacing
    overlay typos.

    Recognised overlay fields per provider entry (additive to the
    pre-existing ``name``/``domains``/``env_keys``/``profile_id``
    shape consumed by the Go-side overlay merger — every field
    below is optional):

    * ``base_provider_type`` — the upstream provider family
      (``openai``/``bedrock``/``azure``/``vertex``/``ollama`` ...)
    * ``base_url``           — the on-prem / proxy endpoint URL
    * ``available_models``   — strings the wizard offers in the
      model picker for this instance
    * ``request_path_overrides`` — per-route URL path overrides
    * ``allowed_requests``   — allow-list of request types
    * ``tls``                — TLS sub-block (ca_cert_pem, insecure_skip_verify)
    * ``bedrock``/``vertex``/``azure`` — provider-typed sub-blocks
    """
    if not out.instance_name or not data_dir:
        return
    overlay_path = os.path.join(data_dir, "custom-providers.json")
    try:
        import json as _json

        with open(overlay_path, encoding="utf-8") as f:
            data = _json.load(f)
    except (OSError, ValueError):
        return
    if not isinstance(data, dict):
        return
    providers = data.get("providers") or []
    if not isinstance(providers, list):
        return
    target_name = out.instance_name.strip().lower()
    entry: dict[str, Any] | None = None
    for p in providers:
        if isinstance(p, dict) and str(p.get("name", "")).strip().lower() == target_name:
            entry = p
            break
    if entry is None:
        return
    if not out.provider:
        bp = entry.get("base_provider_type") or entry.get("provider") or ""
        if isinstance(bp, str) and bp:
            out.provider = bp.strip().lower()
    if not out.base_url:
        bu = entry.get("base_url") or ""
        if isinstance(bu, str) and bu:
            out.base_url = bu
    if not out.api_key_env:
        env_keys = entry.get("env_keys") or []
        if isinstance(env_keys, list) and env_keys:
            first = str(env_keys[0]).strip()
            if first:
                out.api_key_env = first
    if out.tls is None:
        out.tls = _merge_tls(entry.get("tls"))
    if out.bedrock is None:
        out.bedrock = _merge_bedrock(entry.get("bedrock"))
    if out.vertex is None:
        out.vertex = _merge_vertex(entry.get("vertex"))
    if out.azure is None:
        out.azure = _merge_azure(entry.get("azure"))


def _load_dotenv_into_os(data_dir: str) -> None:
    """Load KEY=VALUE pairs from ~/.defenseclaw/.env into os.environ.

    Existing environment variables are never overwritten.  This ensures
    secrets stored by ``defenseclaw setup`` are available to the Python CLI
    even when not exported in the user's shell profile.
    """
    env_path = os.path.join(data_dir, ".env")
    try:
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                key, _, value = line.partition("=")
                key, value = key.strip(), value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                    value = value[1:-1]
                if key and key not in os.environ:
                    os.environ[key] = value
    except FileNotFoundError:
        pass
    except OSError as exc:
        _log.debug("config: cannot read %s: %s", env_path, exc)


def _warn_plaintext_secrets(cfg: Config) -> None:
    """Emit deprecation warnings for plain-text secrets in config.yaml."""

    def _warn(section: str, field: str, env_default: str) -> None:
        _log.warning(
            "%s.%s contains a plain-text secret in config.yaml — "
            "migrate it to ~/.defenseclaw/.env as %s and set %s.%s_env=%s instead",
            section,
            field,
            env_default,
            section,
            field,
            env_default,
        )

    if cfg.llm.api_key:
        _warn("llm", "api_key", "DEFENSECLAW_LLM_KEY")
    if cfg.inspect_llm.api_key:
        _warn("inspect_llm", "api_key", "LLM_API_KEY")
    if cfg.cisco_ai_defense.api_key:
        _warn("cisco_ai_defense", "api_key", "CISCO_AI_DEFENSE_API_KEY")
    if cfg.scanners.skill_scanner.virustotal_api_key:
        _warn("scanners.skill_scanner", "virustotal_api_key", "VIRUSTOTAL_API_KEY")
    if cfg.splunk.hec_token:
        _warn("splunk", "hec_token", "DEFENSECLAW_SPLUNK_HEC_TOKEN")


def _warn_disable_redaction_config(cfg: Config) -> None:
    """Emit the persistent redaction kill-switch warning once per process.

    Colors the prefix and verb yellow when stderr is a TTY so the
    operator notices it among the rest of a busy install log. Falls
    back to plain text on non-TTY (CI logs, ``script``, ``script -a``,
    redirected stderr) so build tooling that pattern-matches against
    the message keeps working unchanged. We deliberately do NOT
    obey ``NO_COLOR`` here because this warning is high-severity —
    everyone should see it visibly highlighted when they have a TTY,
    and ``NO_COLOR`` users have a plain-text fallback either way.
    """
    global _privacy_disable_redaction_warned
    if not cfg.privacy.disable_redaction or _privacy_disable_redaction_warned:
        return
    _privacy_disable_redaction_warned = True

    # Yellow + bold prefix, yellow body. On non-TTY we drop the
    # ANSI codes entirely so the existing pattern-matchers in
    # tests/CI keep working. ``click.style`` honors NO_COLOR
    # implicitly, but for this single high-severity warning we
    # also want it visible to TTY users who set NO_COLOR for OTHER
    # reasons (e.g. screen readers that prefer cleaner panels) —
    # so we manually gate on isatty only.
    try:
        is_tty = sys.stderr.isatty()
    except (AttributeError, ValueError):
        is_tty = False
    if is_tty:
        prefix = "\x1b[1;33m⚠ warning:\x1b[0m \x1b[33m"
        suffix = "\x1b[0m"
    else:
        prefix, suffix = "warning: ", ""

    print(
        f"{prefix}privacy.disable_redaction=true — ALL sinks (audit DB, "
        f"OTel logs, webhooks, Splunk HEC) will receive UNREDACTED prompts, "
        f"judge bodies, and verdict reasons. Disable in shared/multi-tenant "
        f"deployments via `defenseclaw setup redaction on`.{suffix}",
        file=sys.stderr,
    )


def load() -> Config:
    """Load config from ~/.defenseclaw/config.yaml, applying defaults."""
    data_dir = str(default_data_path())
    _load_dotenv_into_os(data_dir)
    cfg_file = str(config_path())

    raw: dict[str, Any] = {}
    try:
        with open(cfg_file) as f:
            raw = yaml.safe_load(f) or {}
    except OSError:
        pass
    _warn_untrusted_managed_config(cfg_file, raw)

    scanners_raw = raw.get("scanners", {})
    ss_raw = scanners_raw.get("skill_scanner", {})
    gw_raw = raw.get("gateway", {})
    splunk_raw = raw.get("splunk", {}) or {}

    # v4 compatibility: the Go gateway routes Splunk forwarding through
    # the generic `audit_sinks:` list. The Python CLI still has its own
    # fire-and-forget Splunk forwarder for events raised in process
    # (aibom scan, skill quarantine, plugin disable, etc.), so mirror
    # the first enabled `splunk_hec` sink into the legacy SplunkConfig
    # shape *in memory only* — we never write the legacy block back to
    # disk (see _config_to_dict). This preserves parallel Python → HEC
    # forwarding without reintroducing the migration tripwire in
    # internal/config/config.go::detectLegacySplunk.
    if not splunk_raw:
        for sink in raw.get("audit_sinks") or []:
            if not isinstance(sink, dict):
                continue
            if sink.get("kind") != "splunk_hec":
                continue
            if sink.get("enabled") is False:
                continue
            hec = sink.get("splunk_hec") or {}
            if not isinstance(hec, dict) or not hec.get("endpoint"):
                continue
            splunk_raw = {
                "enabled": True,
                "hec_endpoint": hec.get("endpoint", ""),
                "hec_token": hec.get("token", ""),
                "hec_token_env": hec.get("token_env", ""),
                "index": hec.get("index", "defenseclaw"),
                "source": hec.get("source", "defenseclaw"),
                "sourcetype": hec.get("sourcetype", "_json"),
                # default verify_tls to True so promoting an
                # audit_sinks declaration into the legacy SplunkConfig
                # block never silently downgrades verification. The
                # explicit opt-out lives on the new
                # ``insecure_skip_verify`` field.
                "verify_tls": _coerce_bool(hec.get("verify_tls", True), default=True),
                "insecure_skip_verify": _coerce_bool(hec.get("insecure_skip_verify", False)),
            }
            break

    cfg = Config(
        data_dir=raw.get("data_dir", data_dir),
        llm=_merge_llm(raw.get("llm")),
        default_llm_api_key_env=raw.get("default_llm_api_key_env", ""),
        default_llm_model=raw.get("default_llm_model", ""),
        audit_db=raw.get("audit_db", os.path.join(data_dir, AUDIT_DB_NAME)),
        quarantine_dir=raw.get("quarantine_dir", os.path.join(data_dir, "quarantine")),
        plugin_dir=raw.get("plugin_dir", os.path.join(data_dir, "plugins")),
        policy_dir=raw.get("policy_dir", os.path.join(data_dir, "policies")),
        environment=raw.get("environment", detect_environment()),
        tenant_id=raw.get("tenant_id", ""),
        workspace_id=raw.get("workspace_id", ""),
        deployment_mode=_validate_deployment_mode(raw.get("deployment_mode", "")),
        discovery_source=raw.get("discovery_source", ""),
        claw=ClawConfig(
            mode=raw.get("claw", {}).get("mode", "openclaw"),
            home_dir=raw.get("claw", {}).get("home_dir", "~/.openclaw"),
            config_file=raw.get("claw", {}).get("config_file", "~/.openclaw/openclaw.json"),
            workspace_dir=raw.get("claw", {}).get("workspace_dir", ""),
            openclaw_home_original=raw.get("claw", {}).get("openclaw_home_original", ""),
        ),
        inspect_llm=_merge_inspect_llm(raw.get("inspect_llm")),
        cisco_ai_defense=_merge_cisco_ai_defense(raw.get("cisco_ai_defense")),
        scanners=ScannersConfig(
            skill_scanner=SkillScannerConfig(
                binary=ss_raw.get("binary", "skill-scanner"),
                use_llm=ss_raw.get("use_llm", False),
                use_behavioral=ss_raw.get("use_behavioral", False),
                enable_meta=ss_raw.get("enable_meta", False),
                use_trigger=ss_raw.get("use_trigger", False),
                use_virustotal=ss_raw.get("use_virustotal", False),
                use_aidefense=ss_raw.get("use_aidefense", False),
                llm_consensus_runs=ss_raw.get("llm_consensus_runs", 0),
                policy=ss_raw.get("policy", "permissive"),
                lenient=ss_raw.get("lenient", True),
                llm=_merge_llm(ss_raw.get("llm")),
                virustotal_api_key=ss_raw.get("virustotal_api_key", ""),
                virustotal_api_key_env=ss_raw.get("virustotal_api_key_env", ""),
            ),
            mcp_scanner=_merge_mcp_scanner(scanners_raw.get("mcp_scanner")),
            plugin_llm=_merge_llm(scanners_raw.get("plugin_llm")),
            codeguard=scanners_raw.get("codeguard", os.path.join(data_dir, "codeguard-rules")),
        ),
        openshell=_merge_openshell(raw.get("openshell")),
        watch=WatchConfig(
            debounce_ms=raw.get("watch", {}).get("debounce_ms", 500),
            auto_block=raw.get("watch", {}).get("auto_block", True),
            allow_list_bypass_scan=raw.get("watch", {}).get("allow_list_bypass_scan", True),
            rescan_enabled=raw.get("watch", {}).get("rescan_enabled", True),
            rescan_interval_min=raw.get("watch", {}).get("rescan_interval_min", 60),
        ),
        firewall=FirewallConfig(
            config_file=raw.get("firewall", {}).get("config_file", os.path.join(data_dir, "firewall.yaml")),
            rules_file=raw.get("firewall", {}).get("rules_file", os.path.join(data_dir, "firewall.pf.conf")),
            anchor_name=raw.get("firewall", {}).get("anchor_name", "com.defenseclaw"),
        ),
        guardrail=_merge_guardrail(raw.get("guardrail"), data_dir),
        splunk=SplunkConfig(
            hec_endpoint=splunk_raw.get("hec_endpoint", "https://localhost:8088/services/collector/event"),
            hec_token=splunk_raw.get("hec_token", ""),
            hec_token_env=splunk_raw.get("hec_token_env", ""),
            index=splunk_raw.get("index", "defenseclaw"),
            source=splunk_raw.get("source", "defenseclaw"),
            sourcetype=splunk_raw.get("sourcetype", "_json"),
            # default verify_tls to True so callers that load a
            # legacy config without the new field still get certificate
            # verification. The explicit dev-mode opt-out lives on
            # ``insecure_skip_verify`` and is wired separately.
            verify_tls=_coerce_bool(splunk_raw.get("verify_tls", True), default=True),
            insecure_skip_verify=_coerce_bool(splunk_raw.get("insecure_skip_verify", False)),
            enabled=splunk_raw.get("enabled", False),
            batch_size=splunk_raw.get("batch_size", 50),
            flush_interval_s=splunk_raw.get("flush_interval_s", 5),
        ),
        otel=_merge_otel(raw.get("otel")),
        gateway=GatewayConfig(
            host=gw_raw.get("host", "127.0.0.1"),
            port=gw_raw.get("port", 18789),
            api_bind=gw_raw.get("api_bind", ""),
            token=gw_raw.get("token", ""),
            token_env=gw_raw.get("token_env", ""),
            device_key_file=gw_raw.get("device_key_file", os.path.join(data_dir, "device.key")),
            auto_approve_safe=gw_raw.get("auto_approve_safe", False),
            reconnect_ms=gw_raw.get("reconnect_ms", 800),
            max_reconnect_ms=gw_raw.get("max_reconnect_ms", 15000),
            approval_timeout_s=gw_raw.get("approval_timeout_s", 30),
            api_port=gw_raw.get("api_port", 18970),
            config_reload=_merge_gateway_config_reload(gw_raw.get("config_reload")),
            watcher=_merge_gateway_watcher(gw_raw.get("watcher")),
        ),
        skill_actions=_merge_skill_actions(raw.get("skill_actions")),
        mcp_actions=_merge_mcp_actions(raw.get("mcp_actions")),
        plugin_actions=_merge_plugin_actions(raw.get("plugin_actions")),
        asset_policy=_merge_asset_policy(raw.get("asset_policy")),
        registries=_merge_registries(raw.get("registries")),
        webhooks=_merge_webhooks(raw.get("webhooks")),
        observability=_merge_observability(raw.get("observability")),
        privacy=_merge_privacy(raw.get("privacy")),
        ai_discovery=_merge_ai_discovery(raw.get("ai_discovery")),
        application_protection=_merge_application_protection(raw.get("application_protection")),
        notifications=_merge_notifications(raw.get("notifications")),
        routing=_merge_routing(raw.get("routing")),
    )
    cfg._loaded_authoritative_dicts = _snapshot_authoritative_dicts(raw)
    cfg._loaded_owned_nested_values = _snapshot_owned_nested_values(raw)
    _migrate_llm_fields(cfg)
    _warn_disable_redaction_config(cfg)
    _warn_plaintext_secrets(cfg)
    # Fail loud on invalid guardrail value invariants, mirroring the Go
    # gateway's Load() which rejects the same shapes. Value-only check —
    # no registry access (see GuardrailConfig.validate).
    cfg.guardrail.validate()
    # Same value-only guard for the per-connector asset_policy overrides
    # (OTHER-7) — empty/duplicate connector names + bad scalar enums. The
    # global asset_policy fields are intentionally not re-validated here.
    cfg.asset_policy.validate()
    # Same value-only guard for per-connector observability overrides (D5b):
    # empty / alias-duplicate connector names. The sink/webhook payloads are
    # validated by their respective writers at write time.
    cfg.observability.validate()
    cfg.application_protection.validate()
    return cfg


def _merge_privacy(raw: dict[str, Any] | None) -> PrivacyConfig:
    """Build a :class:`PrivacyConfig` from the YAML ``privacy:`` block.

    Defaults match the Go side (``disable_redaction: false``) so a
    config without the block keeps the historical
    redact-by-default contract.
    """
    if not isinstance(raw, dict):
        return PrivacyConfig()
    return PrivacyConfig(
        disable_redaction=bool(raw.get("disable_redaction", False)),
    )


def _merge_ai_discovery(raw: dict[str, Any] | None) -> AIDiscoveryConfig:
    if not isinstance(raw, dict):
        return AIDiscoveryConfig(enabled=False)
    return AIDiscoveryConfig(
        enabled=bool(raw.get("enabled", True)),
        mode=str(raw.get("mode", "enhanced") or "enhanced"),
        scan_interval_min=int(raw.get("scan_interval_min", 5) or 5),
        process_interval_s=int(raw.get("process_interval_s", 60) or 60),
        scan_roots=list(raw.get("scan_roots", ["~"]) or ["~"]),
        signature_packs=list(raw.get("signature_packs", []) or []),
        allow_workspace_signatures=bool(raw.get("allow_workspace_signatures", False)),
        disabled_signature_ids=list(raw.get("disabled_signature_ids", []) or []),
        include_shell_history=bool(raw.get("include_shell_history", True)),
        include_package_manifests=bool(raw.get("include_package_manifests", True)),
        include_env_var_names=bool(raw.get("include_env_var_names", True)),
        include_network_domains=bool(raw.get("include_network_domains", True)),
        max_files_per_scan=int(raw.get("max_files_per_scan", 1000) or 1000),
        max_file_bytes=int(raw.get("max_file_bytes", 512 * 1024) or 512 * 1024),
        emit_otel=bool(raw.get("emit_otel", True)),
        store_raw_local_paths=bool(raw.get("store_raw_local_paths", False)),
        confidence_policy_path=str(raw.get("confidence_policy_path", "") or ""),
        require_trusted_binary_paths=bool(raw.get("require_trusted_binary_paths", False)),
        trusted_binary_prefixes=[str(v) for v in (raw.get("trusted_binary_prefixes", []) or [])],
    )


def _merge_application_protection(raw: dict[str, Any] | None) -> ApplicationProtectionConfig:
    if not isinstance(raw, dict):
        return ApplicationProtectionConfig()
    min_confidence = _optional_float(raw.get("min_confidence"))
    guardrail = _merge_application_protection_guardrail(raw.get("guardrail"))
    if not guardrail.mode.strip():
        guardrail.mode = "observe"
    asset_policy = _merge_application_protection_asset_policy(raw.get("asset_policy"))
    if not asset_policy.mode.strip():
        asset_policy.mode = "observe"
    return ApplicationProtectionConfig(
        enabled=bool(raw.get("enabled", True)),
        min_confidence=0.80 if min_confidence is None else min_confidence,
        remove_when_gone=bool(raw.get("remove_when_gone", False)),
        gone_after_min=int(raw.get("gone_after_min", 60) or 0),
        include_connectors=[str(v) for v in (raw.get("include_connectors", []) or [])],
        exclude_connectors=[str(v) for v in (raw.get("exclude_connectors", []) or [])],
        guardrail=guardrail,
        asset_policy=asset_policy,
        connectors=_merge_application_protection_connectors(raw.get("connectors")),
    )


def _merge_application_protection_connectors(
    raw: Any,
) -> dict[str, ApplicationProtectionConnectorConfig]:
    if not isinstance(raw, dict) or not raw:
        return {}
    out: dict[str, ApplicationProtectionConnectorConfig] = {}
    for name, entry in raw.items():
        entry = entry if isinstance(entry, dict) else {}
        enabled_raw = entry.get("enabled")
        min_confidence = _optional_float(entry.get("min_confidence"))
        out[str(name)] = ApplicationProtectionConnectorConfig(
            enabled=enabled_raw if isinstance(enabled_raw, bool) else None,
            min_confidence=min_confidence,
            guardrail=_merge_application_protection_guardrail(entry.get("guardrail")),
            asset_policy=_merge_application_protection_asset_policy(entry.get("asset_policy")),
        )
    return out


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _merge_application_protection_guardrail(raw: Any) -> PerConnectorGuardrailConfig:
    if not isinstance(raw, dict):
        return PerConnectorGuardrailConfig()
    hilt_entry = raw.get("hilt")
    if hilt_entry is None:
        hilt_entry = raw.get("hitl")
    enabled_raw = raw.get("enabled")
    return PerConnectorGuardrailConfig(
        mode=str(raw.get("mode", "") or ""),
        hilt=_merge_hilt(hilt_entry) if hilt_entry is not None else None,
        hook_fail_mode=str(raw.get("hook_fail_mode", "") or ""),
        block_message=str(raw.get("block_message", "") or ""),
        rule_pack_dir=str(raw.get("rule_pack_dir", "") or ""),
        enabled=enabled_raw if isinstance(enabled_raw, bool) else None,
    )


def _merge_application_protection_asset_policy(raw: Any) -> ApplicationProtectionAssetPolicyConfig:
    if not isinstance(raw, dict):
        return ApplicationProtectionAssetPolicyConfig()
    return ApplicationProtectionAssetPolicyConfig(
        mode=str(raw.get("mode", "") or ""),
    )


def _merge_notifications(raw: dict[str, Any] | None) -> NotificationsConfig:
    """Build a :class:`NotificationsConfig` from the YAML ``notifications:`` block.

    Defaults are platform-conditional for the master switch (true on
    darwin, false elsewhere — see :func:`_default_notifications_enabled`)
    and on for every category and source so that once an operator
    opts in via ``defenseclaw setup notifications`` they immediately
    see every block surface; tuning down is then a matter of
    flipping the explicit per-category / per-source keys.

    Throttle defaults (``dedup_window=30s``, ``max_per_minute=12``)
    mirror :data:`NotificationsDefaultDedupWindow` /
    :data:`NotificationsDefaultMaxPerMinute` in the Go config so a
    YAML file written from either end loads identically on the
    other.
    """
    defaults = NotificationsConfig()
    if not isinstance(raw, dict):
        return defaults

    sources_raw = raw.get("sources")
    if isinstance(sources_raw, dict):
        sources = NotificationSourceFilter(
            hook=bool(sources_raw.get("hook", defaults.sources.hook)),
            guardrail=bool(sources_raw.get("guardrail", defaults.sources.guardrail)),
            asset_policy=bool(
                sources_raw.get("asset_policy", defaults.sources.asset_policy),
            ),
        )
    else:
        sources = NotificationSourceFilter()

    dedup_raw = raw.get("dedup_window", defaults.dedup_window)
    dedup_window = str(dedup_raw).strip() if dedup_raw not in (None, "") else defaults.dedup_window

    try:
        max_per_minute = int(raw.get("max_per_minute", defaults.max_per_minute))
    except (TypeError, ValueError):
        max_per_minute = defaults.max_per_minute
    if max_per_minute < 0:
        max_per_minute = defaults.max_per_minute

    return NotificationsConfig(
        enabled=bool(raw.get("enabled", defaults.enabled)),
        block_enforced=bool(raw.get("block_enforced", defaults.block_enforced)),
        block_would_block=bool(raw.get("block_would_block", defaults.block_would_block)),
        hitl_approval=bool(raw.get("hitl_approval", defaults.hitl_approval)),
        sources=sources,
        dedup_window=dedup_window,
        max_per_minute=max_per_minute,
    )


def _merge_routing(raw: dict[str, Any] | None) -> RoutingConfig:
    """Build a :class:`RoutingConfig` from the YAML ``routing:`` block."""
    if not isinstance(raw, dict):
        return RoutingConfig()
    return RoutingConfig(
        enabled=bool(raw.get("enabled", False)),
        version=str(raw.get("version", "") or ""),
        port=int(raw.get("port", 0) or 0),
        algorithm=str(raw.get("algorithm", "") or ""),
    )


def default_config() -> Config:
    """Return a Config with all defaults applied (mirrors DefaultConfig in Go)."""
    data_dir = str(default_data_path())
    return Config(
        data_dir=data_dir,
        audit_db=os.path.join(data_dir, AUDIT_DB_NAME),
        quarantine_dir=os.path.join(data_dir, "quarantine"),
        plugin_dir=os.path.join(data_dir, "plugins"),
        policy_dir=os.path.join(data_dir, "policies"),
        environment=detect_environment(),
        asset_policy=AssetPolicyConfig(),
        scanners=ScannersConfig(
            codeguard=os.path.join(data_dir, "codeguard-rules"),
        ),
        firewall=FirewallConfig(
            config_file=os.path.join(data_dir, "firewall.yaml"),
            rules_file=os.path.join(data_dir, "firewall.pf.conf"),
        ),
        guardrail=GuardrailConfig(),
        ai_discovery=AIDiscoveryConfig(
            enabled=True,
            confidence_policy_path=os.path.join(data_dir, "confidence.yaml"),
        ),
        gateway=GatewayConfig(
            device_key_file=os.path.join(data_dir, "device.key"),
        ),
    )
