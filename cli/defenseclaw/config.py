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

import json
import logging
import os
import platform
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_log = logging.getLogger(__name__)

DATA_DIR_NAME = ".defenseclaw"
AUDIT_DB_NAME = "audit.db"
CONFIG_FILE_NAME = "config.yaml"


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
    return default_data_path() / CONFIG_FILE_NAME


def _expand(p: str) -> str:
    if p.startswith("~/"):
        return str(_home() / p[2:])
    return p


# ---------------------------------------------------------------------------
# Environment detection (mirrors config.DetectEnvironment)
# ---------------------------------------------------------------------------

def detect_environment() -> str:
    if platform.system() == "Darwin":
        return "macos"
    if Path("/etc/dgx-release").exists():
        return "dgx-spark"
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "-L"], stderr=subprocess.DEVNULL, text=True,
        )
        if "DGX" in out:
            return "dgx-spark"
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass
    return "linux"


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

@dataclass
class MCPServerEntry:
    name: str = ""
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str = ""
    transport: str = ""


@dataclass
class ClawConfig:
    mode: str = "openclaw"
    home_dir: str = "~/.openclaw"
    config_file: str = "~/.openclaw/openclaw.json"
    openclaw_home_original: str = ""


@dataclass
class InspectLLMConfig:
    """Shared LLM configuration used by both skill-scanner and mcp-scanner."""
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
            import os
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
    analyzers: str = "yara"
    scan_prompts: bool = False
    scan_resources: bool = False
    scan_instructions: bool = False


@dataclass
class ScannersConfig:
    skill_scanner: SkillScannerConfig = field(default_factory=SkillScannerConfig)
    mcp_scanner: MCPScannerConfig = field(default_factory=MCPScannerConfig)
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
    verify_tls: bool = False
    enabled: bool = False
    batch_size: int = 50
    flush_interval_s: int = 5

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
class OTelConfig:
    enabled: bool = False
    protocol: str = "grpc"
    endpoint: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    tls: OTelTLSConfig = field(default_factory=OTelTLSConfig)
    traces: OTelTracesConfig = field(default_factory=OTelTracesConfig)
    logs: OTelLogsConfig = field(default_factory=OTelLogsConfig)
    metrics: OTelMetricsConfig = field(default_factory=OTelMetricsConfig)
    batch: OTelBatchConfig = field(default_factory=OTelBatchConfig)
    resource: OTelResourceConfig = field(default_factory=OTelResourceConfig)


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
    watcher: GatewayWatcherConfig = field(default_factory=GatewayWatcherConfig)

    def resolved_token(self) -> str:
        """Return gateway token from env var (if set) or direct value."""
        if self.token_env:
            val = os.environ.get(self.token_env, "")
            if val:
                return val
        else:
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
    model: str = ""
    api_key_env: str = ""
    api_base: str = ""
    timeout: float = 30.0
    fallbacks: list[str] = field(default_factory=list)
    adjudication_timeout: float = 5.0


@dataclass
class WebhookConfig:
    url: str = ""
    type: str = "generic"
    secret_env: str = ""
    room_id: str = ""
    min_severity: str = "HIGH"
    events: list[str] = field(default_factory=list)
    timeout_seconds: int = 10
    cooldown_seconds: int = 300
    enabled: bool = False

    def resolved_secret(self) -> str:
        """Return the webhook secret/token from the env var."""
        if self.secret_env:
            return os.environ.get(self.secret_env, "")
        return ""


@dataclass
class GuardrailConfig:
    enabled: bool = False
    mode: str = "observe"           # observe | action
    scanner_mode: str = "both"      # local | remote | both
    host: str = "localhost"         # host where guardrail proxy is reachable (bridge IP in sandbox mode)
    port: int = 4000
    model: str = ""                 # upstream model, e.g. "anthropic/claude-opus-4-5"
    model_name: str = ""            # alias exposed to OpenClaw, e.g. "claude-opus"
    api_key_env: str = ""           # env var holding the API key, e.g. "ANTHROPIC_API_KEY"
    original_model: str = ""        # original OpenClaw model (for revert)
    block_message: str = ""         # custom message shown when a request is blocked (empty = default)
    api_base: str = ""              # base URL override for Azure, custom endpoints
    judge: JudgeConfig = field(default_factory=JudgeConfig)
    detection_strategy: str = "regex_only"  # regex_only | regex_judge | judge_first
    detection_strategy_prompt: str = ""     # per-direction override
    detection_strategy_completion: str = "" # per-direction override
    detection_strategy_tool_call: str = ""  # per-direction override
    judge_sweep: bool = False               # run full judge on no-signal content (regex_judge mode)
    rule_pack_dir: str = ""                 # path to guardrail rule-pack profile directory


@dataclass
class Config:
    data_dir: str = ""
    audit_db: str = ""
    quarantine_dir: str = ""
    plugin_dir: str = ""
    policy_dir: str = ""
    environment: str = ""
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
    webhooks: list[WebhookConfig] = field(default_factory=list)

    # -- Claw-mode path resolution (mirrors claw.go) --

    def claw_home_dir(self) -> str:
        return _expand(self.claw.home_dir)

    def skill_dirs(self) -> list[str]:
        home = self.claw_home_dir()
        dirs: list[str] = []
        oc = _read_openclaw_config(self.claw.config_file)
        workspace = os.path.join(home, "workspace")
        if oc:
            ws = oc.get("agents", {}).get("defaults", {}).get("workspace", "")
            if ws:
                workspace = _expand(ws)
            dirs.append(os.path.join(workspace, "skills"))
            for d in oc.get("skills", {}).get("load", {}).get("extraDirs", []):
                dirs.append(_expand(d))
        else:
            dirs.append(os.path.join(workspace, "skills"))
        dirs.append(os.path.join(home, "skills"))
        return _dedup(dirs)

    def plugin_dirs(self) -> list[str]:
        """Return plugin directories for the active claw mode.

        For OpenClaw, plugins (extensions) live under claw_home/extensions.
        """
        home = self.claw_home_dir()
        return [os.path.join(home, "extensions")]

    def mcp_servers(self) -> list[MCPServerEntry]:
        """Return MCP servers from openclaw.json mcp.servers.

        Tries ``openclaw config get mcp.servers`` first (safe, schema-
        validated).  Falls back to reading the file directly when the CLI
        is unavailable or returns an error (OpenClaw < 2026.3.24).
        """
        servers = _read_mcp_servers_via_cli()
        if servers is not None:
            return servers
        return _read_mcp_servers_from_file(self.claw.config_file)

    def installed_skill_candidates(self, skill_name: str) -> list[str]:
        name = skill_name
        if "/" in name:
            name = name.rsplit("/", 1)[-1]
        name = name.lstrip("@")
        return [os.path.join(d, name) for d in self.skill_dirs()]

    def save(self) -> None:
        path = os.path.join(self.data_dir, CONFIG_FILE_NAME)
        data = _config_to_dict(self)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_openclaw_config(config_file: str) -> dict[str, Any] | None:
    path = _expand(config_file)
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _read_mcp_servers_via_cli() -> list[MCPServerEntry] | None:
    """Read mcp.servers via ``openclaw config get``.  Returns None on failure."""
    try:
        prefix = openclaw_cmd_prefix()
        result = subprocess.run(
            [*prefix, openclaw_bin(), "config", "get", "mcp.servers"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return None
        return _parse_mcp_servers_json(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _read_mcp_servers_from_file(config_file: str) -> list[MCPServerEntry]:
    """Fallback: parse mcp.servers directly from openclaw.json."""
    path = _expand(config_file)
    try:
        with open(path) as f:
            raw = f.read()
    except OSError:
        return []

    data: dict[str, Any] | None = None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        try:
            import json5  # type: ignore[import-untyped]
            data = json5.loads(raw)
        except Exception:
            return []

    if not isinstance(data, dict):
        return []

    servers = data.get("mcp", {}).get("servers")
    if not isinstance(servers, dict):
        return []

    return _parse_mcp_servers_dict(servers)


def _parse_mcp_servers_json(text: str) -> list[MCPServerEntry]:
    text = text.strip()
    if not text:
        return []
    try:
        servers = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(servers, dict):
        return []
    return _parse_mcp_servers_dict(servers)


def _parse_mcp_servers_dict(servers: dict[str, Any]) -> list[MCPServerEntry]:
    entries: list[MCPServerEntry] = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        entries.append(MCPServerEntry(
            name=name,
            command=cfg.get("command", ""),
            args=cfg.get("args", []),
            env=cfg.get("env", {}),
            url=cfg.get("url", ""),
            transport=cfg.get("transport", ""),
        ))
    return entries


def _dedup(paths: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _config_to_dict(cfg: Config) -> dict[str, Any]:
    """Serialize Config to a dict suitable for YAML."""
    from dataclasses import asdict
    d = asdict(cfg)
    gw = d.get("gateway")
    if gw and not gw.get("token"):
        gw.pop("token", None)
    return d


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
        model=raw.get("model", ""),
        api_key_env=raw.get("api_key_env", ""),
        api_base=raw.get("api_base", ""),
        timeout=raw.get("timeout", 30.0),
        fallbacks=raw.get("fallbacks", []),
        adjudication_timeout=raw.get("adjudication_timeout", 5.0),
    )


def _merge_guardrail(raw: dict[str, Any] | None, data_dir: str) -> GuardrailConfig:
    if not raw:
        return GuardrailConfig()
    return GuardrailConfig(
        enabled=raw.get("enabled", False),
        mode=raw.get("mode", "observe"),
        scanner_mode=raw.get("scanner_mode", "both"),
        host=raw.get("host", "localhost"),
        port=raw.get("port", 4000),
        model=raw.get("model", ""),
        model_name=raw.get("model_name", ""),
        api_key_env=raw.get("api_key_env", ""),
        original_model=raw.get("original_model", ""),
        block_message=raw.get("block_message", ""),
        api_base=raw.get("api_base", ""),
        judge=_merge_judge(raw.get("judge")),
        detection_strategy=raw.get("detection_strategy", "regex_only"),
        detection_strategy_prompt=raw.get("detection_strategy_prompt", ""),
        detection_strategy_completion=raw.get("detection_strategy_completion", ""),
        detection_strategy_tool_call=raw.get("detection_strategy_tool_call", ""),
        judge_sweep=raw.get("judge_sweep", False),
        rule_pack_dir=raw.get("rule_pack_dir", ""),
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
            analyzers=raw.get("analyzers", "yara"),
            scan_prompts=raw.get("scan_prompts", False),
            scan_resources=raw.get("scan_resources", False),
            scan_instructions=raw.get("scan_instructions", False),
        )
    return MCPScannerConfig()


def _merge_otel(raw: dict[str, Any] | None) -> OTelConfig:
    if not raw:
        return OTelConfig()
    traces_raw = raw.get("traces", {})
    logs_raw = raw.get("logs", {})
    metrics_raw = raw.get("metrics", {})
    batch_raw = raw.get("batch", {})
    tls_raw = raw.get("tls", {})
    resource_raw = raw.get("resource", {})
    return OTelConfig(
        enabled=raw.get("enabled", False),
        protocol=raw.get("protocol", "grpc"),
        endpoint=raw.get("endpoint", ""),
        headers=raw.get("headers", {}),
        tls=OTelTLSConfig(
            insecure=tls_raw.get("insecure", False),
            ca_cert=tls_raw.get("ca_cert", ""),
        ),
        traces=OTelTracesConfig(
            enabled=traces_raw.get("enabled", True),
            sampler=traces_raw.get("sampler", "always_on"),
            sampler_arg=traces_raw.get("sampler_arg", "1.0"),
            endpoint=traces_raw.get("endpoint", ""),
            protocol=traces_raw.get("protocol", ""),
            url_path=traces_raw.get("url_path", ""),
        ),
        logs=OTelLogsConfig(
            enabled=logs_raw.get("enabled", True),
            emit_individual_findings=logs_raw.get("emit_individual_findings", False),
            endpoint=logs_raw.get("endpoint", ""),
            protocol=logs_raw.get("protocol", ""),
            url_path=logs_raw.get("url_path", ""),
        ),
        metrics=OTelMetricsConfig(
            enabled=metrics_raw.get("enabled", True),
            export_interval_s=metrics_raw.get("export_interval_s", 60),
            endpoint=metrics_raw.get("endpoint", ""),
            protocol=metrics_raw.get("protocol", ""),
            url_path=metrics_raw.get("url_path", ""),
        ),
        batch=OTelBatchConfig(
            max_export_batch_size=batch_raw.get("max_export_batch_size", 512),
            scheduled_delay_ms=batch_raw.get("scheduled_delay_ms", 5000),
            max_queue_size=batch_raw.get("max_queue_size", 2048),
        ),
        resource=OTelResourceConfig(
            attributes=resource_raw.get("attributes", {}),
        ),
    )


def _merge_webhooks(raw: list[dict[str, Any]] | None) -> list[WebhookConfig]:
    if not raw:
        return []
    webhooks: list[WebhookConfig] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        webhooks.append(WebhookConfig(
            url=entry.get("url", ""),
            type=entry.get("type", "generic"),
            secret_env=entry.get("secret_env", ""),
            room_id=entry.get("room_id", ""),
            min_severity=entry.get("min_severity", "HIGH"),
            events=entry.get("events", []),
            timeout_seconds=entry.get("timeout_seconds", 10),
            cooldown_seconds=entry.get("cooldown_seconds", 300),
            enabled=entry.get("enabled", False),
        ))
    return webhooks


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


def _warn_plaintext_secrets(cfg: Config) -> None:
    """Emit deprecation warnings for plain-text secrets in config.yaml."""
    def _warn(section: str, field: str, env_default: str) -> None:
        _log.warning(
            "%s.%s contains a plain-text secret in config.yaml — "
            "migrate it to ~/.defenseclaw/.env as %s and set %s.%s_env=%s instead",
            section, field, env_default, section, field, env_default,
        )
    if cfg.inspect_llm.api_key:
        _warn("inspect_llm", "api_key", "LLM_API_KEY")
    if cfg.cisco_ai_defense.api_key:
        _warn("cisco_ai_defense", "api_key", "CISCO_AI_DEFENSE_API_KEY")
    if cfg.scanners.skill_scanner.virustotal_api_key:
        _warn("scanners.skill_scanner", "virustotal_api_key", "VIRUSTOTAL_API_KEY")
    if cfg.splunk.hec_token:
        _warn("splunk", "hec_token", "DEFENSECLAW_SPLUNK_HEC_TOKEN")


def load() -> Config:
    """Load config from ~/.defenseclaw/config.yaml, applying defaults."""
    data_dir = str(default_data_path())
    _load_dotenv_into_os(data_dir)
    cfg_file = os.path.join(data_dir, CONFIG_FILE_NAME)

    raw: dict[str, Any] = {}
    try:
        with open(cfg_file) as f:
            raw = yaml.safe_load(f) or {}
    except OSError:
        pass

    scanners_raw = raw.get("scanners", {})
    ss_raw = scanners_raw.get("skill_scanner", {})
    gw_raw = raw.get("gateway", {})
    splunk_raw = raw.get("splunk", {})

    cfg = Config(
        data_dir=raw.get("data_dir", data_dir),
        audit_db=raw.get("audit_db", os.path.join(data_dir, AUDIT_DB_NAME)),
        quarantine_dir=raw.get("quarantine_dir", os.path.join(data_dir, "quarantine")),
        plugin_dir=raw.get("plugin_dir", os.path.join(data_dir, "plugins")),
        policy_dir=raw.get("policy_dir", os.path.join(data_dir, "policies")),
        environment=raw.get("environment", detect_environment()),
        claw=ClawConfig(
            mode=raw.get("claw", {}).get("mode", "openclaw"),
            home_dir=raw.get("claw", {}).get("home_dir", "~/.openclaw"),
            config_file=raw.get("claw", {}).get("config_file", "~/.openclaw/openclaw.json"),
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
                virustotal_api_key=ss_raw.get("virustotal_api_key", ""),
                virustotal_api_key_env=ss_raw.get("virustotal_api_key_env", ""),
            ),
            mcp_scanner=_merge_mcp_scanner(scanners_raw.get("mcp_scanner")),
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
            verify_tls=splunk_raw.get("verify_tls", False),
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
            watcher=_merge_gateway_watcher(gw_raw.get("watcher")),
        ),
        skill_actions=_merge_skill_actions(raw.get("skill_actions")),
        mcp_actions=_merge_mcp_actions(raw.get("mcp_actions")),
        plugin_actions=_merge_plugin_actions(raw.get("plugin_actions")),
        webhooks=_merge_webhooks(raw.get("webhooks")),
    )
    _warn_plaintext_secrets(cfg)
    return cfg


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
        scanners=ScannersConfig(
            codeguard=os.path.join(data_dir, "codeguard-rules"),
        ),
        firewall=FirewallConfig(
            config_file=os.path.join(data_dir, "firewall.yaml"),
            rules_file=os.path.join(data_dir, "firewall.pf.conf"),
        ),
        guardrail=GuardrailConfig(),
        gateway=GatewayConfig(
            device_key_file=os.path.join(data_dir, "device.key"),
        ),
    )
