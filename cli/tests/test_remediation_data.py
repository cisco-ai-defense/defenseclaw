"""Remediation tests for hardened bundled data / config / packaging.

Each security finding is verified by reading the shipped file and asserting
that the hardened value is present and the insecure value is gone. A handful
of bundled Python data modules also get focused behaviour tests (they are
data, not importable package modules, so they are loaded directly from disk).
"""

from __future__ import annotations

import importlib.util
import io
import json
import re
import sys
import types
from datetime import UTC, datetime
from pathlib import Path
from urllib import error as urllib_error
from urllib import request as urllib_request

import pytest
import yaml

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback only
    import tomli as tomllib


TESTS_DIR = Path(__file__).resolve().parent
CLI_DIR = TESTS_DIR.parent
REPO_ROOT = CLI_DIR.parent
DATA = CLI_DIR / "defenseclaw" / "_data"
PYPROJECT = REPO_ROOT / "pyproject.toml"

OBS = DATA / "local_observability_stack"
COMPOSE = OBS / "docker-compose.yml"
OTEL = OBS / "otel-collector" / "config.yaml"
OBS_README = OBS / "README.md"
SOURCE_OBS = REPO_ROOT / "bundles" / "local_observability_stack"
SOURCE_COMPOSE = SOURCE_OBS / "docker-compose.yml"

BRIDGE_DIR = DATA / "splunk_local_bridge"
CI_COMPOSE = BRIDGE_DIR / "compose" / "docker-compose.ci.yml"
BRIDGE = BRIDGE_DIR / "bin" / "splunk-claw-bridge"
EXPORTER = BRIDGE_DIR / "s3_exporter" / "export_splunk_to_s3.py"
SPLUNK_DEFAULTS = BRIDGE_DIR / "splunk" / "default.yml"
EXPORT_SEARCH = BRIDGE_DIR / "splunk" / "bin" / "export_search.py"
APP = BRIDGE_DIR / "splunk" / "apps" / "defenseclaw_local_mode"
TELEMETRY = APP / "bin" / "product_telemetry_sender.py"
MACROS = APP / "default" / "macros.conf"
VIEWS = APP / "default" / "data" / "ui" / "views"
CONNECTOR_VIEW = VIEWS / "connector_activity.xml"
RUNS_VIEW = VIEWS / "runs_and_sessions.xml"
SEARCH_VIEW = VIEWS / "search_and_drilldown.xml"

O11Y = DATA / "splunk_o11y_dashboards"
DETECTORS = O11Y / "terraform" / "detectors.tf"
O11Y_README = O11Y / "README.md"

INSTALLER = DATA / "scripts" / "install-openshell-sandbox.sh"

_SECURE_HOST_BIND_PORT = re.compile(
    r"^\$\{(?P<variable>HOST_BIND):-(?P<default>127\.0\.0\.1)\}:"
    r"(?P<host_port>[1-9]\d{0,4}):(?P<container_port>[1-9]\d{0,4})(?:/tcp)?$"
)
_LOCAL_OBSERVABILITY_PORTS: dict[str, tuple[tuple[int, int], ...]] = {
    "otel-collector": ((4317, 4317), (4318, 4318), (8888, 8888), (13133, 13133)),
    "prometheus": ((9090, 9090),),
    "loki": ((3100, 3100),),
    "tempo": ((3200, 3200), (9095, 9095)),
    "grafana": ((3000, 3000),),
}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _load_toml(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def _assert_secure_host_bind_ports(
    compose_text: str,
    *,
    service: str,
    expected_ports: tuple[tuple[int, int], ...],
) -> tuple[str, ...]:
    """Validate every published port for one service as a secure default bind."""
    document = yaml.safe_load(compose_text)
    assert isinstance(document, dict), "Compose document must be a mapping"
    services = document.get("services")
    assert isinstance(services, dict), "Compose services must be a mapping"
    service_config = services.get(service)
    assert isinstance(service_config, dict), f"Compose service {service!r} is missing"
    assert "network_mode" not in service_config, (
        f"Compose service {service!r} must not bypass port publishing with network_mode"
    )
    ports = service_config.get("ports")
    assert isinstance(ports, list), f"Compose service {service!r} ports must be a list"

    observed: list[tuple[int, int]] = []
    entries: list[str] = []
    for entry in ports:
        assert isinstance(entry, str), (
            f"Compose service {service!r} port {entry!r} must use secure short syntax"
        )
        match = _SECURE_HOST_BIND_PORT.fullmatch(entry)
        assert match is not None, (
            f"Compose service {service!r} port {entry!r} must use "
            "${HOST_BIND:-127.0.0.1}:HOST:CONTAINER"
        )
        host_port = int(match.group("host_port"))
        container_port = int(match.group("container_port"))
        assert host_port <= 65535 and container_port <= 65535, (
            f"Compose service {service!r} contains an invalid TCP port"
        )
        observed.append((host_port, container_port))
        entries.append(entry)

    assert sorted(observed) == sorted(expected_ports), (
        f"Compose service {service!r} publishes {observed!r}, expected {expected_ports!r}"
    )
    return tuple(entries)


def _render_host_bind_port(entry: str, host_bind: str | None = None) -> str:
    """Render the strictly validated HOST_BIND subset used by this bundle."""
    match = _SECURE_HOST_BIND_PORT.fullmatch(entry)
    assert match is not None
    address = host_bind or match.group("default")
    return f"{address}:{match.group('host_port')}:{match.group('container_port')}"


def _load_module(name: str, path: Path, stubs: dict[str, types.ModuleType] | None = None):
    for mod_name, mod in (stubs or {}).items():
        sys.modules.setdefault(mod_name, mod)
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------- #
# Local-observability Compose publishing contract
# --------------------------------------------------------------------------- #
def test_local_observability_compose_source_matches_packaged_data() -> None:
    assert COMPOSE.read_bytes() == SOURCE_COMPOSE.read_bytes()


@pytest.mark.parametrize(
    ("service", "expected_ports"),
    _LOCAL_OBSERVABILITY_PORTS.items(),
)
def test_local_observability_ports_use_secure_host_bind_default(
    service: str, expected_ports: tuple[tuple[int, int], ...]
) -> None:
    _assert_secure_host_bind_ports(
        _read(COMPOSE), service=service, expected_ports=expected_ports
    )


@pytest.mark.parametrize(("service", "port"), (("grafana", 3000), ("prometheus", 9090)))
@pytest.mark.parametrize(
    "unsafe_template",
    (
        "127.0.0.1:PORT:PORT",
        "192.0.2.10:PORT:PORT",
        "0.0.0.0:PORT:PORT",
        "[::]:PORT:PORT",
        "PORT:PORT",
        "PORT",
        "${HOST_BIND}:PORT:PORT",
        "${HOST_BIND-127.0.0.1}:PORT:PORT",
        "${HOST_BIND:-}:PORT:PORT",
        "${HOST_BIND:-0.0.0.0}:PORT:PORT",
        "${HOST_BIND:-::}:PORT:PORT",
        "${HOST_BIND:-127.0.0.2}:PORT:PORT",
        "${BIND:-127.0.0.1}:PORT:PORT",
        "${HOST_BIND:-127.0.0.1:PORT:PORT",
        "${HOST_BIND:-127.0.0.1}:PORT",
        "${HOST_BIND:-127.0.0.1}:OTHER:PORT",
        "${HOST_BIND:-127.0.0.1}:PORT:OTHER",
    ),
)
def test_secure_host_bind_rejects_unsafe_or_malformed_mappings(
    service: str, port: int, unsafe_template: str
) -> None:
    other_port = port + 1
    mapping = unsafe_template.replace("PORT", str(port)).replace("OTHER", str(other_port))
    compose = f"services:\n  {service}:\n    ports:\n      - {json.dumps(mapping)}\n"
    with pytest.raises(AssertionError):
        _assert_secure_host_bind_ports(
            compose, service=service, expected_ports=((port, port),)
        )


@pytest.mark.parametrize(("service", "port"), (("grafana", 3000), ("prometheus", 9090)))
def test_secure_host_bind_rejects_host_networking_and_extra_wildcard_publish(
    service: str, port: int
) -> None:
    secure = f"${{HOST_BIND:-127.0.0.1}}:{port}:{port}"
    host_network = (
        f"services:\n  {service}:\n    network_mode: host\n"
        f"    ports:\n      - {json.dumps(secure)}\n"
    )
    duplicate_wildcard = (
        f"services:\n  {service}:\n    ports:\n"
        f"      - {json.dumps(secure)}\n      - \"0.0.0.0:{port}:{port}\"\n"
    )
    unbound_long_syntax = (
        f"services:\n  {service}:\n    ports:\n"
        f"      - target: {port}\n        published: {port}\n"
    )
    for compose in (host_network, duplicate_wildcard, unbound_long_syntax):
        with pytest.raises(AssertionError):
            _assert_secure_host_bind_ports(
                compose, service=service, expected_ports=((port, port),)
            )


def test_host_bind_default_and_documented_manual_override_rendering() -> None:
    compose = _read(COMPOSE)
    rendered_default: set[str] = set()
    rendered_empty: set[str] = set()
    rendered_override: set[str] = set()
    for service, expected_ports in _LOCAL_OBSERVABILITY_PORTS.items():
        entries = _assert_secure_host_bind_ports(
            compose, service=service, expected_ports=expected_ports
        )
        rendered_default.update(_render_host_bind_port(entry) for entry in entries)
        rendered_empty.update(_render_host_bind_port(entry, "") for entry in entries)
        rendered_override.update(
            _render_host_bind_port(entry, "192.0.2.10") for entry in entries
        )

    expected_default = {
        f"127.0.0.1:{host_port}:{container_port}"
        for ports in _LOCAL_OBSERVABILITY_PORTS.values()
        for host_port, container_port in ports
    }
    expected_override = {
        mapping.replace("127.0.0.1", "192.0.2.10") for mapping in expected_default
    }
    assert rendered_default == expected_default
    assert rendered_empty == expected_default
    assert rendered_override == expected_override

    readme = _read(OBS_README)
    assert '$env:HOST_BIND = "192.0.2.10"' in readme
    assert "HOST_BIND=192.0.2.10 docker compose up -d" in readme
    assert "managed controller's loopback enforcement" in readme


# --------------------------------------------------------------------------- #
# F-0561 — local Grafana opens without a login (loopback-only dashboard)
# --------------------------------------------------------------------------- #
def test_f0561_local_grafana_is_loopback_bound_and_loginless() -> None:
    # Operator decision: a login prompt on a localhost-only dashboard is pure
    # friction. The security boundary for this developer-laptop stack is the
    # loopback port bind, NOT a Grafana password. So we assert the dashboard
    # opens with no login (anonymous Admin, login form disabled) AND that the
    # port is published on the loopback default rather than all interfaces.
    text = _read(COMPOSE)
    assert "GF_AUTH_ANONYMOUS_ENABLED=true" in text
    assert "GF_AUTH_DISABLE_LOGIN_FORM=true" in text
    # the loopback bind is what actually protects the stack
    _assert_secure_host_bind_ports(text, service="grafana", expected_ports=((3000, 3000),))
    # no required-password gate (the :? form) and no all-interfaces publish
    assert "GF_SECURITY_ADMIN_PASSWORD=${GF_SECURITY_ADMIN_PASSWORD:?" not in text


# --------------------------------------------------------------------------- #
# F-0562 — local Prometheus admin/remote-write enabled but loopback-bound
# --------------------------------------------------------------------------- #
def test_f0562_local_prometheus_apis_enabled_but_loopback_bound() -> None:
    # The admin + remote-write APIs are useful for local dev; they are kept
    # off the network by the loopback port bind rather than disabled.
    text = _read(COMPOSE)
    assert '"--web.enable-admin-api"' in text
    assert '"--web.enable-remote-write-receiver"' in text
    assert '"--web.enable-lifecycle"' in text
    # the loopback bind is the security boundary, not the absence of the APIs
    _assert_secure_host_bind_ports(
        text, service="prometheus", expected_ports=((9090, 9090),)
    )


# --------------------------------------------------------------------------- #
# F-0563 — OTLP receivers bind container interface, host publish stays loopback
# --------------------------------------------------------------------------- #
def test_f0563_otlp_receiver_accepts_docker_port_forwarding() -> None:
    # Docker's host-side port publish is loopback-bound in docker-compose.yml.
    # Inside the collector container, however, the receiver must bind to the
    # container interface. Binding 127.0.0.1 here makes the host-published
    # 4317/4318 ports accept TCP but never deliver OTLP records to the receiver.
    text = _read(OTEL)
    assert "endpoint: 0.0.0.0:4317" in text
    assert "endpoint: 0.0.0.0:4318" in text
    assert "endpoint: 127.0.0.1:4317" not in text
    assert "endpoint: 127.0.0.1:4318" not in text


# --------------------------------------------------------------------------- #
# F-0581 — Splunk CI ports bind loopback, private env file required
# --------------------------------------------------------------------------- #
def test_f0581_splunk_ci_ports_loopback_and_env_required() -> None:
    text = _read(CI_COMPOSE)
    assert "${SPLUNK_HOST_BIND:-127.0.0.1}:8000:8000" in text
    assert "${SPLUNK_HOST_BIND:-127.0.0.1}:8088:8088" in text
    assert "${SPLUNK_HOST_BIND:-127.0.0.1}:8089:8089" in text
    assert "${SPLUNK_ENV_FILE:?" in text
    # no default publish on all interfaces, no env_file default to public example
    assert '"0.0.0.0:8000:8000"' not in text
    assert "- env/.env.example" not in text


# --------------------------------------------------------------------------- #
# F-0584 — bridge requires an explicit private env file
# --------------------------------------------------------------------------- #
def test_f0584_bridge_requires_explicit_env_file() -> None:
    text = _read(BRIDGE)
    assert 'ENV_FILE="${SPLUNK_ENV_FILE:-}"' in text
    assert "no environment file configured" in text
    # must not silently default to the public example
    assert "${SPLUNK_ENV_FILE:-env/.env.example}" not in text
    assert 'ENV_FILE="env/.env.example"' not in text


# --------------------------------------------------------------------------- #
# F-0585 — exporter has no hardcoded Splunk password
# --------------------------------------------------------------------------- #
def test_f0585_exporter_no_hardcoded_password_string() -> None:
    text = _read(EXPORTER)
    assert 'os.environ.get("SPLUNK_PASSWORD", "")' in text
    assert 'os.environ.get("SPLUNK_PASSWORD", "changeme")' not in text
    assert '"SPLUNK_PASSWORD", "password"' not in text
    # and the CI compose passes the configured credential through
    ci = _read(CI_COMPOSE)
    assert 'SPLUNK_PASSWORD: "${SPLUNK_PASSWORD:?' in ci


# --------------------------------------------------------------------------- #
# F-0601 — Splunk HEC uses TLS and an env-sourced token
# --------------------------------------------------------------------------- #
def test_f0601_hec_ssl_enabled_and_token_from_env() -> None:
    text = _read(SPLUNK_DEFAULTS)
    assert "ssl: true" in text
    assert "ssl: false" not in text
    assert "lookup('env', 'SPLUNK_HEC_TOKEN')" in text


# --------------------------------------------------------------------------- #
# F-0602 — token-bearing telemetry POST refuses redirects
# --------------------------------------------------------------------------- #
def test_f0602_no_redirect_opener_string() -> None:
    text = _read(TELEMETRY)
    assert "_NoRedirectHandler" in text
    assert "_build_no_redirect_opener" in text
    assert "opener.open(req" in text


# --------------------------------------------------------------------------- #
# F-0603 — export_search verifies TLS by default
# --------------------------------------------------------------------------- #
def test_f0603_tls_verified_by_default_string() -> None:
    text = _read(EXPORT_SEARCH)
    assert '"--insecure"' in text
    assert "context = None" in text
    assert "args.insecure" in text


# --------------------------------------------------------------------------- #
# F-0604 — connector token escaped with the |s filter
# --------------------------------------------------------------------------- #
def test_f0604_connector_token_escaped() -> None:
    text = _read(CONNECTOR_VIEW)
    assert "$connector|s$" in text
    assert 'connector="$connector$"' not in text
    assert '"$connector$"' not in text


# --------------------------------------------------------------------------- #
# F-0608 — run_id / session_id escaped in macros + views
# --------------------------------------------------------------------------- #
def test_f0608_run_session_tokens_escaped() -> None:
    macros = _read(MACROS)
    # macro definitions no longer wrap the substituted token in quotes
    assert "run_id=$run_filter$" in macros
    assert 'run_id="$run_filter$"' not in macros
    assert 'session_id="$session_filter$"' not in macros
    for view in (RUNS_VIEW, SEARCH_VIEW):
        text = _read(view)
        assert "$run_id|s$" in text
        assert "$session_id|s$" in text


# --------------------------------------------------------------------------- #
# F-0622 — stalled-exporter detector fires on freshness, not absence
# --------------------------------------------------------------------------- #
def test_f0622_stalled_detector_uses_freshness() -> None:
    text = _read(DETECTORS)
    assert "B = (time() / 1000 - A)" in text
    assert "when(B > 300, '5m')" in text
    assert "when(A is None, '5m')" not in text


# --------------------------------------------------------------------------- #
# F-0623 — README documents the env var, not a CLI token
# --------------------------------------------------------------------------- #
def test_f0623_readme_uses_env_var_not_cli_token() -> None:
    text = _read(O11Y_README)
    assert "SFX_AUTH_TOKEN" in text
    assert "never put the API token on the command line" in text
    # no example passes a literal token placeholder on the CLI
    assert "--o11y-api-token <api-access-token>" not in text


# --------------------------------------------------------------------------- #
# F-0548 — installer verifies an independent pinned checksum before install
# --------------------------------------------------------------------------- #
def test_f0548_installer_verifies_pinned_checksum() -> None:
    text = _read(INSTALLER)
    assert "_sha256()" in text
    assert "EXPECTED_SHA256" in text
    assert "OPENSHELL_SANDBOX_SHA256" in text
    assert "Integrity check failed" in text
    assert "without an independent integrity anchor" in text
    # fail-closed before any blob download, and verify before install
    assert text.index("Refusing to install") < text.index("blobs/${LAYER_DIGEST}")
    assert text.index("ACTUAL_SHA256=") < text.index("install -m 755")


# --------------------------------------------------------------------------- #
# F-0641 — conditional tomli dependency for Python < 3.11
# --------------------------------------------------------------------------- #
def test_f0641_tomli_conditional_dependency() -> None:
    data = _load_toml(PYPROJECT)
    deps = data["project"]["dependencies"]
    assert any(d.startswith("tomli") and "python_version" in d and "3.11" in d for d in deps)


# --------------------------------------------------------------------------- #
# Focused behaviour tests for the bundled Python data modules
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def exporter_module():
    boto3 = types.ModuleType("boto3")
    boto3.client = lambda *args, **kwargs: None  # type: ignore[attr-defined]
    requests = types.ModuleType("requests")
    auth = types.ModuleType("requests.auth")
    auth.HTTPBasicAuth = object  # type: ignore[attr-defined]
    return _load_module(
        "rem_export_splunk_to_s3",
        EXPORTER,
        {"boto3": boto3, "requests": requests, "requests.auth": auth},
    )


@pytest.fixture(scope="module")
def telemetry_module():
    return _load_module("rem_product_telemetry_sender", TELEMETRY)


@pytest.fixture(scope="module")
def export_search_module():
    return _load_module("rem_export_search", EXPORT_SEARCH)


def _make_export_config(exporter, checkpoint: Path):
    return exporter.ExportConfig(
        enabled=True,
        once=True,
        bucket="unused",
        prefix="agentwatch/defenseclaw",
        aws_region="us-west-2",
        endpoint_url=None,
        sse=None,
        splunk_base_url="https://splunk:8089",
        splunk_username="admin",
        splunk_password="secret",
        splunk_verify_tls=False,
        interval_seconds=60,
        window_seconds=300,
        lookback_seconds=30,
        checkpoint_file=checkpoint,
        tenant_id="tenant",
        workspace_id="workspace",
        deployment_environment="local",
    )


def test_f0585_load_config_requires_password(exporter_module, monkeypatch) -> None:
    monkeypatch.setenv("S3_EXPORT_ENABLED", "true")
    monkeypatch.setenv("S3_BUCKET", "bucket")
    monkeypatch.delenv("SPLUNK_PASSWORD", raising=False)
    with pytest.raises(ValueError) as exc:
        exporter_module.load_config()
    assert "SPLUNK_PASSWORD" in str(exc.value)


def test_f0585_load_config_accepts_password(exporter_module, monkeypatch) -> None:
    monkeypatch.setenv("S3_EXPORT_ENABLED", "true")
    monkeypatch.setenv("S3_BUCKET", "bucket")
    monkeypatch.setenv("SPLUNK_PASSWORD", "s3cret")
    config = exporter_module.load_config()
    assert config.splunk_password == "s3cret"


def test_f0805_corrupt_checkpoint_raises(exporter_module, tmp_path) -> None:
    checkpoint = tmp_path / "checkpoint.json"
    checkpoint.write_text("{not-json\n")
    with pytest.raises(exporter_module.CorruptCheckpointError):
        exporter_module.load_checkpoint(checkpoint)


def test_f0805_invalid_shape_raises(exporter_module, tmp_path) -> None:
    checkpoint = tmp_path / "checkpoint.json"
    checkpoint.write_text(json.dumps({"unexpected": "shape"}))
    with pytest.raises(exporter_module.CorruptCheckpointError):
        exporter_module.load_checkpoint(checkpoint)


def test_f0805_missing_checkpoint_is_first_run(exporter_module, tmp_path) -> None:
    assert exporter_module.load_checkpoint(tmp_path / "missing.json") is None


def test_f0805_window_propagates_corruption(exporter_module, tmp_path) -> None:
    checkpoint = tmp_path / "checkpoint.json"
    checkpoint.write_text("{bad")
    config = _make_export_config(exporter_module, checkpoint)
    with pytest.raises(exporter_module.CorruptCheckpointError):
        exporter_module._window_from_checkpoint(config, datetime(2026, 6, 10, 12, 0, tzinfo=UTC))


def test_f0805_valid_checkpoint_window(exporter_module, tmp_path) -> None:
    checkpoint = tmp_path / "checkpoint.json"
    checkpoint.write_text(json.dumps({"latest": "2026-06-01T00:00:00Z"}))
    config = _make_export_config(exporter_module, checkpoint)
    earliest, latest = exporter_module._window_from_checkpoint(
        config, datetime(2026, 6, 10, 12, 0, tzinfo=UTC)
    )
    assert earliest == "2026-05-31T23:59:30Z"
    assert latest == "2026-06-10T12:00:00Z"


def test_f0602_redirect_request_refused(telemetry_module) -> None:
    handler = telemetry_module._NoRedirectHandler()
    req = urllib_request.Request("https://hec.example/services/collector/event")
    with pytest.raises(urllib_error.HTTPError):
        handler.redirect_request(req, io.BytesIO(b""), 302, "Found", {}, "https://evil.example/")


def test_f0603_insecure_defaults_false(export_search_module, monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["export_search.py", "--query", "search index=defenseclaw_local"])
    args = export_search_module.parse_args()
    assert args.insecure is False


def test_f0603_insecure_opt_in(export_search_module, monkeypatch) -> None:
    monkeypatch.setattr(
        sys, "argv", ["export_search.py", "--query", "search index=defenseclaw_local", "--insecure"]
    )
    args = export_search_module.parse_args()
    assert args.insecure is True
