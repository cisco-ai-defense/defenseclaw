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
import sys
import types
from datetime import UTC, datetime
from pathlib import Path
from urllib import error as urllib_error
from urllib import request as urllib_request

import pytest

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


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _load_toml(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


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
    assert "${HOST_BIND:-127.0.0.1}:3000:3000" in text
    # no required-password gate (the :? form) and no all-interfaces publish
    assert "GF_SECURITY_ADMIN_PASSWORD=${GF_SECURITY_ADMIN_PASSWORD:?" not in text
    assert '"0.0.0.0:3000:3000"' not in text


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
    assert "${HOST_BIND:-127.0.0.1}:9090:9090" in text
    assert '"0.0.0.0:9090:9090"' not in text


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
