"""Until 1.1, older config files naming removed connectors still load."""

import copy

import pytest
import yaml
from defenseclaw import config


@pytest.fixture(autouse=True)
def _fresh_retired_settings_warning():
    warned = getattr(config, "_retired_settings_warned", None)
    if warned is not None:
        warned.clear()
    yield
    if warned is not None:
        warned.clear()


@pytest.mark.parametrize("version", (8, 9))
def test_retired_connector_roster_loads_with_remaining_peer(tmp_path, caplog, version):
    (tmp_path / "config.yaml").write_text(
        f"config_version: {version}\n"
        "guardrail:\n"
        "  connector: openhands\n"
        "  connectors:\n"
        "    openhands: {}\n"
        "    codex: {}\n"
        "claw:\n"
        "  mode: omnigent\n",
        encoding="utf-8",
    )

    loaded = config.load(data_dir=tmp_path)

    assert loaded.active_connectors() == ["codex"]
    assert loaded.guardrail.connector == "codex"
    assert loaded.claw.mode == ""
    assert f"{tmp_path / 'config.yaml'} still names OpenHands/OmniGent" in caplog.text
    loaded.save()
    persisted = (tmp_path / "config.yaml").read_text(encoding="utf-8").lower()
    assert "openhands" not in persisted
    assert "omnigent" not in persisted


def test_retired_connector_nested_policy_keys_are_dropped():
    raw = {
        "asset_policy": {"connectors": {"Open_Hands": {"mode": "action"}, "codex": {}}},
        "application_protection": {"include_connectors": ["omnigent", "codex"]},
        "guardrail": {"profiles": {"workers": {"connectors": {"openhands": {}, "codex": {}}}}},
    }

    config._drop_retired_connector_settings(raw)

    assert raw["asset_policy"]["connectors"] == {"codex": {}}
    assert raw["application_protection"]["include_connectors"] == ["codex"]
    assert raw["guardrail"]["profiles"]["workers"]["connectors"] == {"codex": {}}


def test_retired_connector_only_roster_loads_as_unconfigured(tmp_path):
    (tmp_path / "config.yaml").write_text(
        "config_version: 8\n"
        "guardrail:\n  connector: openhands\n  connectors:\n    openhands: {}\n"
        "claw:\n  mode: omnigent\n",
        encoding="utf-8",
    )

    loaded = config.load(data_dir=tmp_path)

    assert loaded.active_connectors() == []
    assert not loaded.has_connector_configured()


def test_retired_connector_only_allow_lists_stay_restrictive():
    raw = {
        "application_protection": {"enabled": True, "include_connectors": ["openhands"]},
        "openshell": {
            "enabled": True,
            "harnesses": ["omnigent"],
            "admin": {"allowed_harnesses": ["openhands"]},
        },
        "guardrail": {
            "profiles": {"workers": {"sandbox": {"allowed_harnesses": ["omnigent"]}}},
            "profile_assignments": [{"profile": "workers", "match": {"connectors": ["openhands"]}}],
        },
    }

    config._drop_retired_connector_settings(raw)

    assert raw["application_protection"]["enabled"] is False
    assert raw["openshell"]["enabled"] is False
    assert raw["openshell"]["admin"]["allowed"] is False
    assert raw["guardrail"]["profiles"]["workers"]["sandbox"]["allowed"] is False
    assert raw["guardrail"]["profile_assignments"] == []


def test_retired_connector_v8_routes_drop_retired_only_and_keep_mixed(tmp_path):
    from defenseclaw.observability.v8_config import load_validate_v8

    (tmp_path / "config.yaml").write_text(
        "config_version: 8\n"
        "guardrail:\n"
        "  connector: codex\n"
        "  connectors:\n"
        "    codex: {}\n"
        "observability:\n"
        "  destinations:\n"
        "    - name: console\n"
        "      kind: console\n"
        "      routes:\n"
        "        - {name: retired-only, signals: [logs], selector: {connectors: [openhands]}}\n"
        "        - {name: mixed, signals: [logs], selector: {connectors: [omnigent, codex]}}\n"
        "        - {name: openhands-named, signals: [logs], selector: {connectors: [codex]}}\n",
        encoding="utf-8",
    )

    loaded = config.load(data_dir=tmp_path)
    loaded.save()

    saved = (tmp_path / "config.yaml").read_bytes()
    load_validate_v8(saved)
    routes = yaml.safe_load(saved)["observability"]["destinations"][0]["routes"]
    assert [route["name"] for route in routes] == ["mixed", "openhands-named"]
    assert routes[0]["selector"]["connectors"] == ["codex"]


def test_retired_connector_cleanup_keeps_values_outside_connector_fields():
    raw = {
        "skill_actions": {"allowed": ["openhands"]},
        "mcp": {"servers": {"openhands": {"command": "npx"}}},
        "asset_policy": {"mcp": {"allowed": [{"name": "omnigent"}]}},
        "observability": {
            "destinations": [{"name": "openhands", "routes": [{"name": "omnigent", "selector": {"connectors": ["codex"]}}]}],
        },
        "guardrail": {"connector": "codex", "connectors": {"codex": {}}},
    }
    before = copy.deepcopy(raw)

    config._drop_retired_connector_settings(raw)

    assert raw == before


def test_retired_connector_only_profile_assignment_is_dropped_even_with_other_matchers():
    # An emptied connectors list would match every connector of the group.
    raw = {
        "guardrail": {
            "profile_assignments": [
                {"profile": "strict", "match": {"groups": ["eng"], "connectors": ["openhands"]}},
                {"profile": "strict", "match": {"groups": ["eng"], "connectors": ["omnigent", "codex"]}},
                {"profile": "strict", "match": {"groups": ["ops"]}},
            ]
        }
    }

    config._drop_retired_connector_settings(raw)

    assert raw["guardrail"]["profile_assignments"] == [
        {"profile": "strict", "match": {"groups": ["eng"], "connectors": ["codex"]}},
        {"profile": "strict", "match": {"groups": ["ops"]}},
    ]


def test_retired_connector_only_destination_is_dropped_and_save_validates(tmp_path):
    # Every route of "retired-only" was for removed connectors: an emptied
    # routes list fails minItems and no routes would send every signal.
    from defenseclaw.observability.v8_config import load_validate_v8

    (tmp_path / "config.yaml").write_text(
        "config_version: 8\n"
        "guardrail:\n"
        "  connector: codex\n"
        "  connectors:\n"
        "    codex: {}\n"
        "observability:\n"
        "  destinations:\n"
        "    - name: retired-only\n"
        "      kind: console\n"
        "      routes:\n"
        "        - {name: omnigent, signals: [logs], selector: {connectors: [omnigent]}}\n"
        "        - {name: openhands, signals: [logs], selector: {connectors: [Open_Hands]}, action: drop}\n"
        "    - name: mixed\n"
        "      kind: console\n"
        "      routes:\n"
        "        - {name: retired, signals: [logs], selector: {connectors: [openhands]}}\n"
        "        - {name: codex, signals: [logs], selector: {connectors: [codex]}}\n"
        "    - name: everything\n"
        "      kind: console\n",
        encoding="utf-8",
    )

    loaded = config.load(data_dir=tmp_path)
    loaded.save()

    saved = (tmp_path / "config.yaml").read_bytes()
    load_validate_v8(saved)
    destinations = yaml.safe_load(saved)["observability"]["destinations"]
    assert [destination["name"] for destination in destinations] == ["mixed", "everything"]
    assert [route["name"] for route in destinations[0]["routes"]] == ["codex"]
    assert "routes" not in destinations[1]


_PROFILE_SANDBOXES = (
    "  profiles:\n"
    "    workers:\n"
    "      sandbox:\n"
    "        allowed_harnesses: [omnigent]\n"
    "        required_for: [openhands]\n"
    "    mixed:\n"
    "      sandbox:\n"
    "        allowed_harnesses: [omnigent, codex]\n"
    "        required_for: [openhands, codex]\n"
)
_ADMIN_SANDBOX = "openshell:\n  admin:\n    allowed_harnesses: [openhands]\n    required_for: [omnigent]\n"


@pytest.mark.parametrize("where", ("admin", "profiles"))
def test_retired_connector_only_sandbox_lists_are_omitted_and_stay_restrictive(tmp_path, where):
    # The sandbox lists refuse an empty list; an absent key means no
    # constraint, so allowed: false keeps the emptied allow-list closed.
    (tmp_path / "config.yaml").write_text(
        "config_version: 9\n"
        "guardrail:\n"
        "  connector: codex\n"
        "  connectors:\n"
        "    codex: {}\n" + (_PROFILE_SANDBOXES if where == "profiles" else _ADMIN_SANDBOX),
        encoding="utf-8",
    )

    loaded = config.load(data_dir=tmp_path)
    loaded.save()
    config.load(data_dir=tmp_path)

    saved = yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))
    if where == "admin":
        closed = saved["openshell"]["admin"]
    else:
        closed = saved["guardrail"]["profiles"]["workers"]["sandbox"]
        mixed = saved["guardrail"]["profiles"]["mixed"]["sandbox"]
        assert mixed["allowed_harnesses"] == ["codex"]
        assert mixed["required_for"] == ["codex"]
        assert "allowed" not in mixed
    assert closed["allowed"] is False
    assert "allowed_harnesses" not in closed
    assert "required_for" not in closed


def test_retired_connector_load_warning_is_once_named_and_not_the_installer_notice(tmp_path, monkeypatch):
    """GAP-2043: a config the upgrade could not migrate (its folder is not the
    user's) is loaded by later installer steps. The load says once, through
    the module logger (no raw "WARNING:root:" line), which file still names
    them; it does not repeat the installers' removal notice or send the user
    to the migrate that just ran."""
    import subprocess
    import sys

    outside = tmp_path / "outside.yaml"
    outside.write_text(
        "config_version: 9\nguardrail:\n  connectors:\n    openhands: {}\n    codex: {}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("DEFENSECLAW_CONFIG", str(outside))
    script = f"from defenseclaw import config\nfor _ in range(3):\n    config.load(data_dir={str(tmp_path)!r})\n"
    out = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, check=True)
    lines = [line for line in out.stderr.splitlines() if "OpenHands/OmniGent" in line]
    assert lines == [
        f"{outside} still names OpenHands/OmniGent, which DefenseClaw no longer supports; "
        "they are ignored. Delete them from that file."
    ], out.stderr
    assert "WARNING:root" not in out.stderr
    assert "removed in 1.0.5" not in out.stderr
    assert "run defenseclaw migrate" not in out.stderr
