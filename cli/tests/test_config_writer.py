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

"""The single config writer (config_writer) and Config.save on top of it."""

from __future__ import annotations

import os
import stat

import pytest
import yaml
from defenseclaw import config_writer
from defenseclaw.config import locked_config_yaml
from defenseclaw.config_writer import Change
from defenseclaw.observability.v8_config import V8ConfigError


def _reference_page(name: str) -> str:
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    with open(os.path.join(root, "docs-site", "content", "docs", "reference", name), encoding="utf-8") as stream:
        return stream.read()


def _config(tmp_path, body: str = "") -> str:
    path = tmp_path / "config.yaml"
    path.write_text(f"config_version: 9\ndata_dir: {tmp_path}\n# operator note\n{body}observability: {{}}\n")
    return str(path)


def test_apply_keeps_comments_validates_and_advances_generation(tmp_path, monkeypatch):
    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    path = _config(tmp_path, "guardrail:\n  mode: observe # keep\n")

    first = config_writer.apply([Change("guardrail.mode", "action")], "cli:test", "test", path=path)
    text = open(path, encoding="utf-8").read()
    assert first.generation == 1 and first.changed == ["guardrail.mode"]
    assert "# operator note" in text and "mode: action # keep" in text
    assert config_writer.read_generation_state(path).config_sha256 == first.sha256

    with pytest.raises(config_writer.ConfigConflictError):
        config_writer.apply([Change("guardrail.mode", "observe")], "cli:test", "t", "0" * 64, path=path)
    with pytest.raises(Exception):
        config_writer.apply([Change("guardrail.mode", "bogus")], "cli:test", "t", path=path)
    assert open(path, encoding="utf-8").read() == text

    second = config_writer.apply(
        [Change("gateway.api_port", 18971), Change("guardrail.mode", unset=True)],
        "cli:test",
        "t",
        first.sha256,
        path=path,
    )
    assert second.generation == 2 and second.restart_required == ["gateway.api_port"]
    # A truncated state file keeps its counter: the next write resumes past it.
    with open(config_writer.generation_path(path), "w", encoding="utf-8") as handle:
        handle.write('{"generation": 41, "config_sha')
    third = config_writer.apply([Change("guardrail.mode", "action")], "cli:test", "t", path=path)
    assert third.generation == 42 and config_writer.read_generation_state(path).generation_reset
    # The writer names every key the running gateway applies only on restart.
    assert config_writer.restart_required(
        [
            "guardrail.hook_fail_mode",
            "guardrail.hook_self_heal",
            "guardrail.connectors.codex.enabled",
            "guardrail.connectors.codex.hook_fail_mode",
            "guardrail.block_at",
            "gateway.watcher.enabled",
            "application_protection.connectors.codex.guardrail.block_at",
            "cisco_ai_defense.endpoint",
            "policy_dir",
            "plugin_dir",
        ]
    ) == ["guardrail.hook_self_heal", "plugin_dir"]


def test_unset_removes_a_dependent_pair_in_one_write(tmp_path, monkeypatch):
    # GAP-0084: the digest pins the pack, so each key alone is refused.
    from unittest.mock import patch

    from click.testing import CliRunner
    from defenseclaw.commands import cmd_config

    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    path = _config(
        tmp_path,
        "openshell:\n  admin:\n    required_pack: balanced\n    required_pack_digest: sha256:" + "ab" * 32 + "\n",
    )
    pack, digest = "openshell.admin.required_pack", "openshell.admin.required_pack_digest"
    with (
        patch.object(cmd_config.config_module, "config_path", return_value=tmp_path / "config.yaml"),
        patch("defenseclaw.gateway.local_policy_digest", return_value=None),
    ):
        alone = CliRunner().invoke(cmd_config.config_cmd, ["unset", pack])
        both = CliRunner().invoke(cmd_config.config_cmd, ["unset", pack, digest])
        # GAP-0307: relabelling the file as version 8 would make the next
        # migration overwrite the 0.8.x backup; only the migration sets it.
        relabel = CliRunner().invoke(cmd_config.config_cmd, ["set", "config_version", "8"])
    assert alone.exit_code != 0 and f"config unset {pack} {digest}" in alone.output
    assert both.exit_code == 0, both.output
    assert relabel.exit_code == 1 and "defenseclaw migrate" in relabel.output
    text = open(path, encoding="utf-8").read()
    assert "required_pack" not in text and "config_version: 9" in text


def test_unset_multiple_list_indexes_uses_original_positions(tmp_path, monkeypatch):
    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    path = _config(
        tmp_path,
        "asset_policy:\n  skill:\n    allowed:\n"
        "      - {name: a}\n      - {name: b}\n      - {name: c}\n",
    )
    result = config_writer.apply(
        [Change("asset_policy.skill.allowed[0]", unset=True), Change("asset_policy.skill.allowed[1]", unset=True)],
        "cli:test",
        "t",
        path=path,
    )
    assert result.changed == ["asset_policy.skill.allowed[0]", "asset_policy.skill.allowed[1]"]
    assert yaml.safe_load(open(path, encoding="utf-8"))["asset_policy"]["skill"]["allowed"] == [{"name": "c"}]


def test_set_equal_integer_does_not_bypass_boolean_validation(tmp_path, monkeypatch):
    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    path = _config(tmp_path, "admission:\n  skill:\n    scan_on_install: false\n")
    before = open(path, encoding="utf-8").read()
    with pytest.raises(V8ConfigError):
        config_writer.apply([Change("admission.skill.scan_on_install", 0)], "cli:test", "t", path=path)
    assert open(path, encoding="utf-8").read() == before


def test_removed_scanner_keys_are_ignored_on_load_and_refused_by_config_set(tmp_path, monkeypatch):
    # GAP-0295/GAP-0301: no scan read scanners.mcp_scanner.api or .timeouts
    # or skill_scanner.timeouts.llm_s. A file a pre-release build wrote with
    # them still validates and takes writes; config set refuses them.
    from unittest.mock import patch

    from click.testing import CliRunner
    from defenseclaw.commands import cmd_config
    from defenseclaw.observability.v8_config import validate_v8_source

    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    path = _config(
        tmp_path,
        "scanners:\n  skill_scanner:\n    timeouts: {scan_s: 600, llm_s: 60}\n"
        "  mcp_scanner:\n    api: {endpoint: https://aid.example.test}\n    timeouts: {remote_s: 5}\n",
    )
    validate_v8_source(open(path, encoding="utf-8").read())
    with (
        patch.object(cmd_config.config_module, "config_path", return_value=tmp_path / "config.yaml"),
        patch("defenseclaw.gateway.local_policy_digest", return_value=None),
    ):
        refused = CliRunner().invoke(cmd_config.config_cmd, ["set", "scanners.mcp_scanner.timeouts.remote_s", "9"])
        written = CliRunner().invoke(cmd_config.config_cmd, ["set", "guardrail.mode", "action"])
    assert refused.exit_code == 1 and "no scan read it" in refused.output, refused.output
    assert written.exit_code == 0, written.output
    assert "remote_s: 9" not in open(path, encoding="utf-8").read()


def test_a_field_of_an_unlisted_destination_names_the_range(tmp_path, monkeypatch):
    # GAP-0154: set indexes the destinations written in config.yaml, as get does.
    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    path = _config(tmp_path)
    before = open(path, encoding="utf-8").read()
    with pytest.raises(config_writer.ConfigWriteError, match=r"index is out of range \(config.yaml lists 0 destinations\)"):
        config_writer.apply([Change("observability.destinations[1].enabled", False)], "cli:test", "t", path=path)
    assert open(path, encoding="utf-8").read() == before


def test_every_write_re_renders_custom_providers_from_llm_providers(tmp_path, monkeypatch):
    import json

    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    path = _config(tmp_path)
    entry = {"name": "custom-gateway", "domains": ["llm.example.internal"], "env_keys": ["LLM_GATEWAY"]}
    config_writer.apply([Change("llm_providers.custom", [entry])], "cli:test", "t", path=path)
    overlay = json.loads((tmp_path / "custom-providers.json").read_text(encoding="utf-8"))
    assert overlay["_derived_from"] and [p["name"] for p in overlay["providers"]] == ["custom-gateway"]


def test_writer_refuses_local_actors_on_a_standalone_managed_device(tmp_path, monkeypatch):
    path = _config(tmp_path)
    (tmp_path / config_writer.MANAGED_RUNTIME_DESCRIPTOR).write_text("{}")
    tmp_path.chmod(0o755)
    monkeypatch.setenv("DEFENSECLAW_DEPLOYMENT_MODE", "managed_enterprise")
    monkeypatch.setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "standalone")
    with pytest.raises(config_writer.ManagedConfigWriteError):
        config_writer.apply([Change("guardrail.mode", "action")], "cli:test", "t", path=path)
    with pytest.raises(config_writer.ManagedConfigWriteError):
        with locked_config_yaml(path):
            pass
    with pytest.raises(FileNotFoundError):
        config_writer.read_generation_state(path)
    # A refusal leaves nothing behind: no lock file (GAP-0171), and the
    # lifecycle's folder keeps its mode, because every user's hook reads it.
    assert not os.path.lexists(path + config_writer.LOCK_SUFFIX)
    if os.name != "nt":
        assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o755


def test_machine_marker_makes_a_standard_users_writers_managed(tmp_path, monkeypatch):
    # A standard user's per-user config says nothing about the host: the
    # machine marker the enterprise lifecycle publishes decides.
    from defenseclaw import upgrade_shim
    from defenseclaw.config import default_config
    from defenseclaw.enforce import asset_lists

    path = _config(tmp_path)
    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    monkeypatch.setattr(upgrade_shim, "managed_deployment", lambda: "standalone")
    with pytest.raises(config_writer.ManagedConfigWriteError):
        config_writer.apply([Change("guardrail.mode", "action")], "cli:test", "t", path=path)
    with pytest.raises(asset_lists.ManagedDeviceError):
        asset_lists.refuse_if_managed(default_config(), target_type="skill", op=asset_lists.OP_BLOCK, name="x")
    config_writer.apply([Change("guardrail.mode", "action")], config_writer.ACTOR_LIFECYCLE, "t", path=path)


def test_a_managed_device_without_a_user_config_is_not_told_to_run_init(tmp_path, monkeypatch):
    # GAP-0172: a standard user with no per-user config was sent to init, whose
    # wizard would create a config the device ignores.
    from click.testing import CliRunner
    from defenseclaw import upgrade_shim
    from defenseclaw.main import cli

    home = tmp_path / ".defenseclaw"
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    monkeypatch.setattr(upgrade_shim, "managed_deployment", lambda: "standalone")
    from defenseclaw.enforce import asset_lists

    audited: list[tuple[str, str, str]] = []
    monkeypatch.setattr(asset_lists, "audit_managed_refusal", lambda *row: audited.append(row))
    for argv in (
        ["skill", "block", "x"],
        ["guardrail", "protection", "enable", "x"],
        ["setup", "codex", "--yes"],
        ["init"],
        # GAP-0215: the connector flags reach the first-run steps, which printed tracebacks.
        ["quickstart", "--connector", "claudecode", "--skip-gateway"],
        # GAP-0172: doctor said "not initialized, run init" on a managed device.
        ["doctor"],
    ):
        monkeypatch.setattr("sys.argv", ["defenseclaw", *argv])
        result = CliRunner().invoke(cli, argv)
        assert result.exit_code == 3, (argv, result.output)
        assert "This device is managed" in result.output and "run 'defenseclaw init'" not in result.output
    # GAP-0205: the refused writers leave the audit row an initialized user's refusal leaves.
    assert audited == [
        ("skill-block", "x", "type=skill"),
        ("action", "guardrail protection enable", "command=guardrail protection enable"),
    ]
    # config get names no init step either (it has no write to refuse, so exit 1).
    result = CliRunner().invoke(cli, ["config", "get", "guardrail.mode", "--effective"])
    assert "device is managed" in result.output and "defenseclaw init" not in result.output
    # GAP-0207: config show prints the built-in defaults, so it says they are not what is enforced.
    result = CliRunner().invoke(cli, ["config", "show", "--section", "guardrail"])
    assert "gateway enforces the administrator's config" in result.output
    assert not home.exists()


def test_a_refusal_is_audited_when_the_command_has_no_logger(monkeypatch):
    # `config` skips the startup load, so the refusal opens its own logger.
    from unittest.mock import MagicMock

    import click
    from defenseclaw import config as config_module
    from defenseclaw import logger as logger_module
    from defenseclaw.context import AppContext
    from defenseclaw.enforce import asset_lists

    audit = MagicMock()
    monkeypatch.setattr(config_module, "load", lambda: object())
    monkeypatch.setattr(logger_module.Logger, "from_config", staticmethod(lambda _cfg: audit))
    with click.Context(click.Command("set"), obj=AppContext()):
        asset_lists.audit_managed_config_refusal("guardrail.mode", "config set")
    # Not config-update: the gateway would record that as an applied change.
    audit.log_action.assert_called_once_with(
        "action", "guardrail.mode", "outcome=refused reason=managed_device command=config set"
    )


@pytest.mark.skipif(os.name == "nt", reason="the managed gateway hook socket is a Unix socket")
def test_a_standard_users_refusal_goes_to_the_managed_gateway_hook_socket(monkeypatch):
    # A standard user holds no gateway token, so its refusal is reported over
    # the managed gateway hook socket, which names the caller from the kernel.
    import http.server
    import json
    import socketserver
    import tempfile
    import threading
    from unittest.mock import MagicMock

    import click
    from defenseclaw.enforce import asset_lists

    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            received.append((self.path, json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *args):
            pass

    with tempfile.TemporaryDirectory(dir="/tmp") as folder:
        path = os.path.join(folder, "hook.sock")
        server = socketserver.UnixStreamServer(path, Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            monkeypatch.setattr(asset_lists, "_managed_hook_socket", lambda: path)
            logger = MagicMock()
            with click.Context(click.Command("block"), obj=MagicMock(logger=logger)):
                asset_lists.audit_managed_refusal("skill-block", "p0-test-skill", "type=skill")
        finally:
            server.shutdown()
            server.server_close()
    assert received == [
        (asset_lists.MANAGED_REFUSAL_PATH, {"action": "skill-block", "target": "p0-test-skill", "details": "type=skill"})
    ]
    logger.log_action.assert_not_called()
@pytest.mark.skipif(os.name == "nt", reason="POSIX directory modes")
def test_managed_refusal_leaves_the_config_directory_and_lock_alone(tmp_path, monkeypatch):
    path = _config(tmp_path)
    tmp_path.chmod(0o755)
    monkeypatch.setenv("DEFENSECLAW_DEPLOYMENT_MODE", "managed_enterprise")
    monkeypatch.setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "standalone")
    with pytest.raises(config_writer.ManagedConfigWriteError):
        config_writer.apply([Change("guardrail.mode", "action")], "cli:test", "t", path=path)
    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o755
    assert not os.path.exists(path + ".lock")


def test_failed_generation_record_restores_the_previous_config(tmp_path, monkeypatch):
    path = _config(tmp_path, "guardrail:\n  mode: observe\n")
    before = open(path, "rb").read()
    verified: list[str] = []

    def no_space(*_args, **_kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(config_writer, "record_generation", no_space)
    with pytest.raises(OSError):
        config_writer.write_with(
            lambda current, _name: (current.replace(b"observe", b"action"), ["guardrail.mode"]),
            "cli:test",
            "t",
            path=path,
            verify=verified.append,
        )
    assert open(path, "rb").read() == before
    assert not verified


def test_config_save_goes_through_the_writer(tmp_path, monkeypatch):
    from defenseclaw import config as config_module

    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    path = _config(tmp_path, "guardrail:\n  mode: observe # keep\n")
    cfg = config_module.load(data_dir=str(tmp_path))
    cfg.guardrail.mode = "action"

    result = cfg.save()

    assert result.generation == 1 and result.changed == ["guardrail.mode"]
    assert "mode: action # keep" in open(path, encoding="utf-8").read()


def test_verified_noop_rejects_a_concurrent_registry_policy_change(tmp_path, monkeypatch):
    from defenseclaw import config as config_module
    from defenseclaw.registry_policy import RegistryRequiredUpdateError, set_registry_required

    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    path = _config(tmp_path, "asset_policy:\n  skill:\n    registry_required: true\n")
    stale = config_module.load(data_dir=str(tmp_path))
    changed = config_writer.apply(
        [Change("asset_policy.skill.registry_required", False)],
        "cli:other",
        "concurrent policy update",
        path=path,
    )

    with pytest.raises(RegistryRequiredUpdateError, match="persisted global"):
        set_registry_required(stale, "skill", True)

    assert config_module.load(data_dir=str(tmp_path)).asset_policy.skill.registry_required is False
    assert config_writer.read_generation_state(path).generation == changed.generation


def test_operator_block_from_a_stale_config_keeps_a_concurrent_block(tmp_path, monkeypatch):
    # Two processes load the same config, then each blocks a different skill:
    # the second write is made against the file on disk, so both stay blocked.
    from defenseclaw import config as config_module
    from defenseclaw.enforce import asset_lists

    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    _config(tmp_path)
    first = config_module.load(data_dir=str(tmp_path))
    second = config_module.load(data_dir=str(tmp_path))

    for cfg, name in ((first, "evil-a"), (second, "evil-b")):
        asset_lists.write_operator_decision(cfg, op=asset_lists.OP_BLOCK, target_type="skill", name=name)

    on_disk = config_module.load(data_dir=str(tmp_path)).asset_policy.skill.denied
    assert [rule.name for rule in on_disk] == ["evil-a", "evil-b"]
    # GAP-0060: the file holds the two names, not the default asset_policy tree or empty rule fields.
    written = yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))["asset_policy"]
    assert written == {"skill": {"denied": [{"name": "evil-a"}, {"name": "evil-b"}]}}

    # Names match case-insensitively, as the readers match them: an unblock
    # in another case finds and removes the rule (GAP-0319).
    cfg = config_module.load(data_dir=str(tmp_path))
    assert asset_lists.has_entry(cfg, None, "skill", "EVIL-A", "", "block")
    asset_lists.write_operator_decision(cfg, op=asset_lists.OP_UNBLOCK, target_type="skill", name="EVIL-A")
    on_disk = config_module.load(data_dir=str(tmp_path)).asset_policy.skill.denied
    assert [rule.name for rule in on_disk] == ["evil-b"]


def test_plain_error_names_the_key_without_the_validator_internals():
    """GAP-0050: a refused change says the key and the fix, not the JSON path, the bracketed code or the schema."""
    from defenseclaw.config_inspect import ConfigInspectError
    from defenseclaw.observability.v8_config import V8ConfigError

    reason = (
        '[config_semantic_invalid] config rule pack "/home/u/marker": guardrail.rules.enable: unknown rule NOPE-X; '
        "expected rule packs, custom pack digests and rule IDs the gateway can load; fix the reference, then retry"
    )
    inspected = ConfigInspectError(f"candidate field=$.guardrail; reason={reason}", field_path="$.guardrail", reason=reason)
    rejected = config_writer.ConfigWriteError(f"config.yaml change rejected: {inspected}")
    rejected.__cause__ = inspected
    assert config_writer.plain_error(rejected) == "guardrail.rules.enable: unknown rule NOPE-X. Fix the reference, then retry."

    # GAP-0261: the way out of a deleted pack folder is named, since each single change is refused meanwhile.
    gone = (
        '[config_semantic_invalid] config rule pack "/home/u/marker": rule pack directory_not_found at .: '
        "rule-pack directory does not exist; fix the reference, then retry"
    )
    missing = ConfigInspectError(f"candidate field=$.guardrail; reason={gone}", field_path="$.guardrail", reason=gone)
    refused = config_writer.ConfigWriteError("config.yaml change rejected")
    refused.__cause__ = missing
    assert config_writer.plain_error(refused).endswith(
        "To stop using the deleted pack: defenseclaw guardrail use-pack default."
    )

    pattern = V8ConfigError("config.yaml", "$.guardrail.custom_packs.bad.digest", "pattern", "correct the field using the configuration schema and reference")
    assert config_writer.plain_error(pattern) == (
        "guardrail.custom_packs.bad.digest is not in the expected format (sha256: followed by 64 hex digits)."
    )
    block_at = V8ConfigError("config.yaml", "$.guardrail.block_at", "pattern", "use one of CRITICAL, HIGH, MEDIUM, LOW in any case (empty inherits)")
    assert config_writer.plain_error(block_at) == (
        "guardrail.block_at is not in the expected format. Use one of CRITICAL, HIGH, MEDIUM, LOW in any case (empty inherits)."
    )
    other = V8ConfigError("config.yaml", "$.gateway.api_port", "type", "use the value type documented by the configuration schema")
    assert "configuration schema" not in config_writer.plain_error(other)

    # The CLI reference quotes this message for a rejected `config set`.
    shown = f"Error: config.yaml was not changed: {config_writer.plain_error(block_at)}\n"
    assert shown in _reference_page("cli.mdx")


def test_plain_error_reports_length_and_write_directory() -> None:
    import errno

    from defenseclaw.observability.v8_config import V8ConfigError

    too_long = V8ConfigError("config.yaml", "$.guardrail.block_message", "maxLength", "check the value")
    assert config_writer.plain_error(too_long, value="B" * 5000) == (
        "guardrail.block_message is longer than 4096 characters (it has 5000)"
    )
    denied = OSError(errno.EACCES, "Permission denied", "/home/u/.defenseclaw/.config.yaml.candidate-abc.yaml")
    assert config_writer.plain_error(denied) == "cannot write in /home/u/.defenseclaw: permission denied"


def test_edited_pack_error_names_narrow_repin():
    from defenseclaw.config_inspect import ConfigInspectError

    reason = (
        "[config_semantic_invalid] config rule pack \"custom\": digest sha256:aaa does not match "
        "guardrail.custom_packs.custom.digest; fix the reference, then retry"
    )
    inspected = ConfigInspectError("rejected", field_path="$.guardrail", reason=reason)
    refused = config_writer.ConfigWriteError("config.yaml change rejected")
    refused.__cause__ = inspected
    assert (
        "defenseclaw config set guardrail.custom_packs.custom.digest sha256:<files digest>"
        in config_writer.plain_error(refused)
    )


def test_source_of_truth_page_lists_every_restart_required_key():
    """The page names each key config set reports as restart-required, not a shorter list."""
    page = _reference_page("source-of-truth.mdx")
    section = page.split("Most keys apply with no restart.", 1)[1].split("`config set` says so", 1)[0]
    missing = [
        key
        for key in config_writer.RESTART_KEYS
        if not any(f"`{form}`" in section for form in (key, f"{key}.*", key.replace("*", "<c>")))
    ]
    assert not missing, f"source-of-truth.mdx leaves out restart-required keys: {missing}"


def test_a_refused_config_set_names_the_missing_and_the_unknown_field(tmp_path):
    """GAP-0159: the key a typo or a missing field is about is in the sentence, with no v8 reference."""
    path = _config(tmp_path)
    expected = {
        "guardrail.custom_packs.bad": ({"path": str(tmp_path)}, "guardrail.custom_packs.bad: add the required field digest."),
        "guardrail.mdoe": ("observe", 'guardrail.mdoe: unknown field (did you mean "mode"?). All fields: '),
    }
    for key, (value, sentence) in expected.items():
        with pytest.raises(Exception) as refused:
            config_writer.apply([Change(key, value)], "cli:test", "t", path=path)
        assert config_writer.plain_error(refused.value).startswith(sentence)


def test_only_the_writer_writes_config_yaml():
    """Spec section 3 guard: config.yaml is written through config_writer
    (which takes config.yaml.lock, validates and records the generation).
    The modules listed here are that writer, its callers' shared helpers and
    the 0.x import steps, which lock and record the generation themselves."""
    import pathlib
    import re

    package = pathlib.Path(config_writer.__file__).resolve().parent
    allowed = {
        "config.py",
        "config_writer.py",
        "migrations.py",
        "observability/v8_writer.py",
        "commands/cmd_setup.py",  # setup rollback: replace_document, or a recorded exact restore
    }
    names = r"(?:config_path|cfg_path|config_file|CONFIG_PATH)"
    direct = re.compile(
        rf"open\([^)\n]*\b{names}\b[^)\n]*,\s*[\"'][wax]"
        rf"|os\.replace\([^)\n]*,\s*{names}\s*\)"
        rf"|\b\w*atomic_write\w*\(\s*{names}\b"
        rf"|\b{names}\.write_(?:text|bytes)\("
    )
    offenders = []
    for path in package.rglob("*.py"):
        rel = path.relative_to(package).as_posix()
        if rel in allowed:
            continue
        match = direct.search(path.read_text(encoding="utf-8"))
        if match:
            offenders.append(f"{rel}: {match.group(0)}")
    assert not offenders, "config.yaml written outside config_writer: " + "; ".join(offenders)


def test_a_stray_deployment_pin_is_ignored_for_a_per_user_config(tmp_path, monkeypatch):
    # GAP-0091: DEFENSECLAW_DEPLOYMENT_MODE exported in a user's shell made
    # the CLI refuse as a managed device (or fail on an invalid mode).
    from defenseclaw import config as config_module
    from defenseclaw import envvars

    home = tmp_path / "home"
    machine = tmp_path / "machine"
    for directory in (home / ".defenseclaw", machine):
        directory.mkdir(parents=True)
    monkeypatch.setattr(config_module, "_home", lambda: home)
    monkeypatch.setattr(config_module, "_ignored_deployment_pins", [])
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home / ".defenseclaw"))
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    monkeypatch.setenv("DEFENSECLAW_JUDGE_TRACE", "1")

    for pin in ("managed_enterprise", "oss"):
        monkeypatch.setenv("DEFENSECLAW_DEPLOYMENT_MODE", pin)
        assert config_module.ignore_unmanaged_deployment_pins() == ["DEFENSECLAW_DEPLOYMENT_MODE"]
        assert "DEFENSECLAW_DEPLOYMENT_MODE" not in os.environ
    assert config_module.ignored_deployment_pins() == ["DEFENSECLAW_DEPLOYMENT_MODE"]
    assert envvars.ignored_off_secure_client() == ["DEFENSECLAW_JUDGE_TRACE"]

    # A machine-owned config (outside any home) keeps its pin.
    monkeypatch.setenv("DEFENSECLAW_CONFIG", str(machine / "config.yaml"))
    monkeypatch.setenv("DEFENSECLAW_DEPLOYMENT_MODE", "managed_enterprise")
    assert config_module.ignore_unmanaged_deployment_pins() == []
    assert os.environ["DEFENSECLAW_DEPLOYMENT_MODE"] == "managed_enterprise"


def test_a_global_mode_change_names_the_connectors_that_keep_their_own_mode(tmp_path, monkeypatch):
    # GAP-0259: guardrail.connectors.<C>.mode wins over guardrail.mode, so the change must say so.
    from click.testing import CliRunner
    from defenseclaw.commands import cmd_config

    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    _config(tmp_path, "guardrail:\n  mode: observe\n  connectors:\n    codex: {mode: observe, enabled: true}\n")
    out = CliRunner().invoke(cmd_config.config_cmd, ["set", "guardrail.mode", "action"])
    assert out.exit_code == 0, out.output
    assert "keeps its own mode (observe)" in out.output
    assert "defenseclaw guardrail mode action --connector codex" in out.output


def test_derived_provider_keeps_yaml_12_name_after_unrelated_write(tmp_path, monkeypatch):
    import json

    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    path = _config(tmp_path, "llm_providers:\n  custom:\n    - name: on\n      domains: [llm.example.test]\n")
    config_writer.apply([Change("update.check", False)], "cli:test", "t", path=path)
    overlay = json.loads((tmp_path / "custom-providers.json").read_text(encoding="utf-8"))
    assert overlay["providers"][0]["name"] == "on"


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership")
def test_durable_replacement_preserves_existing_owner_and_group(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    path.write_bytes(b"old")
    owner = path.stat()
    wanted = (owner.st_uid + 1, owner.st_gid + 1)
    real_stat = os.stat
    seen = []

    def existing_owner(name, *args, **kwargs):
        result = real_stat(name, *args, **kwargs)
        if os.fspath(name) != str(path):
            return result
        fields = list(result)
        fields[4:6] = wanted
        return os.stat_result(fields)

    def record_owner(_fd, uid, gid):
        seen.append((uid, gid))

    monkeypatch.setattr(os, "stat", existing_owner)
    monkeypatch.setattr(os, "fchown", record_owner)
    config_writer._write_durable(str(path), b"new", 0o600)
    assert seen == [wanted]
    assert path.read_bytes() == b"new"

