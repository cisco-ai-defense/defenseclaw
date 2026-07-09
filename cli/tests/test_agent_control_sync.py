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

from __future__ import annotations

import json
import os
import plistlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

import yaml
from defenseclaw.agent_control.models import (
    MAX_CONTROLS,
    MAX_RULES,
    ControlValidationError,
    digest_bytes,
    extract_candidates,
)
from defenseclaw.agent_control.publisher import (
    ActivationError,
    GatewayClient,
    ManagedPublisher,
    PublicationError,
    RollbackDivergenceError,
    SingleWriterLock,
)
from defenseclaw.agent_control.sync import (
    AgentControlSynchronizer,
    SynchronizationError,
    _watch_retry_delay,
    configured_rule_pack_base_dirs,
)
from defenseclaw.config import (
    AgentControlConfig,
    Config,
    GuardrailConfig,
    _config_to_dict,
    _merge_agent_control,
    _merge_guardrail,
)


def opa_control(*, block_at: str = "HIGH", alert_at: str = "MEDIUM") -> dict[str, Any]:
    return {
        "id": 42,
        "name": "guardrail-thresholds",
        "control": {
            "enabled": True,
            "execution": "sdk",
            "scope": {},
            "condition": {
                "selector": {"path": "*"},
                "evaluator": {
                    "name": "defenseclaw.opa_policy",
                    "config": {
                        "schema_version": 1,
                        "policy": {
                            "domain": "guardrail",
                            "block_at": block_at,
                            "alert_at": alert_at,
                            "cisco_trust_level": "full",
                        },
                    },
                },
            },
            "action": {"decision": "observe"},
            "tags": [],
        },
    }


def rule_control(*, rule_id: str = "AC-CMD-RM-RF", title: str = "Recursive deletion") -> dict[str, Any]:
    return {
        "id": 43,
        "name": "managed-rules",
        "control": {
            "enabled": True,
            "execution": "sdk",
            "scope": {},
            "condition": {
                "selector": {"path": "*"},
                "evaluator": {
                    "name": "defenseclaw.rule_pack",
                    "config": {
                        "schema_version": 1,
                        "rule_pack": {
                            "version": 1,
                            "category": "agent-control",
                            "rules": [
                                {
                                    "id": rule_id,
                                    "pattern": r"(?i)rm\s+-rf",
                                    "title": title,
                                    "severity": "HIGH",
                                    "confidence": 0.99,
                                    "tags": ["filesystem"],
                                }
                            ],
                        },
                    },
                },
            },
            "action": {"decision": "observe"},
            "tags": [],
        },
    }


def sdk_canonical_control(control: dict[str, Any]) -> dict[str, Any]:
    """Mirror nullable default fields emitted by get_server_controls()."""
    canonical = json.loads(json.dumps(control))
    canonical["control"]["scope"] = {
        "step_types": None,
        "step_names": None,
        "step_name_regex": None,
        "stages": None,
    }
    canonical["control"]["action"]["steering_context"] = None
    canonical["control"]["condition"].update({"and": None, "or": None, "not": None})
    canonical["control"]["template"] = None
    canonical["control"]["template_values"] = None
    return canonical


class CandidateTests(unittest.TestCase):
    def test_extracts_and_renders_both_lanes(self) -> None:
        candidates = extract_candidates([opa_control(), rule_control(), {"control": {}}])
        self.assertEqual(candidates.matching_controls, 2)
        self.assertEqual(candidates.ignored_controls, 1)
        opa = json.loads(candidates.opa_artifact("stricter"))
        self.assertEqual(opa["agent_control"]["guardrail"]["block_threshold"], 3)
        self.assertEqual(opa["agent_control"]["guardrail"]["alert_threshold"], 2)
        rules = yaml.safe_load(candidates.rule_pack_artifact())
        self.assertEqual(rules["category"], "agent-control")
        self.assertEqual(rules["rules"][0]["id"], "AC-CMD-RM-RF")

    def test_empty_snapshot_generates_disabled_opa_and_no_rules(self) -> None:
        candidates = extract_candidates([])
        opa = json.loads(candidates.opa_artifact("remote"))
        self.assertFalse(opa["agent_control"]["enabled"])
        self.assertEqual(opa["agent_control"]["precedence"], "remote")
        self.assertIsNone(candidates.rule_pack_artifact())

    def test_rejects_bad_envelope(self) -> None:
        value = opa_control()
        value["control"]["execution"] = "server"
        with self.assertRaisesRegex(ControlValidationError, "execution"):
            extract_candidates([value])

    def test_accepts_sdk_canonical_nullable_envelope_fields(self) -> None:
        candidates = extract_candidates([sdk_canonical_control(opa_control()), sdk_canonical_control(rule_control())])
        self.assertEqual(candidates.matching_controls, 2)
        self.assertEqual(len(candidates.rules), 1)

    def test_rejects_nonempty_sdk_scope_or_composite(self) -> None:
        scoped = sdk_canonical_control(opa_control())
        scoped["control"]["scope"]["stages"] = ["pre"]
        with self.assertRaisesRegex(ControlValidationError, "scope"):
            extract_candidates([scoped])

        composite = sdk_canonical_control(opa_control())
        composite["control"]["condition"]["and"] = []
        with self.assertRaisesRegex(ControlValidationError, "selector/evaluator leaf"):
            extract_candidates([composite])

    def test_rejects_matching_evaluator_hidden_in_composite_condition(self) -> None:
        value = opa_control()
        leaf = value["control"]["condition"]
        value["control"]["condition"] = {"all": [leaf]}
        with self.assertRaisesRegex(ControlValidationError, "selector/evaluator leaf"):
            extract_candidates([value])

    def test_rejects_invalid_threshold_order(self) -> None:
        with self.assertRaisesRegex(ControlValidationError, "alert_at"):
            extract_candidates([opa_control(block_at="MEDIUM", alert_at="HIGH")])

    def test_malformed_membership_values_raise_validation_errors_not_type_errors(self) -> None:
        malformed_name = opa_control()
        malformed_name["control"]["condition"]["evaluator"]["name"] = []
        self.assertEqual(extract_candidates([malformed_name]).matching_controls, 0)

        malformed_threshold = opa_control()
        malformed_threshold["control"]["condition"]["evaluator"]["config"]["policy"]["block_at"] = []
        with self.assertRaisesRegex(ControlValidationError, "block_at"):
            extract_candidates([malformed_threshold])

        malformed_severity = rule_control()
        rules = malformed_severity["control"]["condition"]["evaluator"]["config"]["rule_pack"]["rules"]
        rules[0]["severity"] = []
        with self.assertRaisesRegex(ControlValidationError, "severity"):
            extract_candidates([malformed_severity])

    def test_deduplicates_identical_rules_and_rejects_conflicts(self) -> None:
        candidates = extract_candidates([rule_control(), rule_control()])
        self.assertEqual(len(candidates.rules), 1)
        with self.assertRaisesRegex(ControlValidationError, "conflicting duplicate"):
            extract_candidates([rule_control(), rule_control(title="Different")])

    def test_does_not_mutate_sdk_snapshot(self) -> None:
        value = rule_control(rule_id="  AC-1  ")
        extract_candidates([value])
        rule_id = value["control"]["condition"]["evaluator"]["config"]["rule_pack"]["rules"][0]["id"]
        self.assertEqual(rule_id, "  AC-1  ")

    def test_evaluator_discovery_rejects_excessive_depth(self) -> None:
        value: dict[str, Any] = {"leaf": opa_control()["control"]}
        for _ in range(70):
            value = {"nested": value}
        with self.assertRaisesRegex(ControlValidationError, "traversal limits"):
            extract_candidates([{"control": value}])

    def test_evaluator_discovery_handles_cycles_without_recursion(self) -> None:
        value: dict[str, Any] = {}
        value["self"] = value
        candidates = extract_candidates([{"control": value}])
        self.assertEqual(candidates.matching_controls, 0)

    def test_snapshot_and_rule_resource_limits(self) -> None:
        with self.assertRaisesRegex(ControlValidationError, "controls"):
            extract_candidates([{} for _ in range(MAX_CONTROLS + 1)])

        value = rule_control()
        template = value["control"]["condition"]["evaluator"]["config"]["rule_pack"]["rules"][0]
        value["control"]["condition"]["evaluator"]["config"]["rule_pack"]["rules"] = [
            {**template, "id": f"AC-{index}"} for index in range(MAX_RULES + 1)
        ]
        with self.assertRaisesRegex(ControlValidationError, "rules exceeds"):
            extract_candidates([value])


class PublisherTests(unittest.TestCase):
    def test_publication_and_rollback_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "policies"
            (policy / "rego").mkdir(parents=True)
            publisher = ManagedPublisher(data_dir=str(root), policy_dir=str(policy))
            first = b'{"agent_control":{"enabled":false,"precedence":"stricter","schema_version":1}}\n'
            second = b'{"agent_control":{"enabled":false,"precedence":"remote","schema_version":1}}\n'
            publisher.publish_opa(first)
            self.assertEqual(publisher.opa_active_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(publisher.managed_dir.stat().st_mode & 0o777, 0o700)
            publication = publisher.publish_opa(second)
            self.assertEqual(publisher.opa_active_path.read_bytes(), second)
            self.assertEqual(publication.digest, digest_bytes(second))
            publisher.rollback(publication)
            self.assertEqual(publisher.opa_active_path.read_bytes(), first)

    def test_rollback_refuses_to_overwrite_a_newer_publication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "policies"
            (policy / "rego").mkdir(parents=True)
            publisher = ManagedPublisher(data_dir=str(root), policy_dir=str(policy))
            publisher.publish_opa(b"first\n")
            stale = publisher.publish_opa(b"second\n")
            publisher.publish_opa(b"third\n")
            with self.assertRaisesRegex(RollbackDivergenceError, "refusing rollback"):
                publisher.rollback(stale)
            self.assertEqual(publisher.opa_active_path.read_bytes(), b"third\n")

    def test_refuses_hard_linked_active_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "policies"
            (policy / "rego").mkdir(parents=True)
            publisher = ManagedPublisher(data_dir=str(root), policy_dir=str(policy))
            publisher.publish_opa(b"first\n")
            os.link(publisher.opa_active_path, root / "alias")
            with self.assertRaisesRegex(PublicationError, "hard-linked"):
                publisher.publish_opa(b"second\n")

    def test_refuses_symlinked_managed_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            actual = root / "actual"
            actual.mkdir()
            linked = root / "linked"
            linked.symlink_to(actual, target_is_directory=True)
            with self.assertRaisesRegex(PublicationError, "symlink"):
                ManagedPublisher(data_dir=str(root), policy_dir=str(root), managed_dir=str(linked))

    def test_preserves_shared_rego_directory_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rego = root / "policies" / "rego"
            rego.mkdir(parents=True, mode=0o750)
            rego.chmod(0o750)
            publisher = ManagedPublisher(data_dir=str(root), policy_dir=str(root / "policies"))
            publisher.prepare()
            self.assertEqual(rego.stat().st_mode & 0o777, 0o750)
            publisher.publish_opa(b"first\n")
            self.assertEqual(rego.stat().st_mode & 0o777, 0o750)
            publication = publisher.publish_opa(b"second\n")
            publisher.rollback(publication)
            self.assertEqual(rego.stat().st_mode & 0o777, 0o750)

    def test_requires_shared_rego_directory_to_be_provisioned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "policies"
            publisher = ManagedPublisher(data_dir=str(root), policy_dir=str(policy))
            with self.assertRaisesRegex(PublicationError, "must already exist"):
                publisher.prepare()
            self.assertFalse((policy / "rego").exists())

    def test_managed_directory_chmod_failure_is_fatal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "policies"
            (policy / "rego").mkdir(parents=True)
            publisher = ManagedPublisher(data_dir=str(root), policy_dir=str(policy))
            with mock.patch.object(Path, "chmod", side_effect=PermissionError("denied")):
                with self.assertRaisesRegex(PublicationError, "cannot restrict"):
                    publisher.prepare()

    def test_single_writer_lock_rejects_second_owner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = Path(tmp).resolve() / "managed" / "lock"
            with SingleWriterLock(lock_path):
                with self.assertRaisesRegex(PublicationError, "another Agent Control synchronizer"):
                    with SingleWriterLock(lock_path):
                        self.fail("second lock unexpectedly succeeded")


class ConfigTests(unittest.TestCase):
    def test_gateway_client_formats_ipv6_loopback(self) -> None:
        client = GatewayClient(bind="::1", port=43123, token="test-token")
        self.assertEqual(client.base_url, "http://[::1]:43123")

    def test_gateway_client_rejects_malformed_artifact_status(self) -> None:
        client = GatewayClient(bind="127.0.0.1", port=43123, token="test-token")
        client._request = lambda *_args: {}  # type: ignore[method-assign]
        with self.assertRaisesRegex(ActivationError, "malformed agent_control metadata"):
            client.reload_opa(None)
        client._request = lambda *_args: {  # type: ignore[method-assign]
            "rule_pack": {"present": True}
        }
        with self.assertRaisesRegex(ActivationError, "malformed rule_pack artifact digest"):
            client.verify_rule_pack("sha256:expected")

    def test_empty_rule_pack_bases_do_not_become_working_directory(self) -> None:
        cfg = Config()
        cfg.guardrail.rule_pack_dir = ""
        cfg.guardrail.connectors = []
        cfg.application_protection.guardrail.rule_pack_dir = ""
        cfg.application_protection.connectors = {}
        self.assertEqual(configured_rule_pack_base_dirs(cfg), [])

    def test_agent_control_config_round_trip_shape(self) -> None:
        settings = _merge_agent_control(
            {
                "enabled": True,
                "target_id": "installation-1",
                "opa": {"precedence": "remote", "activation": "manual"},
                "rule_pack": {"enabled": True, "activation": "restart", "max_rules": 500},
                "observability": {"enabled": False},
            }
        )
        settings.validate()
        cfg = Config(agent_control=settings)
        value = _config_to_dict(cfg)["agent_control"]
        self.assertEqual(value["target_id"], "installation-1")
        self.assertEqual(value["opa"]["precedence"], "remote")
        self.assertTrue(value["rule_pack"]["enabled"])
        self.assertFalse(value["observability"]["enabled"])
        self.assertTrue(value["observability"]["include_content"])

    def test_default_agent_control_block_is_not_serialized(self) -> None:
        self.assertNotIn("agent_control", _config_to_dict(Config()))
        self.assertEqual(AgentControlConfig().target_type, "defenseclaw.installation")

    def test_guardrail_rejects_duplicate_overlay_dirs(self) -> None:
        value = GuardrailConfig(rule_pack_overlay_dirs=["/tmp/rules", "/tmp/rules/"])
        with self.assertRaisesRegex(ValueError, "duplicate path"):
            value.validate()

    def test_guardrail_rejects_scalar_overlay_dirs(self) -> None:
        with self.assertRaisesRegex(ValueError, "rule_pack_overlay_dirs must be a list"):
            _merge_guardrail({"rule_pack_overlay_dirs": "/tmp/rules"}, "/tmp")

    def test_agent_control_rejects_credentials_and_unknown_keys(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported keys"):
            _merge_agent_control({"enabled": True, "api_key": "must-not-live-in-config"})

    def test_agent_control_rejects_non_mapping_blocks(self) -> None:
        with self.assertRaisesRegex(ValueError, "agent_control must be a mapping"):
            _merge_agent_control("enabled")
        with self.assertRaisesRegex(ValueError, "agent_control.opa must be a mapping"):
            _merge_agent_control({"opa": "remote"})
        with self.assertRaisesRegex(ValueError, "agent_control.rule_pack must be a mapping"):
            _merge_agent_control({"rule_pack": []})
        with self.assertRaisesRegex(ValueError, "agent_control.observability must be a mapping"):
            _merge_agent_control({"observability": "enabled"})

    def test_agent_control_requires_dedicated_agent_and_target_type(self) -> None:
        value = AgentControlConfig(enabled=True, target_id="installation-1", agent_name="shared-agent")
        with self.assertRaisesRegex(ValueError, "agent_name"):
            value.validate()

    def test_unredacted_observability_uses_private_spool_without_global_privacy_opt_out(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "policies"
            (policy / "rego").mkdir(parents=True)
            cfg = Config(data_dir=str(root), policy_dir=str(policy))
            cfg.agent_control.enabled = True
            cfg.agent_control.target_id = "installation-1"
            self.assertFalse(cfg.privacy.disable_redaction)
            synchronizer = AgentControlSynchronizer(
                cfg,
                sdk=FakeSDK([]),
                gateway=FakeGateway(),
                validator=FakeValidator(),
            )
            self.assertEqual(
                synchronizer.event_bridge.event_log_path,
                root / "agent-control" / "gateway-events-unredacted.jsonl",
            )

    def test_metadata_only_observability_uses_standard_gateway_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "policies"
            (policy / "rego").mkdir(parents=True)
            cfg = Config(data_dir=str(root), policy_dir=str(policy))
            cfg.agent_control.enabled = True
            cfg.agent_control.target_id = "installation-1"
            cfg.agent_control.observability.include_content = False
            synchronizer = AgentControlSynchronizer(
                cfg,
                sdk=FakeSDK([]),
                gateway=FakeGateway(),
                validator=FakeValidator(),
            )
            self.assertEqual(synchronizer.event_bridge.event_log_path, root / "gateway.jsonl")


class PackagingTests(unittest.TestCase):
    def test_agent_control_service_definitions_are_valid_and_secret_free(self) -> None:
        root = Path(__file__).resolve().parents[2]
        plist_path = root / "packaging" / "launchd" / "com.defenseclaw.agent-control.plist"
        with plist_path.open("rb") as handle:
            plist = plistlib.load(handle)
        self.assertEqual(plist["Label"], "com.defenseclaw.agent-control")
        self.assertEqual(
            plist["ProgramArguments"],
            ["/Library/DefenseClaw/bin/defenseclaw-agent-control-launcher"],
        )
        self.assertNotIn("AGENT_CONTROL_API_KEY", plist.get("EnvironmentVariables", {}))

        unit = (root / "packaging" / "systemd" / "defenseclaw-agent-control.service").read_text(encoding="utf-8")
        self.assertIn("agent-control sync --watch", unit)
        self.assertIn("EnvironmentFile=/etc/defenseclaw/agent-control.env", unit)
        self.assertIn("StartLimitIntervalSec=300", unit)
        self.assertIn("StartLimitBurst=5", unit)
        self.assertIn("NoNewPrivileges=true", unit)
        self.assertNotIn("AGENT_CONTROL_API_KEY=", unit)

        launcher = root / "packaging" / "launchd" / "defenseclaw-agent-control-launcher"
        launcher_text = launcher.read_text(encoding="utf-8")
        self.assertIn("agent-control.env", launcher_text)
        self.assertIn("must be owned by root", launcher_text)
        self.assertIn("directory must be root:defenseclaw mode 0750", launcher_text)
        self.assertNotIn("AGENT_CONTROL_API_KEY=", launcher_text)


class FakeSDK:
    __version__ = "8.2.0"

    def __init__(self, controls: list[dict[str, Any]]) -> None:
        self.controls = controls
        self.init_kwargs: dict[str, Any] = {}
        self.shutdown_calls = 0
        self.written_events: list[Any] = []

    def init(self, **kwargs: Any) -> None:
        self.init_kwargs = kwargs

    def get_server_controls(self) -> list[dict[str, Any]]:
        return self.controls

    def write_events(self, events: list[Any]) -> Any:
        self.written_events.extend(events)
        return SimpleNamespace(accepted=len(events), dropped=0)

    def shutdown(self) -> None:
        self.shutdown_calls += 1


class SequenceSDK(FakeSDK):
    def __init__(self, snapshots: list[list[dict[str, Any]] | None]) -> None:
        super().__init__([])
        self.snapshots = snapshots
        self.init_calls = 0

    def init(self, **kwargs: Any) -> None:
        super().init(**kwargs)
        self.init_calls += 1

    def get_server_controls(self) -> list[dict[str, Any]] | None:
        return self.snapshots.pop(0)


class ImmediateEvent:
    def is_set(self) -> bool:
        return False

    def wait(self, _timeout: float) -> bool:
        return False


class FakeValidator:
    def __init__(self) -> None:
        self.calls: list[tuple[Path, Path]] = []
        self.rule_calls: list[tuple[list[Path], Path]] = []

    def validate_opa(self, *, rego_dir: Path, candidate: Path) -> None:
        self.calls.append((rego_dir, candidate))

    def validate_rule_pack(self, *, base_dirs: list[Path], overlay_dir: Path) -> None:
        self.rule_calls.append((base_dirs, overlay_dir))


class FakeGateway:
    def __init__(self) -> None:
        self.opa: list[str | None] = []
        self.rules: list[str | None] = []

    def reload_opa(self, expected_digest: str | None) -> dict[str, Any]:
        self.opa.append(expected_digest)
        return {"status": "reloaded"}

    def restart_and_verify_rule_pack(self, expected_digest: str | None) -> dict[str, Any]:
        self.rules.append(expected_digest)
        return {"status": "ready"}

    def status(self) -> dict[str, Any]:
        opa_digest = self.opa[-1] if self.opa else None
        rule_digest = self.rules[-1] if self.rules else None
        return {
            "agent_control": {"present": opa_digest is not None, "artifact_digest": opa_digest},
            "rule_pack": {"present": rule_digest is not None, "artifact_digest": rule_digest},
            "restart_supported": True,
        }

    def ensure_restart_supported(self) -> None:
        if self.status().get("restart_supported") is not True:
            raise ActivationError("automatic rule-pack activation requires a supervised gateway")


class FailFirstActivationGateway(FakeGateway):
    def __init__(self, *, lane: str) -> None:
        super().__init__()
        self.lane = lane
        self.failed = False

    def reload_opa(self, expected_digest: str | None) -> dict[str, Any]:
        self.opa.append(expected_digest)
        if self.lane == "opa" and not self.failed:
            self.failed = True
            raise RuntimeError("simulated OPA digest mismatch")
        return {"status": "reloaded"}

    def restart_and_verify_rule_pack(self, expected_digest: str | None) -> dict[str, Any]:
        self.rules.append(expected_digest)
        if self.lane == "rule_pack" and not self.failed:
            self.failed = True
            raise RuntimeError("simulated rule-pack digest mismatch")
        return {"status": "ready"}


class AlwaysFailGateway(FakeGateway):
    def reload_opa(self, expected_digest: str | None) -> dict[str, Any]:
        self.opa.append(expected_digest)
        raise RuntimeError("simulated persistent gateway failure")


class FakeAuditLogger:
    def __init__(self) -> None:
        self.actions: list[str] = []

    def log_action(self, action: str, _target: str, _details: str) -> None:
        self.actions.append(action)


class StopAfterPolls:
    def __init__(self, polls: int) -> None:
        self.polls = polls
        self.wait_calls = 0

    def is_set(self) -> bool:
        return False

    def wait(self, _timeout: float) -> bool:
        self.wait_calls += 1
        return self.wait_calls > self.polls


class SynchronizerTests(unittest.TestCase):
    def test_watch_retry_delay_is_exponential_capped_and_jittered(self) -> None:
        with mock.patch("defenseclaw.agent_control.sync.random.uniform", return_value=0.0):
            self.assertEqual(
                [_watch_retry_delay(i, poll_seconds=2, cap_seconds=10) for i in range(1, 6)],
                [2.0, 4.0, 8.0, 10.0, 10.0],
            )

    def test_observability_bridge_init_failure_does_not_block_policy_sync(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "policies"
            (policy / "rego").mkdir(parents=True)
            cfg = Config(data_dir=str(root), policy_dir=str(policy))
            cfg.agent_control.enabled = True
            cfg.agent_control.target_id = "installation-1"
            with mock.patch(
                "defenseclaw.agent_control.sync.EnforcementEventBridge",
                side_effect=OSError("sensitive local detail"),
            ):
                synchronizer = AgentControlSynchronizer(
                    cfg,
                    sdk=FakeSDK([]),
                    gateway=FakeGateway(),
                    validator=FakeValidator(),
                )

            self.assertIsNone(synchronizer.event_bridge)
            self.assertEqual(synchronizer.state.observability_status, "degraded")
            self.assertEqual(
                synchronizer.state.observability_last_error,
                "observability bridge initialization failed (OSError)",
            )
            synchronizer.process_snapshot([])

    def test_watch_does_not_retry_unchanged_poison_snapshot_at_poll_rate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "policies"
            (policy / "rego").mkdir(parents=True)
            cfg = Config(data_dir=str(root), policy_dir=str(policy))
            cfg.agent_control.enabled = True
            cfg.agent_control.target_id = "installation-1"
            sdk = FakeSDK([])
            stop_event = StopAfterPolls(5)
            synchronizer = AgentControlSynchronizer(
                cfg,
                sdk=sdk,
                gateway=FakeGateway(),
                validator=FakeValidator(),
                stop_event=stop_event,  # type: ignore[arg-type]
            )
            calls = 0

            def process(controls: list[dict[str, Any]]) -> Any:
                nonlocal calls
                calls += 1
                if calls == 1:
                    sdk.controls = [opa_control()]
                    return synchronizer.state
                raise ActivationError("poison snapshot")

            synchronizer.process_snapshot = process  # type: ignore[method-assign]
            synchronizer.run_watch()
            self.assertEqual(calls, 2)

    def test_watch_recovers_when_initial_snapshot_is_poisoned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "policies"
            (policy / "rego").mkdir(parents=True)
            cfg = Config(data_dir=str(root), policy_dir=str(policy))
            cfg.agent_control.enabled = True
            cfg.agent_control.target_id = "installation-1"
            sdk = FakeSDK([opa_control()])
            stop_event = StopAfterPolls(1)
            synchronizer = AgentControlSynchronizer(
                cfg,
                sdk=sdk,
                gateway=FakeGateway(),
                validator=FakeValidator(),
                stop_event=stop_event,  # type: ignore[arg-type]
            )
            calls: list[list[dict[str, Any]]] = []

            def process(controls: list[dict[str, Any]]) -> Any:
                calls.append(controls)
                if len(calls) == 1:
                    sdk.controls = []
                    raise ActivationError("poison initial snapshot")
                return synchronizer.state

            synchronizer.process_snapshot = process  # type: ignore[method-assign]
            synchronizer.run_watch()
            self.assertEqual(calls, [[opa_control()], []])

    def test_disabled_opa_manual_mode_does_not_report_pending_activation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "policies"
            (policy / "rego").mkdir(parents=True)
            cfg = Config(data_dir=str(root), policy_dir=str(policy))
            cfg.agent_control.enabled = True
            cfg.agent_control.target_id = "installation-1"
            cfg.agent_control.opa.enabled = False
            cfg.agent_control.opa.activation = "manual"
            synchronizer = AgentControlSynchronizer(
                cfg,
                sdk=FakeSDK([]),
                gateway=FakeGateway(),
                validator=FakeValidator(),
            )
            state = synchronizer.process_snapshot([])
            self.assertEqual(state.status, "active")

    def test_rule_only_sync_does_not_require_policy_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = Config(data_dir=str(root), policy_dir="")
            cfg.agent_control.enabled = True
            cfg.agent_control.target_id = "installation-1"
            cfg.agent_control.opa.enabled = False
            cfg.agent_control.rule_pack.enabled = True
            cfg.agent_control.rule_pack.activation = "manual"
            synchronizer = AgentControlSynchronizer(
                cfg,
                sdk=FakeSDK([rule_control()]),
                gateway=FakeGateway(),
                validator=FakeValidator(),
            )
            state = synchronizer.run_once()
            self.assertEqual(state.status, "published_pending_activation")
            self.assertTrue(synchronizer.publisher.rule_pack_active_path.exists())

    def test_manual_mode_reports_pending_only_for_digest_delta(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "policies"
            (policy / "rego").mkdir(parents=True)
            cfg = Config(data_dir=str(root), policy_dir=str(policy))
            cfg.agent_control.enabled = True
            cfg.agent_control.target_id = "installation-1"
            cfg.agent_control.opa.activation = "manual"
            synchronizer = AgentControlSynchronizer(
                cfg,
                sdk=FakeSDK([]),
                gateway=FakeGateway(),
                validator=FakeValidator(),
            )
            state = synchronizer.process_snapshot([opa_control()])
            self.assertEqual(state.status, "published_pending_activation")
            state.opa_active_digest = state.opa_published_digest
            state = synchronizer.process_snapshot([opa_control()])
            self.assertEqual(state.status, "active")

    def test_state_persistence_failure_rolls_back_publication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "policies"
            (policy / "rego").mkdir(parents=True)
            cfg = Config(data_dir=str(root), policy_dir=str(policy))
            cfg.agent_control.enabled = True
            cfg.agent_control.target_id = "installation-1"
            synchronizer = AgentControlSynchronizer(
                cfg,
                sdk=FakeSDK([]),
                gateway=FakeGateway(),
                validator=FakeValidator(),
            )
            with mock.patch(
                "defenseclaw.agent_control.sync.save_state",
                side_effect=[OSError("disk full"), None],
            ):
                with self.assertRaisesRegex(SynchronizationError, "state persistence failed"):
                    synchronizer.process_snapshot([opa_control()])
            self.assertFalse(synchronizer.publisher.opa_active_path.exists())

    def test_initial_none_retries_full_sdk_init_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "policies"
            (policy / "rego").mkdir(parents=True)
            cfg = Config(data_dir=str(root), policy_dir=str(policy))
            cfg.agent_control.enabled = True
            cfg.agent_control.target_id = "installation-1"
            sdk = SequenceSDK([None, []])
            synchronizer = AgentControlSynchronizer(
                cfg,
                sdk=sdk,
                gateway=FakeGateway(),
                validator=FakeValidator(),
                stop_event=ImmediateEvent(),  # type: ignore[arg-type]
            )

            state = synchronizer.run_once()

            self.assertEqual(sdk.init_calls, 2)
            self.assertEqual(sdk.shutdown_calls, 2)
            self.assertEqual(state.snapshot_state, "empty")
            self.assertTrue(synchronizer.publisher.opa_active_path.exists())

    def test_run_once_publishes_and_activates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "policies"
            (policy / "rego").mkdir(parents=True)
            cfg = Config(data_dir=str(root), policy_dir=str(policy))
            cfg.agent_control.enabled = True
            cfg.agent_control.target_id = "installation-1"
            cfg.agent_control.rule_pack.enabled = True
            sdk = FakeSDK([opa_control(), rule_control()])
            gateway = FakeGateway()
            validator = FakeValidator()
            synchronizer = AgentControlSynchronizer(cfg, sdk=sdk, gateway=gateway, validator=validator)

            state = synchronizer.run_once()

            self.assertEqual(state.status, "active")
            self.assertEqual(state.opa_active_digest, gateway.opa[-1])
            self.assertEqual(state.rule_pack_active_digest, gateway.rules[-1])
            self.assertEqual(sdk.init_kwargs["target_type"], "defenseclaw.installation")
            self.assertEqual(sdk.shutdown_calls, 1)
            self.assertEqual(len(validator.calls), 1)
            self.assertEqual(len(validator.rule_calls), 1)
            self.assertTrue(synchronizer.publisher.opa_active_path.exists())
            self.assertTrue(synchronizer.publisher.rule_pack_active_path.exists())

    def test_invalid_rule_lane_does_not_block_valid_opa_lane(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "policies"
            (policy / "rego").mkdir(parents=True)
            cfg = Config(data_dir=str(root), policy_dir=str(policy))
            cfg.agent_control.enabled = True
            cfg.agent_control.target_id = "installation-1"
            cfg.agent_control.rule_pack.enabled = True
            invalid_rule = rule_control()
            invalid_rule["control"]["execution"] = "server"
            gateway = FakeGateway()
            synchronizer = AgentControlSynchronizer(
                cfg,
                sdk=FakeSDK([]),
                gateway=gateway,
                validator=FakeValidator(),
            )

            with self.assertRaisesRegex(SynchronizationError, "rule_pack"):
                synchronizer.process_snapshot([opa_control(), invalid_rule])

            self.assertEqual(len(gateway.opa), 1)
            self.assertEqual(gateway.rules, [])
            self.assertEqual(synchronizer.state.status, "error_lkg_preserved")

    def test_unchanged_snapshot_is_a_noop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "policies"
            (policy / "rego").mkdir(parents=True)
            cfg = Config(data_dir=str(root), policy_dir=str(policy))
            cfg.agent_control.enabled = True
            cfg.agent_control.target_id = "installation-1"
            gateway = FakeGateway()
            validator = FakeValidator()
            audit_logger = FakeAuditLogger()
            synchronizer = AgentControlSynchronizer(
                cfg,
                sdk=FakeSDK([]),
                gateway=gateway,
                validator=validator,
                audit_logger=audit_logger,
            )

            synchronizer.process_snapshot([opa_control()])
            synchronizer.process_snapshot([opa_control()])

            self.assertEqual(len(gateway.opa), 1)
            self.assertEqual(len(validator.calls), 1)
            self.assertEqual(audit_logger.actions.count("agent-control-sync"), 1)

    def test_opa_activation_failure_restores_and_verifies_lkg(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "policies"
            (policy / "rego").mkdir(parents=True)
            cfg = Config(data_dir=str(root), policy_dir=str(policy))
            cfg.agent_control.enabled = True
            cfg.agent_control.target_id = "installation-1"
            publisher = ManagedPublisher(data_dir=str(root), policy_dir=str(policy))
            previous = extract_candidates([]).opa_artifact("stricter")
            previous_digest = publisher.publish_opa(previous).digest
            gateway = FailFirstActivationGateway(lane="opa")
            synchronizer = AgentControlSynchronizer(
                cfg,
                sdk=FakeSDK([]),
                publisher=publisher,
                gateway=gateway,
                validator=FakeValidator(),
            )
            synchronizer.state.opa_published_digest = previous_digest
            synchronizer.state.opa_active_digest = previous_digest

            with self.assertRaisesRegex(SynchronizationError, "LKG was restored"):
                synchronizer.process_snapshot([opa_control()])

            self.assertEqual(publisher.opa_active_path.read_bytes(), previous)
            self.assertEqual(gateway.opa[-1], previous_digest)
            self.assertEqual(synchronizer.state.opa_active_digest, previous_digest)

    def test_rule_pack_activation_failure_restores_and_verifies_lkg(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "policies"
            (policy / "rego").mkdir(parents=True)
            cfg = Config(data_dir=str(root), policy_dir=str(policy))
            cfg.agent_control.enabled = True
            cfg.agent_control.target_id = "installation-1"
            cfg.agent_control.opa.enabled = False
            cfg.agent_control.rule_pack.enabled = True
            publisher = ManagedPublisher(data_dir=str(root), policy_dir=str(policy))
            previous = extract_candidates([rule_control()]).rule_pack_artifact()
            assert previous is not None
            previous_digest = publisher.publish_rule_pack(previous).digest
            gateway = FailFirstActivationGateway(lane="rule_pack")
            synchronizer = AgentControlSynchronizer(
                cfg,
                sdk=FakeSDK([]),
                publisher=publisher,
                gateway=gateway,
                validator=FakeValidator(),
            )
            synchronizer.state.rule_pack_published_digest = previous_digest
            synchronizer.state.rule_pack_active_digest = previous_digest

            with self.assertRaisesRegex(SynchronizationError, "LKG was restored"):
                synchronizer.process_snapshot([rule_control(title="Changed")])

            self.assertEqual(publisher.rule_pack_active_path.read_bytes(), previous)
            self.assertEqual(gateway.rules[-1], previous_digest)
            self.assertEqual(synchronizer.state.rule_pack_active_digest, previous_digest)

    def test_rule_pack_restart_requires_supervised_gateway_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "policies"
            (policy / "rego").mkdir(parents=True)
            cfg = Config(data_dir=str(root), policy_dir=str(policy))
            cfg.agent_control.enabled = True
            cfg.agent_control.target_id = "installation-1"
            cfg.agent_control.opa.enabled = False
            cfg.agent_control.rule_pack.enabled = True
            gateway = FakeGateway()
            gateway.status = lambda: {"restart_supported": False}  # type: ignore[method-assign]
            synchronizer = AgentControlSynchronizer(
                cfg,
                sdk=FakeSDK([]),
                gateway=gateway,
                validator=FakeValidator(),
            )
            with self.assertRaisesRegex(SynchronizationError, "supervised gateway"):
                synchronizer.process_snapshot([rule_control()])
            self.assertFalse(synchronizer.publisher.rule_pack_active_path.exists())

    def test_rollback_verification_failure_reports_critical_divergence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "policies"
            (policy / "rego").mkdir(parents=True)
            cfg = Config(data_dir=str(root), policy_dir=str(policy))
            cfg.agent_control.enabled = True
            cfg.agent_control.target_id = "installation-secret-target"
            publisher = ManagedPublisher(data_dir=str(root), policy_dir=str(policy))
            previous = extract_candidates([]).opa_artifact("stricter")
            publisher.publish_opa(previous)
            synchronizer = AgentControlSynchronizer(
                cfg,
                sdk=FakeSDK([]),
                publisher=publisher,
                gateway=AlwaysFailGateway(),
                validator=FakeValidator(),
            )

            with self.assertRaisesRegex(RollbackDivergenceError, "rollback verification failed"):
                synchronizer.process_snapshot([opa_control()])

            self.assertEqual(synchronizer.state.status, "critical_disk_runtime_divergence")
            self.assertNotIn("installation-secret-target", synchronizer.state.last_error or "")
            self.assertEqual(publisher.opa_active_path.read_bytes(), previous)

    def test_successful_empty_snapshot_removes_only_managed_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "policies"
            (policy / "rego").mkdir(parents=True)
            cfg = Config(data_dir=str(root), policy_dir=str(policy))
            cfg.agent_control.enabled = True
            cfg.agent_control.target_id = "installation-1"
            cfg.agent_control.rule_pack.enabled = True
            gateway = FakeGateway()
            synchronizer = AgentControlSynchronizer(
                cfg,
                sdk=FakeSDK([]),
                gateway=gateway,
                validator=FakeValidator(),
            )

            synchronizer.process_snapshot([opa_control(), rule_control()])
            synchronizer.process_snapshot([])

            disabled = json.loads(synchronizer.publisher.opa_active_path.read_bytes())
            self.assertFalse(disabled["agent_control"]["enabled"])
            self.assertFalse(synchronizer.publisher.rule_pack_active_path.exists())
            self.assertIsNone(synchronizer.state.rule_pack_active_digest)
            self.assertEqual(len(gateway.opa), 2)
            self.assertEqual(len(gateway.rules), 2)


if __name__ == "__main__":
    unittest.main()
