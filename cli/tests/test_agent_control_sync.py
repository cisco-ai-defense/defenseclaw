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
from typing import Any

import yaml
from defenseclaw.agent_control.models import (
    ControlValidationError,
    digest_bytes,
    extract_candidates,
)
from defenseclaw.agent_control.publisher import (
    GatewayClient,
    ManagedPublisher,
    PublicationError,
    RollbackDivergenceError,
)
from defenseclaw.agent_control.sync import (
    AgentControlSynchronizer,
    SynchronizationError,
    configured_rule_pack_base_dirs,
)
from defenseclaw.config import AgentControlConfig, Config, GuardrailConfig, _config_to_dict, _merge_agent_control


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

    def test_rejects_matching_evaluator_hidden_in_composite_condition(self) -> None:
        value = opa_control()
        leaf = value["control"]["condition"]
        value["control"]["condition"] = {"all": [leaf]}
        with self.assertRaisesRegex(ControlValidationError, "selector/evaluator leaf"):
            extract_candidates([value])

    def test_rejects_invalid_threshold_order(self) -> None:
        with self.assertRaisesRegex(ControlValidationError, "alert_at"):
            extract_candidates([opa_control(block_at="MEDIUM", alert_at="HIGH")])

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


class ConfigTests(unittest.TestCase):
    def test_gateway_client_formats_ipv6_loopback(self) -> None:
        client = GatewayClient(bind="::1", port=43123, token="test-token")
        self.assertEqual(client.base_url, "http://[::1]:43123")

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
            }
        )
        settings.validate()
        cfg = Config(agent_control=settings)
        value = _config_to_dict(cfg)["agent_control"]
        self.assertEqual(value["target_id"], "installation-1")
        self.assertEqual(value["opa"]["precedence"], "remote")
        self.assertTrue(value["rule_pack"]["enabled"])

    def test_default_agent_control_block_is_not_serialized(self) -> None:
        self.assertNotIn("agent_control", _config_to_dict(Config()))
        self.assertEqual(AgentControlConfig().target_type, "defenseclaw.installation")

    def test_guardrail_rejects_duplicate_overlay_dirs(self) -> None:
        value = GuardrailConfig(rule_pack_overlay_dirs=["/tmp/rules", "/tmp/rules/"])
        with self.assertRaisesRegex(ValueError, "duplicate path"):
            value.validate()

    def test_agent_control_rejects_credentials_and_unknown_keys(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported keys"):
            _merge_agent_control({"enabled": True, "api_key": "must-not-live-in-config"})

    def test_agent_control_requires_dedicated_agent_and_target_type(self) -> None:
        value = AgentControlConfig(enabled=True, target_id="installation-1", agent_name="shared-agent")
        with self.assertRaisesRegex(ValueError, "agent_name"):
            value.validate()


class PackagingTests(unittest.TestCase):
    def test_agent_control_service_definitions_are_valid_and_secret_free(self) -> None:
        root = Path(__file__).resolve().parents[2]
        plist_path = root / "packaging" / "launchd" / "com.defenseclaw.agent-control.plist"
        with plist_path.open("rb") as handle:
            plist = plistlib.load(handle)
        self.assertEqual(plist["Label"], "com.defenseclaw.agent-control")
        self.assertEqual(
            plist["ProgramArguments"][1:],
            ["agent-control", "sync", "--watch"],
        )
        self.assertNotIn("AGENT_CONTROL_API_KEY", plist.get("EnvironmentVariables", {}))

        unit = (root / "packaging" / "systemd" / "defenseclaw-agent-control.service").read_text(
            encoding="utf-8"
        )
        self.assertIn("agent-control sync --watch", unit)
        self.assertIn("EnvironmentFile=-/etc/defenseclaw/agent-control.env", unit)
        self.assertIn("NoNewPrivileges=true", unit)
        self.assertNotIn("AGENT_CONTROL_API_KEY=", unit)


class FakeSDK:
    __version__ = "8.2.0"

    def __init__(self, controls: list[dict[str, Any]]) -> None:
        self.controls = controls
        self.init_kwargs: dict[str, Any] = {}
        self.shutdown_calls = 0

    def init(self, **kwargs: Any) -> None:
        self.init_kwargs = kwargs

    def get_server_controls(self) -> list[dict[str, Any]]:
        return self.controls

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
        }


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


class SynchronizerTests(unittest.TestCase):
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
