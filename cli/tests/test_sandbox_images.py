"""Tests for the harness image evidence the setup gate reads (#1069).

Companion to internal/gateway/hook_contract_sandbox_evidence_test.go: the
setup gate must never accept what the gateway refuses.
"""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from defenseclaw.sandbox_images import (
    DEFAULT_BASE_IMAGE,
    SandboxImageSettings,
    image_kinds,
    image_version,
    verified_harness_contract,
)

CUSTOM_BASE = "ghcr.io/nvidia/openshell-community/sandboxes/base@sha256:" + "ab" * 32

RELEASE = "1.0.2"
OWNER = "0123456789abcdef"
UID = 1000
SETTINGS = SandboxImageSettings(ingress_port=18971)


def claudecode_image(**overrides: object) -> dict:
    record = {
        "tag": "defenseclaw/sandbox:claudecode-41d116a05187f7ae-u1000",
        "image_id": "sha256:b5c5beadc6252084bf397c610cc7a214b62dd4a07213a1ef50d98c1f52eb453e",
        "content_hash": "41d116a05187f7aea74790a94d6bda7be78e5efddc0e42d1d054a14dbacff3f7",
        "connector": "claudecode",
        "harness_version": "2.1.156",
        "hook_contract": "claudecode-hooks-v1",
        "base_image": DEFAULT_BASE_IMAGE,
        "uid": UID,
        "gid": UID,
        "ingress_port": 18971,
        "defenseclaw_version": RELEASE,
        "fail_mode": "closed",
        "owner": OWNER,
        "built_at": "2026-10-13T10:27:41.669899487Z",
        "hook_fire_verified": True,
        "hook_fire_verified_at": "2026-10-13T10:27:46.596385645Z",
    }
    record.update(overrides)
    return record


def evidence_for(tmp: str, connector: str = "claudecode", **kwargs: object):
    kwargs.setdefault("release", RELEASE)
    kwargs.setdefault("settings", SETTINGS)
    kwargs.setdefault("uid", UID)
    kwargs.setdefault("platform_name", "linux")
    return verified_harness_contract(tmp, connector, **kwargs)  # type: ignore[arg-type]


class VerifiedHarnessContractTest(unittest.TestCase):
    def write_store(self, root: Path, records: list[dict]) -> None:
        directory = root / "sandboxes"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "images.json").write_text(
            json.dumps({"version": 1, "owner": OWNER, "images": records}), encoding="utf-8"
        )

    def test_accepts_the_current_fire_verified_image(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.write_store(Path(tmp), [claudecode_image()])
            evidence = evidence_for(tmp)
        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual(evidence.harness_version, "2.1.156")
        self.assertEqual(evidence.contract_id, "claudecode-hooks-v1")
        self.assertFalse(evidence.microvm)

    def test_refusals(self) -> None:
        cases: dict[str, tuple[list[dict], dict]] = {
            "no store": ([], {}),
            "unverified hooks": ([claudecode_image(hook_fire_verified=False)], {}),
            "another connector": ([claudecode_image(connector="codex")], {}),
            "another release built it": ([claudecode_image(defenseclaw_version="1.0.1")], {}),
            "record has no release": ([claudecode_image(defenseclaw_version="")], {}),
            "another host user": ([claudecode_image(uid=1001)], {}),
            "another data dir's image": ([claudecode_image(owner="fedcba9876543210")], {}),
            "harness pin changed since the build": (
                [claudecode_image()],
                {"settings": SandboxImageSettings(harness_pin="2.1.157", ingress_port=18971)},
            ),
            "base image changed since the build": (
                [claudecode_image()],
                {"settings": SandboxImageSettings(base_image="registry.example/b@sha256:" + "cd" * 32, ingress_port=18971)},
            ),
            # GAP-0450: an empty setting means the default base, as in Go.
            "built on a custom base, the setting is empty": ([claudecode_image(base_image=CUSTOM_BASE)], {}),
            "record names no base image": ([claudecode_image(base_image="")], {}),
            # GAP-0451: the docker driver runs no MicroVM image on Linux.
            "Linux docker driver with only a MicroVM image": (
                [claudecode_image(microvm=True, microvm_verified=True)],
                {"settings": SandboxImageSettings(ingress_port=18971, driver="docker")},
            ),
            "ingress port changed since the build": (
                [claudecode_image()],
                {"settings": SandboxImageSettings(ingress_port=19001)},
            ),
            "rebuilt: the newest record is not verified yet": (
                [
                    claudecode_image(),
                    claudecode_image(
                        tag="defenseclaw/sandbox:claudecode-newer-u1000",
                        built_at="2026-10-13T11:00:00Z",
                        hook_fire_verified=False,
                    ),
                ],
                {},
            ),
            "harness version below every reviewed range": ([claudecode_image(harness_version="2.0.0")], {}),
            "harness version cannot be normalized": ([claudecode_image(harness_version="not-a-version")], {}),
            "record has no harness version": ([claudecode_image(harness_version="")], {}),
            "MicroVM image whose MicroVM scenario did not pass": (
                [claudecode_image(microvm=True, microvm_inconclusive="settled nothing")],
                {"platform_name": "darwin"},
            ),
            "macOS with only a docker-driver image": ([claudecode_image()], {"platform_name": "darwin"}),
            "Windows runs no sandbox": ([claudecode_image()], {"platform_name": "win32"}),
        }
        for name, (records, kwargs) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                if records:
                    self.write_store(Path(tmp), records)
                self.assertIsNone(evidence_for(tmp, **kwargs), f"{name}: evidence must not be accepted")

    def test_a_configured_base_image_matches_its_build(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.write_store(Path(tmp), [claudecode_image(base_image=CUSTOM_BASE)])
            evidence = evidence_for(tmp, settings=SandboxImageSettings(base_image=CUSTOM_BASE, ingress_port=18971))
        self.assertIsNotNone(evidence)

    def test_the_default_base_image_is_the_go_one(self) -> None:
        version_go = Path(__file__).resolve().parents[2] / "internal" / "openshell" / "version.go"
        if not version_go.is_file():
            self.skipTest("Go sources are not next to this checkout")
        match = re.search(r'DefaultBaseImage = "([^"]+)"', version_go.read_text(encoding="utf-8"))
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(DEFAULT_BASE_IMAGE, match.group(1))

    def test_image_kinds_follow_the_driver(self) -> None:
        self.assertEqual(image_kinds("linux", ""), (False, True))
        self.assertEqual(image_kinds("linux", "vm"), (False, True))
        self.assertEqual(image_kinds("linux", "auto"), (False, True))
        self.assertEqual(image_kinds("linux", " Docker "), (False,))
        self.assertEqual(image_kinds("darwin", ""), (True,))
        self.assertEqual(image_kinds("darwin", "docker"), (False,))
        self.assertEqual(image_kinds("win32", ""), ())

    def test_linux_docker_driver_accepts_its_docker_image(self) -> None:
        records = [claudecode_image(), claudecode_image(tag="vm", microvm=True, microvm_verified=True)]
        with tempfile.TemporaryDirectory() as tmp:
            self.write_store(Path(tmp), records)
            evidence = evidence_for(tmp, settings=SandboxImageSettings(ingress_port=18971, driver="docker"))
        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertFalse(evidence.microvm)

    def test_accepts_a_microvm_verified_image_on_macos(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.write_store(Path(tmp), [claudecode_image(microvm=True, microvm_verified=True)])
            evidence = evidence_for(tmp, platform_name="darwin")
        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertTrue(evidence.microvm)

    def test_the_newest_verified_record_is_used(self) -> None:
        older = claudecode_image(tag="defenseclaw/sandbox:claudecode-older-u1000", built_at="2026-10-12T10:27:41Z")
        newer = claudecode_image(tag="defenseclaw/sandbox:claudecode-newer-u1000", built_at="2026-10-13T10:27:41Z")
        with tempfile.TemporaryDirectory() as tmp:
            self.write_store(Path(tmp), [newer, older])
            evidence = evidence_for(tmp)
        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual(evidence.tag, newer["tag"])

    def test_sandbox_only_connectors_are_not_resolved_here(self) -> None:
        # Their sandbox contracts live in the Go tables only, so the setup gate
        # keeps its host-based verdict instead of accepting evidence the
        # gateway might refuse.
        for connector in ("kiro", ):
            with self.subTest(connector=connector), tempfile.TemporaryDirectory() as tmp:
                self.write_store(Path(tmp), [claudecode_image(connector=connector)])
                self.assertIsNone(evidence_for(tmp, connector))

    def test_image_version_matches_the_go_sanitizer(self) -> None:
        self.assertEqual(image_version("1.0.2"), "1.0.2")
        self.assertEqual(image_version(" 1.0.2 rc/1 "), "1.0.2-rc-1")
        self.assertEqual(image_version("+1.0.2+"), "1.0.2")
        self.assertEqual(image_version(""), "dev")


class SetupGateUsesTheEvidenceTest(unittest.TestCase):
    """The action-mode setup gate admits a connector with no host CLI only on evidence."""

    def _gate(self, evidence: object) -> bool:
        from types import SimpleNamespace
        from unittest import mock

        from defenseclaw.commands import cmd_setup

        discovery = SimpleNamespace(agents={"claudecode": SimpleNamespace(installed=False, version="", error="")})
        with (
            mock.patch.object(cmd_setup.agent_discovery, "discover_with_probes", return_value=discovery),
            mock.patch.object(cmd_setup, "verified_harness_contract", return_value=evidence) as seen,
            mock.patch.dict("os.environ", {"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT": ""}),
        ):
            admitted = cmd_setup._check_connector_version_supported_for_setup(
                "claudecode", mode="action", emit=False, data_dir="/nonexistent-dc-data"
            )
        seen.assert_called_once_with("/nonexistent-dc-data", "claudecode")
        return admitted

    def test_no_evidence_refuses_action_mode(self) -> None:
        self.assertFalse(self._gate(None))

    def test_current_verified_image_admits_action_mode(self) -> None:
        from defenseclaw.sandbox_images import HarnessImageEvidence

        evidence = HarnessImageEvidence(
            tag="defenseclaw/sandbox:claudecode-41d116a05187f7ae-u1000",
            connector="claudecode",
            harness_version="2.1.156",
            contract_id="claudecode-hooks-v1",
            hook_fire_verified_at="2026-10-13T10:27:46Z",
            defenseclaw_version=RELEASE,
        )
        self.assertTrue(self._gate(evidence))


if __name__ == "__main__":
    unittest.main()
