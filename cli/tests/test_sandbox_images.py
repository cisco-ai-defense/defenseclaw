"""Tests for the harness image evidence the setup gate reads.

F9 companion to internal/gateway/hook_contract_sandbox_evidence_test.go: the
setup gate must accept exactly what the gateway accepts, and nothing else.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from defenseclaw.sandbox_images import (
    verified_harness_contract,
)

RELEASE = "0.8.10"


def verified_claudecode_image(**overrides: object) -> dict:
    record = {
        "tag": "defenseclaw/sandbox:claudecode-41d116a05187f7ae-u1000",
        "image_id": "sha256:b5c5beadc6252084bf397c610cc7a214b62dd4a07213a1ef50d98c1f52eb453e",
        "content_hash": "41d116a05187f7aea74790a94d6bda7be78e5efddc0e42d1d054a14dbacff3f7",
        "connector": "claudecode",
        "harness_version": "2.1.156",
        "hook_contract": "claudecode-hooks-v1",
        "uid": 1000,
        "gid": 1000,
        "ingress_port": 18971,
        "defenseclaw_version": RELEASE,
        "fail_mode": "closed",
        "built_at": "2026-10-02T10:27:41.669899487Z",
        "hook_fire_verified": True,
        "hook_fire_verified_at": "2026-10-02T10:27:46.596385645Z",
    }
    record.update(overrides)
    return record


class VerifiedHarnessContractTest(unittest.TestCase):
    def write_store(self, root: Path, records: list[dict]) -> None:
        directory = root / "sandboxes"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "images.json").write_text(
            json.dumps({"version": 1, "images": records}), encoding="utf-8"
        )

    def test_accepts_fire_verified_image(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.write_store(Path(tmp), [verified_claudecode_image()])
            evidence = verified_harness_contract(tmp, "claudecode", release=RELEASE)
        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual(evidence.harness_version, "2.1.156")
        self.assertEqual(evidence.contract_id, "claudecode-hooks-v1")

    def test_refusals(self) -> None:
        cases = {
            "no store": [],
            "unverified hooks": [verified_claudecode_image(hook_fire_verified=False)],
            "another connector": [verified_claudecode_image(connector="codex")],
            "another release built it": [verified_claudecode_image(defenseclaw_version="0.8.9")],
            # 2.0.0 is below claudecode-hooks-v1's reviewed range (>= 2.1.154).
            "harness version below every reviewed range": [
                verified_claudecode_image(harness_version="2.0.0")
            ],
            "harness version cannot be normalized": [
                verified_claudecode_image(harness_version="not-a-version")
            ],
            "record has no harness version": [verified_claudecode_image(harness_version="")],
        }
        for name, records in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                if records:
                    self.write_store(Path(tmp), records)
                self.assertIsNone(
                    verified_harness_contract(tmp, "claudecode", release=RELEASE),
                    f"{name}: evidence must not be accepted",
                )

    def test_inherits_the_builders_forward_compatibility(self) -> None:
        # A harness version above the newest reviewed minimum is claimed by that
        # contract: the same predicate the image build applied before the record
        # existed (harness.Spec.InstallSteps -> CheckContract).
        with tempfile.TemporaryDirectory() as tmp:
            self.write_store(Path(tmp), [verified_claudecode_image(harness_version="9.9.9")])
            evidence = verified_harness_contract(tmp, "claudecode", release=RELEASE)
        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual(evidence.contract_id, "claudecode-hooks-v2")

    def test_prefers_newest_record(self) -> None:
        older = verified_claudecode_image(
            tag="defenseclaw/sandbox:claudecode-older-u1000",
            built_at="2026-10-01T10:27:41Z",
        )
        newer = verified_claudecode_image(
            tag="defenseclaw/sandbox:claudecode-newer-u1000",
            built_at="2026-10-02T10:27:41Z",
        )
        with tempfile.TemporaryDirectory() as tmp:
            self.write_store(Path(tmp), [older, newer])
            evidence = verified_harness_contract(tmp, "claudecode", release=RELEASE)
        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual(evidence.tag, newer["tag"])

    def test_sandbox_only_connectors_are_not_resolved_here(self) -> None:
        # Their sandbox contracts live in the Go tables only, so the setup gate
        # must keep its host-based verdict instead of accepting evidence the
        # gateway might refuse.
        for connector in ("kiro", "omnigent"):
            with self.subTest(connector=connector), tempfile.TemporaryDirectory() as tmp:
                self.write_store(
                    Path(tmp), [verified_claudecode_image(connector=connector)]
                )
                self.assertIsNone(verified_harness_contract(tmp, connector, release=RELEASE))


if __name__ == "__main__":
    unittest.main()
