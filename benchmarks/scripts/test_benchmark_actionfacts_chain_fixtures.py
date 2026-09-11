# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
import json
import unittest

from benchmarks.scripts import benchmark_actionfacts_chain_fixtures as fixtures


class ActionFactsChainFixtureTests(unittest.TestCase):
    def test_checked_in_fixture_validates(self) -> None:
        data, cases = fixtures.load_jsonl(fixtures.DEFAULT_CORPUS)
        manifest = json.loads(fixtures.DEFAULT_MANIFEST.read_text(encoding="utf-8"))
        fixtures.validate_fixture(cases, manifest, corpus_data=data)

    def test_checked_in_fixture_is_reproducible(self) -> None:
        fixtures.write_fixture(fixtures.DEFAULT_CORPUS, fixtures.DEFAULT_MANIFEST, check=True)

    def test_complete_proof_rejects_identity_drift(self) -> None:
        cases, metadata = fixtures.build_fixture()
        cases = copy.deepcopy(cases)
        target = next(case for case in cases if case["id"].endswith("secret-same-path-two-event"))
        target["payload"]["events"][1]["args"]["_actionfacts"]["identities"]["input_ref"] = (
            "path:/fixtures/output/unrelated.txt"
        )
        manifest = fixtures.build_manifest(cases, metadata)
        with self.assertRaisesRegex(fixtures.FixtureValidationError, "invalid identity join"):
            fixtures.validate_fixture(cases, manifest)

    def test_only_over_bound_control_exceeds_eight_events(self) -> None:
        cases, _ = fixtures.build_fixture()
        over_bound = [case for case in cases if len(case["payload"]["events"]) > fixtures.MAX_PROOF_EVENTS]
        self.assertEqual([case["id"] for case in over_bound], [
            "actionfacts-chain-v1/secret-same-path-over-eight-separation"
        ])
        self.assertEqual(over_bound[0]["truth"]["expected_disposition"], "allow")


if __name__ == "__main__":
    unittest.main()
