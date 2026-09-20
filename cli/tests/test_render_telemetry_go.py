# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import dataclasses
import importlib.util
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"


def _load(name: str, path: Path) -> Any:
    existing = sys.modules.get(name)
    if existing is not None:
        assert Path(existing.__file__).resolve() == path.resolve()
        return existing
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_load("telemetry_canonical_record", SCRIPTS / "telemetry_canonical_record.py")
_load("telemetry_go_inbound_plan", SCRIPTS / "telemetry_go_inbound_plan.py")
_load("telemetry_go_api_plan", SCRIPTS / "telemetry_go_api_plan.py")
coordinator = _load("telemetry_go_output_coordinator", SCRIPTS / "telemetry_go_output_coordinator.py")
_load("telemetry_go_producer_plan", SCRIPTS / "telemetry_go_producer_plan.py")
_load("telemetry_go_fixture_plan", SCRIPTS / "telemetry_go_fixture_plan.py")
renderer = _load("render_telemetry_go_test", SCRIPTS / "render_telemetry_go.py")


@pytest.fixture(scope="module")
def candidate_index() -> Any:
    generator = _load("telemetry_go_render_real_generator", SCRIPTS / "generate_telemetry_registry.py")
    candidate_renderer = _load(
        "telemetry_go_render_real_candidate_renderer",
        SCRIPTS / "render_telemetry_registry_candidates.py",
    )
    view = generator.compile_registry(ROOT).materialized_view
    return candidate_renderer.build_candidate_render_index(view)


@pytest.fixture(scope="module")
def rendered(candidate_index: Any) -> Any:
    return renderer.render_go_candidate(candidate_index)


def test_real_candidate_renders_exact_complete_deterministic_outputs(
    candidate_index: Any,
    rendered: Any,
) -> None:
    repeated = renderer.render_go_candidate(candidate_index)
    assert repeated == rendered
    assert tuple(item.path for item in rendered.outputs) == coordinator.EXACT_GO_OUTPUT_PATHS
    assert tuple(item.path for item in rendered.declaration_inventory) == coordinator.EXACT_GO_OUTPUT_PATHS
    assert len(rendered.expected_declaration_keys) == sum(
        len(item.declaration_keys) for item in rendered.declaration_inventory
    )
    assert all(isinstance(item, coordinator.RenderedGoOutput) for item in rendered.outputs)
    assert all(isinstance(item, coordinator.GoFileDeclarationInventory) for item in rendered.declaration_inventory)

    payloads = {item.path: item.payload for item in rendered.outputs}
    assert payloads[coordinator.EXACT_GO_OUTPUT_PATHS[0]].count(b"\n\tTelemetry") == len(
        rendered.declaration_inventory[0].declaration_keys
    )
    family_counts = Counter(item.signal for item in candidate_index.enriched_families.values())
    family_total = sum(family_counts.values())
    catalog = payloads[coordinator.EXACT_GO_OUTPUT_PATHS[1]]
    base_contracts = catalog.split(b"var generatedFamilyBaseContracts = map[string]familyDescriptorContract{", 1)[1]
    base_contracts = base_contracts.split(b"\n}\n", 1)[0]
    assert base_contracts.count(b'\n\t"') == family_total
    assert catalog.count(b" familyTraceContract() familyTraceContract {") == family_counts["traces"]
    assert catalog.count(b" familyMetricContract() familyMetricContract {") == family_counts["metrics"]
    assert (
        f"func generatedFamilyIdentityDescriptors() [{family_total}]generatedFamilyIdentityDescriptor".encode()
        in catalog
    )
    identity_table = catalog.split(b"func generatedFamilyIdentityDescriptors()", maxsplit=1)[1]
    assert identity_table.count(b"Descriptor: generated") == family_total
    assert identity_table.count(b"Signal: SignalLogs") == family_counts["logs"]
    assert identity_table.count(b"Signal: SignalTraces") == family_counts["traces"]
    assert identity_table.count(b"Signal: SignalMetrics") == family_counts["metrics"]
    producer = payloads[coordinator.EXACT_GO_OUTPUT_PATHS[2]]
    producer_plan = renderer.compile_go_producer_plan(candidate_index)
    assert producer.count(b"FamilyRefs: generatedProducerFamilyRefs{") == len(producer_plan.identities)
    assert producer.count(b"IdentityKeys: []generatedProducerIdentityKey{") == len(producer_plan.context_sets)
    assert producer.count(b"ContextIdentitySetID:") == len(producer_plan.groups)
    assert b"var generatedInboundNonNativeMatches = []generatedInboundMatch{" in producer
    assert b"var generatedInboundNonNativeTargets = []generatedInboundTarget{" in producer
    assert b"var generatedInboundMatches, generatedInboundTargets = deriveGeneratedInboundNativeCatalog(" in producer
    assert b'ClassID: "otlp.native.' not in producer
    assert b"NativeRoundTrip: true" not in producer
    assert b"var generatedInboundNativeMarkers = []generatedInboundNativeMarker{" in producer
    assert b"var generatedInboundEchoRecognizers = []generatedInboundEchoRecognizer{" in producer
    assert b"var generatedInboundImportContexts = []generatedInboundImportContext{" in producer
    assert b"generatedInboundSemanticInstanceKey" in producer and b'"defenseclaw.instance.id"' in producer
    assert (
        b"generatedInboundForwardInstanceKey" in producer and b'"defenseclaw.telemetry.forward.instance_id"' in producer
    )
    assert b"generatedInboundUnknownFields" in producer and b'"drop_and_count"' in producer
    assert b"generatedInboundNativeMarkerRule" in producer
    assert b"generatedInboundStructuralMarkerRule" in producer
    assert b"generatedInboundNativeMalformedDisposition" in producer
    assert b"&generatedInboundTargetOverride{" in producer
    assert b"type generatedInboundUnitScale struct" in producer
    assert b"type generatedInboundUnitRule struct" in producer
    assert b"SourceUnitRule:" in producer and b"generatedInboundUnitRule{" in producer
    assert b"InstrumentUnit:" in producer
    assert b'SourceUnit: "milliseconds", Scale: 0.001' in producer
    assert b'SourceUnit: "tokens", Scale: 1.0' in producer
    assert b"FieldRefs:" in producer and b"[]string{" in producer
    domains = b"".join(payloads[path] for path in coordinator.EXACT_GO_OUTPUT_PATHS[3:6])
    assert domains.count(b"func (builder *FamilyBuilder) Build") == family_total
    assert domains.count(b"func New") > 0
    assert domains.count(b"func ValidateTelemetryResourceAttributes") == 1
    assert domains.count(b"type ") >= 464
    assert b"type SpanGuardrailJudgeInput struct" in domains
    judge_input = domains.split(b"type SpanGuardrailJudgeInput struct", maxsplit=1)[1].split(b"}\n", maxsplit=1)[0]
    assert [b"DefenseClawJudgeKind", b"string"] in [line.split() for line in judge_input.splitlines()]
    fixtures = payloads[coordinator.EXACT_GO_OUTPUT_PATHS[6]]
    fixture_plan = renderer.compile_go_fixture_plan(candidate_index)
    assert fixtures.count(b"func TestGeneratedTelemetry") == len(fixture_plan.curated_cases)
    assert b"TestGeneratedTelemetryCoverage" not in fixtures
    assert b"generatedFamilyBuilderMethodContractsJSON" not in fixtures
    assert all(b"func init(" not in payload for payload in payloads.values())
    current_registry_symbols = (
        b"registeredEventNameSet",
        b"registeredEventNameOrder",
        b"registeredLogEventNameSet",
        b"registeredTraceEventNameSet",
        b"registeredMetricEventNameSet",
        b"buildEventNameRegistry",
    )
    assert all(symbol not in payload for payload in payloads.values() for symbol in current_registry_symbols)


def test_real_candidate_preflights_with_one_digest_bound_inventory(rendered: Any) -> None:
    result = coordinator.preflight_go_outputs(
        rendered.outputs,
        rendered.declaration_inventory,
        expected_declaration_keys=rendered.expected_declaration_keys,
        materialized_view_sha256=rendered.materialized_view_sha256,
        candidate_render_index_sha256=rendered.candidate_render_index_sha256,
        go_symbol_table_sha256=rendered.go_symbol_table_sha256,
    )
    assert len(result.outputs) == 7
    assert result.metadata.materialized_view_sha256 == rendered.materialized_view_sha256
    assert result.metadata.candidate_render_index_sha256 == rendered.candidate_render_index_sha256
    assert result.metadata.go_symbol_table_sha256 == rendered.go_symbol_table_sha256


def test_real_render_is_already_gofmt_clean_and_compiles_without_rewrite(rendered: Any, tmp_path: Path) -> None:
    replacements: dict[str, str] = {}
    generated_paths: list[str] = []
    for output in rendered.outputs:
        replacement = tmp_path / output.path
        replacement.parent.mkdir(parents=True, exist_ok=True)
        replacement.write_bytes(output.payload)
        replacements[str(ROOT / output.path)] = str(replacement)
        generated_paths.append(str(replacement))

    formatted = subprocess.run(
        ["gofmt", "-d", *generated_paths],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert formatted.returncode == 0, formatted.stderr
    assert formatted.stdout == "", formatted.stdout

    overlay = tmp_path / "overlay.json"
    overlay.write_text(json.dumps({"Replace": replacements}, sort_keys=True), encoding="utf-8")
    compiled = subprocess.run(
        [
            "go",
            "test",
            f"-overlay={overlay}",
            "./internal/observability",
            "-run",
            "^TestGeneratedTelemetry",
            "-count=1",
            "-v",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
        env={**os.environ, "DEFENSECLAW_GENERATED_TELEMETRY_ROOT": str(tmp_path)},
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    assert "--- PASS: TestGeneratedTelemetryExplicitOverlayCandidate" in compiled.stdout


def test_supplied_api_plan_must_be_the_candidate_owned_plan(candidate_index: Any) -> None:
    forged = dataclasses.replace(candidate_index.go_api_plan, version=2)
    with pytest.raises(renderer.GoRenderError, match="supplied GoAPIPlanIR disagree"):
        renderer.render_go_candidate(candidate_index, forged)


def test_mixed_candidate_and_api_materialized_digests_fail_before_render(candidate_index: Any) -> None:
    forged = dataclasses.replace(candidate_index, materialized_view_sha256="9" * 64)
    with pytest.raises(renderer.GoRenderError, match="materialized-view digests disagree"):
        renderer.render_go_candidate(forged)


def test_unknown_producer_body_opcode_fails_closed(
    candidate_index: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    producer = renderer.compile_go_producer_plan(candidate_index)
    function = producer.file.functions[0]
    operation = dataclasses.replace(function.body_operations[0], opcode="raw_go_escape")
    function = dataclasses.replace(function, body_operations=(operation, *function.body_operations[1:]))
    file_plan = dataclasses.replace(producer.file, functions=(function, *producer.file.functions[1:]))
    forged = dataclasses.replace(producer, file=file_plan)
    monkeypatch.setattr(renderer, "compile_go_producer_plan", lambda _: forged)
    monkeypatch.setattr(renderer, "RenderedGoOutput", lambda *_: pytest.fail("partial output object escaped"))
    with pytest.raises(renderer.GoRenderError, match="missing or unknown body opcode"):
        renderer.render_go_candidate(candidate_index)


def test_stale_candidate_digest_rejects_mutated_relation_before_output_construction(
    candidate_index: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = candidate_index.go_api_plan
    descriptor_at, descriptor = next(
        (position, item)
        for position, item in enumerate(plan.descriptors)
        if item.catalog_contract.base.cross_field_relations
    )
    base = descriptor.catalog_contract.base
    relation = base.cross_field_relations[0]
    mutated_entry = dataclasses.replace(relation.entries[0], code=relation.entries[0].code + 1)
    mutated_relation = dataclasses.replace(relation, entries=(mutated_entry, *relation.entries[1:]))
    mutated_base = dataclasses.replace(
        base,
        cross_field_relations=(mutated_relation, *base.cross_field_relations[1:]),
    )
    mutated_catalog = dataclasses.replace(descriptor.catalog_contract, base=mutated_base)
    mutated_descriptor = dataclasses.replace(descriptor, catalog_contract=mutated_catalog)
    mutated_plan = dataclasses.replace(
        plan,
        descriptors=(
            *plan.descriptors[:descriptor_at],
            mutated_descriptor,
            *plan.descriptors[descriptor_at + 1 :],
        ),
    )
    mutated_plan = dataclasses.replace(
        mutated_plan,
        api_plan_sha256=mutated_plan.recomputed_digest(),
    )
    forged = dataclasses.replace(
        candidate_index,
        go_api_plan=mutated_plan,
        api_plan_sha256=mutated_plan.api_plan_sha256,
    )
    monkeypatch.setattr(renderer, "RenderedGoOutput", lambda *_: pytest.fail("partial output object escaped"))
    monkeypatch.setattr(renderer, "compile_go_producer_plan", lambda _: pytest.fail("producer compilation escaped"))
    monkeypatch.setattr(renderer, "compile_go_fixture_plan", lambda _: pytest.fail("fixture compilation escaped"))
    with pytest.raises(renderer.GoRenderError, match="CandidateRenderIndex digest disagrees"):
        renderer.render_go_candidate(forged)


def test_relation_code_requires_bounded_signed_int64(candidate_index: Any) -> None:
    descriptor = next(
        item for item in candidate_index.go_api_plan.descriptors if item.catalog_contract.base.cross_field_relations
    )
    base = descriptor.catalog_contract.base
    relation = base.cross_field_relations[0]
    invalid_entry = dataclasses.replace(relation.entries[0], code=1 << 63)
    invalid_relation = dataclasses.replace(relation, entries=(invalid_entry, *relation.entries[1:]))
    invalid_base = dataclasses.replace(
        base,
        cross_field_relations=(invalid_relation, *base.cross_field_relations[1:]),
    )
    with pytest.raises(renderer.GoRenderError, match="signed 64-bit integer"):
        renderer._base_contract_literal(invalid_base, "test.base")


def test_catalog_renderer_rejects_duplicate_family_identity(candidate_index: Any) -> None:
    plan = candidate_index.go_api_plan
    duplicate = dataclasses.replace(
        plan.descriptors[1],
        identity_bucket=plan.descriptors[0].identity_bucket,
        signal=plan.descriptors[0].signal,
        identity_name=plan.descriptors[0].identity_name,
    )
    forged = dataclasses.replace(plan, descriptors=(plan.descriptors[0], duplicate, *plan.descriptors[2:]))
    with pytest.raises(renderer.GoRenderError, match="duplicate family identity"):
        renderer._render_catalog_body(forged)


def test_catalog_renderer_has_no_hand_maintained_global_family_count(candidate_index: Any) -> None:
    plan = candidate_index.go_api_plan
    forged = dataclasses.replace(plan, descriptors=plan.descriptors[:-1])
    rendered = renderer._render_catalog_body(forged)
    base_contracts = rendered.split(b"var generatedFamilyBaseContracts = map[string]familyDescriptorContract{", 1)[1]
    base_contracts = base_contracts.split(b"\n}\n", 1)[0]
    assert base_contracts.count(b'\n\t"') == len(forged.descriptors)


def test_renderer_uses_the_compiler_owned_cross_field_relation_bound() -> None:
    assert renderer.MAX_CROSS_FIELD_RELATION_ENTRIES == 8192


def test_mapping_roots_are_rejected_as_noncanonical_typed_ir() -> None:
    with pytest.raises(renderer.GoRenderError, match="canonical typed CandidateRenderIndex"):
        renderer.render_go_candidate({"go_api_plan": {}})


def test_missing_private_declaration_fails_closed(candidate_index: Any) -> None:
    plan = candidate_index.go_api_plan
    missing = plan.private_declarations[-1]
    files = tuple(
        dataclasses.replace(
            file_plan,
            private_declarations=tuple(
                item for item in file_plan.private_declarations if item.declaration_id != missing.declaration_id
            ),
        )
        for file_plan in plan.files
    )
    forged = dataclasses.replace(plan, private_declarations=plan.private_declarations[:-1], files=files)
    with pytest.raises(renderer.GoRenderError, match="private declaration coverage is incomplete"):
        renderer._validate_private_declaration_coverage(forged, files)


def test_unknown_fixture_expression_opcode_fails_closed() -> None:
    forged = type(
        "ForgedExpression",
        (),
        {
            "arm": "raw_go_escape",
            "type_ref": type("TypeRef", (), {"arm": "builtin", "name": "string", "element": None})(),
            "arguments": (),
        },
    )()
    with pytest.raises(renderer.GoRenderError, match="unknown fixture expression arm"):
        renderer._fixture_expression(forged, "forged")


def test_unpaired_surrogate_is_rejected_before_payload_construction() -> None:
    with pytest.raises(renderer.GoRenderError, match="unpaired surrogate"):
        renderer._go_string("bad\ud800", "test")


def test_renderer_source_has_no_filesystem_registry_or_current_go_dependency() -> None:
    source = (SCRIPTS / "render_telemetry_go.py").read_text(encoding="utf-8")
    assert "pathlib" not in source
    assert "open(" not in source
    assert "import subprocess" not in source
    assert "from subprocess import" not in source
    assert "import yaml" not in source.casefold()
    assert "yaml." not in source.casefold()
    assert "zz_generated_telemetry" not in source
    assert 'split("#"' not in source
    assert "split('.')" not in source


def test_render_candidate_is_recursively_immutable(rendered: Any) -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        rendered.outputs = ()
