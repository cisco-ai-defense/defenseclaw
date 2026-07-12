"""Regression tests for the tracked observability-v8 specification gate."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts" / "check_observability_v8_spec.py"
PACKAGE = ROOT / "docs" / "design" / "observability-v8"


def _run(package: Path = PACKAGE) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), "--package", str(package)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )


def _copy_package(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    target = repository / "docs" / "design" / "observability-v8"
    repository.mkdir()
    shutil.copy2(ROOT / "spec.md", repository / "spec.md")
    reference = repository / "schemas" / "config" / "v8" / "reference"
    reference.mkdir(parents=True)
    shutil.copy2(
        ROOT / "schemas" / "config" / "v8" / "reference" / "observability.yaml",
        reference / "observability.yaml",
    )
    target.parent.mkdir(parents=True)
    shutil.copytree(PACKAGE, target)
    return target


def test_observability_v8_spec_is_complete_and_traceable() -> None:
    result = _run()

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.startswith("observability-v8 spec valid: D=")


def test_observability_v8_redaction_contract_locks_machine_boundaries() -> None:
    redaction = (PACKAGE / "04-redaction-contract.md").read_text(encoding="utf-8")
    verification = (PACKAGE / "07-verification-and-acceptance.md").read_text(encoding="utf-8")
    traceability = (PACKAGE / "13-decision-traceability.md").read_text(encoding="utf-8")

    assert "| `credential` | `preserve` | `remove` | `remove` | `remove` |" in redaction
    assert "schemas/telemetry/v8/redaction/detector-catalog-v1.yaml" in redaction
    assert "raw|inspected|transformed|failed_closed" in redaction
    assert "at most 4,198,400 bytes" in redaction
    assert "unicode-age-13.0.json" in redaction
    assert "projection_context_mismatch" in redaction
    assert "one shared success/error fixture" in redaction
    assert "`P-001` through `P-070`" in verification
    assert "| P-038 | 04 §7.6 | 07 §6.3 |" in traceability


def test_observability_v8_structural_contract_is_normative() -> None:
    taxonomy = (PACKAGE / "02-taxonomy-and-data-model.md").read_text(encoding="utf-8")
    verification = (PACKAGE / "07-verification-and-acceptance.md").read_text(
        encoding="utf-8",
    )
    decisions = (PACKAGE / "08-decisions-and-exclusions.md").read_text(encoding="utf-8")
    traces = (PACKAGE / "11-trace-and-span-contract.md").read_text(encoding="utf-8")
    schemas = (PACKAGE / "12-telemetry-schema-architecture.md").read_text(encoding="utf-8")
    traceability = (PACKAGE / "13-decision-traceability.md").read_text(encoding="utf-8")

    assert "| P-069 | Define one typed `registry.yaml` `structural_contract`" in decisions
    assert "| P-069 | 02 §§3-3.6; 11 §§5-6; 12 §§4-6.1,8,10-12 |" in traceability
    assert "`/body/message` and" in taxonomy
    assert "`instrument_data` object is exactly `{value, attributes}`" in taxonomy
    assert "`start_time_unix_nano`" in traces
    assert "Span, event, link, resource, and scope dropped" in verification
    assert "workflow {defenseclaw.workflow.name}" in traces
    assert "id: defenseclaw.canonical-record" in schemas
    assert "connector-known-v1" in schemas
    assert "admin-principal-known-v1" in schemas
    assert "agent-phase-v1" in schemas
    assert "kind: string-int64-bijection" in schemas
    assert "Complete single-fault examples" in schemas
    assert "Candidate-bundle acceptance" in verification


def test_observability_v8_generated_builder_source_contract_is_normative() -> None:
    verification = (PACKAGE / "07-verification-and-acceptance.md").read_text(
        encoding="utf-8",
    )
    decisions = (PACKAGE / "08-decisions-and-exclusions.md").read_text(encoding="utf-8")
    schemas = (PACKAGE / "12-telemetry-schema-architecture.md").read_text(
        encoding="utf-8",
    )
    traceability = (PACKAGE / "13-decision-traceability.md").read_text(
        encoding="utf-8",
    )

    assert "| P-070 | Add one closed generated-builder source contract" in decisions
    assert "| P-070 | 12 §§5.2.3,6,12,17 |" in traceability
    assert "`mandatory_rule_catalog` is the closed object" in schemas
    assert "twelve rules" in schemas
    for rule in (
        "always",
        "control_plane_mutation",
        "approval_resolution",
        "alert_mutation",
        "protected_boundary_auth_failure",
        "enforced_outcome",
        "enforcement_state_change",
        "schema_validation_failure",
        "sqlite_failure",
        "exporter_initialization_failure",
        "durable_health_transition",
        "destination_test_activity",
    ):
        assert f"`{rule}`" in schemas
    assert "`structured_types`" in schemas
    assert "`structured_bindings`" in schemas
    assert "The scalar-leaf arm is" in schemas
    assert "The container/reference arm is" in schemas
    assert "Scalar items use exactly" in schemas
    assert "{name, required, type, field_class, sensitivity, normalization}" in schemas
    assert "{name, required, structured_ref}" in schemas
    assert "{type, field_class, sensitivity, normalization}" in schemas
    assert "{name, type: string, field_class, sensitivity, normalization}" in schemas
    assert "kind: canonical_json" in schemas
    assert "introduced_in: telemetry-registry-v1" in schemas
    assert "arms: [boolean, int64, finite_double, string, array, object]" in schemas
    assert "discriminator: {visibility: internal, wire: false}" in schemas
    assert "leaf_privacy: {field_class: content, sensitivity: sensitive}" in schemas
    assert "member_id: entry" in schemas
    for limit, value in (
        ("max_depth", 8),
        ("max_aggregate_members", 256),
        ("max_array_items", 256),
        ("max_string_utf8_bytes", 4096),
        ("max_member_name_utf8_bytes", 256),
        ("max_item_bytes", 32768),
        ("max_canonical_bytes", 65536),
    ):
        assert f"{limit}: {value}" in schemas
    assert "The root object or array is at depth zero" in schemas
    assert "counts every object entry plus every" in schemas
    assert "canonical UTF-8 JSON" in schemas
    assert "public_encoding: ordered_typed_entries" in schemas
    assert "wire_encoding: native_object_properties" in schemas
    assert "duplicate_name_policy: reject" in schemas
    assert "fixed_name_collision_policy: reject" in schemas
    assert "post_redaction_name_collision_policy: reject" in schemas
    assert "`structured_member_name_collision`" in schemas
    assert "arm_id: generic" in schemas
    assert "exclude_registered_tags: true" in schemas
    assert "with empty `fields`" in schemas
    assert "no `dynamic_members` is invalid" in schemas
    assert "reject null at any nesting depth" in schemas
    assert "Upstream nullable optional properties normalize" in schemas
    assert "only by omission" in schemas
    for type_id in (
        "gen_ai.canonical_json",
        "gen_ai.tool_call_arguments",
        "gen_ai.tool_call_result",
        "gen_ai.input_messages",
        "gen_ai.output_messages",
        "gen_ai.message_parts",
        "gen_ai.message_part",
        "gen_ai.chat_message",
        "gen_ai.output_message",
        "gen_ai.text_part",
        "gen_ai.tool_call_request_part",
        "gen_ai.tool_call_response_part",
        "gen_ai.server_tool_call_part",
        "gen_ai.server_tool_call_response_part",
        "gen_ai.blob_part",
        "gen_ai.file_part",
        "gen_ai.uri_part",
        "gen_ai.reasoning_part",
        "gen_ai.compaction_part",
        "gen_ai.generic_part",
        "gen_ai.generic_server_tool_payload",
    ):
        assert f"`{type_id}`" in schemas
    for tag in (
        "text",
        "tool_call",
        "tool_call_response",
        "server_tool_call",
        "server_tool_call_response",
        "blob",
        "file",
        "uri",
        "reasoning",
        "compaction",
    ):
        assert f"| `{tag}` | `gen_ai." in schemas
    assert "union owns the" in schemas
    assert "only wire `type` discriminator" in schemas
    for path, digest in (
        (
            "model/gen-ai/gen-ai-input-messages.json",
            "034fcd8c87f1e013f3a5a5018503210e2bee4d2499c361823b96e906d40a50ad",
        ),
        (
            "model/gen-ai/gen-ai-output-messages.json",
            "a825a6c0cc1b7b22fdbfb9488d8dc3a318be3897ef6d3dbae01a10297bb6e569",
        ),
        (
            "model/gen-ai/gen-ai-tool-call-arguments.json",
            "73607a8e8d9e84393475ef460108c59dbb9e1d2ddc0d0177fce6f735a62367ea",
        ),
        (
            "model/gen-ai/gen-ai-tool-call-result.json",
            "44eb4a93b05eea7da14489f1d253814c6429772d1fe869f8f6fc1749d7593412",
        ),
    ):
        assert f"`{path}`" in schemas
        assert f"`{digest}`" in schemas
    assert "Version 1 is exactly" in schemas
    for attribute in (
        "gen_ai.input.messages",
        "gen_ai.output.messages",
        "gen_ai.tool.call.arguments",
        "gen_ai.tool.call.result",
    ):
        assert f"| `{attribute}` |" in schemas
    assert (
        "| `gen_ai.tool.call.arguments` | `gen_ai.tool_call_arguments` | "
        "`ordered_typed_entries` | `native_json_object` |"
    ) in schemas
    assert (
        "| `gen_ai.tool.call.result` | `gen_ai.tool_call_result` | `ordered_typed_entries` | `native_json_object` |"
    ) in schemas
    assert "distinct closed" in schemas
    assert "invalid as the whole arguments or" in schemas
    assert "Local scalar arrays" in schemas
    assert "complete property-disposition table" in schemas
    assert "tagged-union discriminators" in verification
    assert "Expansion proves every reachable" in verification
    assert "concrete leaf exactly once" in verification
    assert "object/array/variant container carry none" in verification
    assert "`go_symbol_policy` is exactly" in schemas
    assert "defenseclaw: DefenseClaw" in schemas
    assert "opentelemetry: OpenTelemetry" in schemas
    assert "otel: OTel" in schemas
    assert "separators: ['.', '-', '/', '_']" in schemas
    assert (
        "initialisms: [AI, API, DB, HEC, HTTP, ID, JSON, LLM, OTEL, OTLP, PII, RPC, SDK, SQL, TLS, URL, UTF8]"
    ) in schemas
    assert "lowercase `brand_spellings` lookup first" in schemas
    assert "uppercase `initialisms` lookup second" in schemas
    assert "ordinary title-case last" in schemas
    assert "public structured type for `gen_ai.canonical_json` is" in schemas
    assert "`TelemetryStructuredGenAICanonicalJSON`" in schemas
    assert "`<MemberName>` comes from a fixed field `name` or from `member_id`" in schemas
    assert "`<ArmName>` comes from a registered `tag`, or from `arm_id`" in schemas
    assert "No global row count is an\nauthored contract" in schemas
    assert "The table order is the declaration-kind order above" in schemas
    assert "`[[kind,source_id,symbol,declaration_form], ...]`" in schemas
    assert "`DefenseClaw GoSymbolTableIR v1` plus one NUL byte" in schemas
    assert "it is not a hand-maintained acceptance value" in schemas
    assert "never requires editing a\ncount, digest, or digest-addressed symbol-table baseline" in schemas
    for successor_id in (
        "user.id",
        "defenseclaw.tool.id",
        "defenseclaw.agent.reported_cost.present",
        "defenseclaw.agent.reported_cost.usd",
        "agent-reported-cost-available-v1",
    ):
        assert f"`{successor_id}`" in schemas
    assert "Every one of the five builders\nrequires the availability Boolean" in schemas
    assert "`false` forbids the USD value, while `true`\nrequires a finite nonnegative value" in schemas
    assert "`llm.cost.total` is not a default alias" in schemas
    assert "explicitly Galileo-ineligible" in schemas
    assert "rather than fabricate any of those values" in schemas
    assert "compiler-owned `declaration_form`" in schemas
    assert "`exported_const`, `exported_type`, `exported_function`, and" in schemas
    assert "emits every row exactly" in schemas
    assert "emit no row as both a constant and a type" in schemas
    assert "whose\n  `declaration_form` is `exported_const`" in schemas
    assert "17 `TelemetryStructuredArm*` types are absent as constants" in schemas
    assert "The override `kind` vocabulary is exactly" in schemas
    assert "`span_link_constructor`" in schemas
    assert "`<structured_type_id>#<member_id_or_arm_id>`" in schemas
    assert "`<span_family_id>#<event_name_or_relation>`" in schemas
    assert "A free-standing rename" in schemas
    assert "Registry v1 has no prior" in schemas
    assert "`go_symbol_overrides` is absent or an empty list" in schemas
    assert "The complete `GoSymbolTableIR`\n  contains one stable symbol" in verification
    assert "Override fixtures cover all closed `kind` tokens" in verification
    assert "a prose reason\n  never authorizes a rename" in verification
    assert "Additive rows do\n  not require a hand-edited count, digest, or symbol-table baseline" in verification
    assert "false-plus-value is `forbidden_field`" in verification
    assert "true-without-value is `missing_required`" in verification
    assert "reported zero succeeds" in verification
    assert "no default `llm.cost.total`" in verification
    assert "Galileo-ineligible without fabricated" in verification
    for namespace in (
        "TelemetryAttribute<Name>",
        "TelemetryFamily<Name>",
        "TelemetryEvent<Name>",
        "TelemetrySpanEvent<Name>",
        "TelemetryLinkRelation<Name>",
        "TelemetryInstrument<Name>",
        "TelemetryCondition<Name>",
        "TelemetryConditionFact<Name>",
        "TelemetryPhase<Name>",
        "TelemetryPhaseCode<Name>",
        "TelemetrySemanticProfile<Name>",
        "TelemetryStructured<Name>",
        "TelemetryStructuredMember<TypeName><MemberName>",
        "TelemetryStructuredArm<TypeName><ArmName>",
        "<TypeName><MemberName>MemberInput",
        "New<TypeName><MemberName>Member",
        "Log<Name>Input",
        "Span<Name>Input",
        "Metric<Name>Input",
        "BuildLog<Name>",
        "BuildSpan<Name>",
        "BuildMetric<Name>",
        "NewSpan<FamilyName><EventName>Event",
        "NewSpan<FamilyName><RelationName>Link",
    ):
        assert f"`{namespace}`" in schemas
    assert "auto_suffix_policy: reject" in schemas
    assert "collision_policy: reject" in schemas
    assert "never appends a numeric, signal, or" in schemas
    assert "BuildTelemetry<Family>" not in schemas
    assert "Telemetry<Family>Input" not in schemas
    assert "`GoSymbolTableIR`" in schemas
    assert "`builder_context`" in schemas
    assert "`CandidateRenderIndex`" in schemas
    assert "`EnrichedFieldDescriptor`" in schemas
    assert "`EnrichedContainerDescriptor`" in schemas
    assert "`GoAPIPlanIR`" in schemas
    assert "`GoDeclarationPlanIR`" in schemas
    assert "The compiler-derived symbol table is the package-declaration ABI" in schemas
    assert "governed by `boolean_attribute`" in schemas
    assert "exposes no independent condition selector" in schemas
    assert "`service.version <- provenance.binary_version`" in schemas
    assert "`trace_scope.version <- provenance.binary_version`" in schemas
    assert "selected canonical family is the sole floor authority" in schemas
    assert "`Condition<FactName>`" in schemas
    assert "`Mandatory<FactName>`" in schemas
    assert "No generated public field" in schemas
    assert "`candidate_render_index_sha256`" in schemas
    assert "carrying no field class, sensitivity, or" in schemas
    assert "`ConditionIR.enforcement.fact` tokens" in schemas
    assert "never condition IDs, display names, or Go" in schemas
    assert "`^[a-z][a-z0-9-]{0,127}$`" in schemas
    assert "renderer coordinator preflights the complete output set" in schemas
    assert "unique both byte-for-byte and after NFC case folding" in schemas
    assert "`a/../../catalog`" in verification
    assert "129-character IDs" in verification
    for path in (
        "internal/observability/zz_generated_telemetry_ids.go",
        "internal/observability/zz_generated_telemetry_catalog.go",
        "internal/observability/zz_generated_telemetry_producers.go",
        "internal/observability/zz_generated_telemetry_builders_genai.go",
        "internal/observability/zz_generated_telemetry_builders_security.go",
        "internal/observability/zz_generated_telemetry_builders_operations.go",
        "internal/observability/zz_generated_telemetry_builder_fixtures_test.go",
    ):
        assert path in schemas
    assert "validates all seven as one in-memory candidate" in schemas
    assert "not to transient filesystem visibility" in schemas
    assert "expects no concurrent mutation of its explicit output paths" in schemas
    assert "final committed checked-in state" in schemas
    assert "the direct writer\n  repeats containment, symlink" in verification
    assert "an interruption leaves no false success" in verification
    assert "never a durable journal, rollback database, ownership manifest" in decisions
    assert "`legacy.audit.*`" in schemas
    assert "The former candidate-generation blockers are resolved" in schemas
    assert "Generated-builder source authority" in verification
    assert "exactly version 1 and its eleven" in verification
    assert "Expanded producer-row tests" in verification
    assert "Derived-value fixtures cover all eleven trace derivations" in verification
    assert "complete compiler-owned `GoAPIPlanIR`" in verification
    assert "accepted together or none is accepted" in verification


def test_observability_v8_delivery_contract_locks_machine_boundaries() -> None:
    configuration = (PACKAGE / "03-configuration-contract.md").read_text(
        encoding="utf-8",
    )
    storage = (PACKAGE / "05-storage-retention-and-delivery.md").read_text(
        encoding="utf-8",
    )
    traceability = (PACKAGE / "13-decision-traceability.md").read_text(
        encoding="utf-8",
    )

    assert "`batch.max_queue_bytes`" in configuration
    assert "`batch.max_export_batch_bytes`" in configuration
    assert "newest attempted enqueue is dropped" in storage
    assert "immutable projection selected and redacted for that" in storage
    assert "Splunk destination" in storage
    assert "| P-062 | 01 §10; 03 §§1.1,2.1,4.4; 05 §§6-7 |" in traceability
    assert "| P-063 | 03 §4.4; 05 §7.1 |" in traceability


def test_observability_v8_spec_detects_missing_traceability(tmp_path: Path) -> None:
    package = _copy_package(tmp_path)
    path = package / "13-decision-traceability.md"
    text = path.read_text(encoding="utf-8")
    path.write_text(
        text.replace("| P-047 |", "| P-999 |", 1),
        encoding="utf-8",
    )

    result = _run(package)

    assert result.returncode == 1
    assert "decisions missing traceability rows: ['P-047']" in result.stderr
    assert "traceability rows without decisions: ['P-999']" in result.stderr


def test_observability_v8_spec_detects_broken_package_link(tmp_path: Path) -> None:
    package = _copy_package(tmp_path)
    path = package / "README.md"
    path.write_text(
        path.read_text(encoding="utf-8") + "\n[missing](not-present.md)\n",
        encoding="utf-8",
    )

    result = _run(package)

    assert result.returncode == 1
    assert "README.md: missing linked path 'not-present.md'" in result.stderr


def test_observability_v8_spec_ignores_rows_and_links_in_fences(tmp_path: Path) -> None:
    package = _copy_package(tmp_path)
    path = package / "README.md"
    path.write_text(
        path.read_text(encoding="utf-8")
        + "\n```markdown\n"
        + "| D-001 | illustrative duplicate |\n"
        + "| P-999 | illustrative contract | illustrative test |\n"
        + "[illustrative missing link](not-present.md)\n"
        + "```\n",
        encoding="utf-8",
    )

    result = _run(package)

    assert result.returncode == 0, result.stdout + result.stderr


def test_observability_v8_spec_detects_unclosed_tilde_fence(tmp_path: Path) -> None:
    package = _copy_package(tmp_path)
    path = package / "README.md"
    path.write_text(
        path.read_text(encoding="utf-8") + "\n~~~yaml\nunclosed: true\n",
        encoding="utf-8",
    )

    result = _run(package)

    assert result.returncode == 1
    assert "README.md: unbalanced fenced code blocks" in result.stderr
