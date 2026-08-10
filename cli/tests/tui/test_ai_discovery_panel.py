# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""AI Discovery panel parity tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from defenseclaw.tui.panels.ai_discovery import (
    AIDiscoveryPanelModel,
    AIUsageComponent,
    AIUsageModel,
    AIUsageRuntime,
    AIUsageSignal,
    AIUsageSnapshot,
    AIUsageSummary,
    format_confidence,
    humanize_age,
    state_weight,
)
from defenseclaw.tui.services.ai_discovery_state import (
    AIUsageModelProvenance,
    country_flag,
    format_model_country,
)


def _snapshot_with_component(count: int = 3) -> AIUsageSnapshot:
    now = datetime(2026, 5, 5, 12, tzinfo=timezone.utc)
    last_active = now - timedelta(minutes=2)
    return AIUsageSnapshot(
        enabled=True,
        summary=AIUsageSummary(active_signals=count, new_signals=count, total_signals=count),
        signals=tuple(
            AIUsageSignal(
                signal_id=f"sig-{index:02d}",
                signature_id="anthropic-sdk-npm",
                name="Anthropic Claude SDK",
                vendor="Anthropic",
                product="Anthropic Claude",
                category="package_dependency",
                state="new",
                detector="package_manifest",
                source="scan",
                identity_score=0.91,
                identity_band="high",
                presence_score=0.78,
                presence_band="medium",
                first_seen=now,
                last_seen=now,
                last_active_at=last_active,
                component=AIUsageComponent(ecosystem="npm", name="@anthropic-ai/sdk", version="0.20.0"),
            )
            for index in range(count)
        ),
        fetched_at=now,
    )


def test_ai_discovery_no_snapshot_and_disabled_states() -> None:
    panel = AIDiscoveryPanelModel()
    assert "snapshot not yet available" in panel.empty_state()
    assert "DEFENSECLAW_GATEWAY_TOKEN" in panel.empty_state()

    panel.set_snapshot(AIUsageSnapshot(enabled=False))
    assert "disabled" in panel.empty_state()
    assert "agent discovery enable" in panel.empty_state()


def test_ai_discovery_snapshot_decodes_and_surfaces_live_model_lookup_state() -> None:
    offline = AIUsageSnapshot.from_mapping({"enabled": True})
    assert offline.lookup_model_provenance_online is False

    online = AIUsageSnapshot.from_mapping(
        {
            "enabled": True,
            "lookup_model_provenance_online": True,
            "summary": {"active_signals": 1, "files_scanned": 2},
        }
    )
    assert online.lookup_model_provenance_online is True

    panel = AIDiscoveryPanelModel()
    panel.set_snapshot(online)
    assert panel.header_parts() == (
        "active=1",
        "files=2",
        "model-lookup=online",
    )


def test_ai_discovery_scan_uses_the_usage_scan_command() -> None:
    panel = AIDiscoveryPanelModel()
    intent = panel.scan_intent()
    assert intent.label == "agent discovery scan"
    assert intent.args == ("agent", "discovery", "scan")


def test_ai_discovery_dedups_signals_by_component_and_renders_confidence() -> None:
    panel = AIDiscoveryPanelModel()
    panel.set_snapshot(_snapshot_with_component(3))

    assert len(panel.rows) == 1
    row = panel.rows[0]
    assert row.count == 3
    assert row.identity_label == "high (91%)"
    assert row.presence_label == "medium (78%)"
    assert panel.data_table_rows()[0][7] == "3"


def test_ai_discovery_filter_filters_and_persists_across_refresh() -> None:
    now = datetime.now(timezone.utc)
    snapshot = AIUsageSnapshot(
        enabled=True,
        summary=AIUsageSummary(active_signals=2),
        signals=(
            AIUsageSignal(
                signal_id="s1",
                state="new",
                category="ai_cli",
                product="Codex",
                vendor="OpenAI",
                detector="binary",
                first_seen=now,
                last_seen=now,
            ),
            AIUsageSignal(
                signal_id="s2",
                state="new",
                category="active_process",
                product="Cursor",
                vendor="Anysphere",
                detector="process",
                first_seen=now,
                last_seen=now,
            ),
        ),
        fetched_at=now,
    )
    panel = AIDiscoveryPanelModel()
    panel.set_snapshot(snapshot)
    assert len(panel.filtered) == 2

    panel.set_filter("codex")
    assert [row.product for row in panel.filtered] == ["Codex"]
    panel.set_snapshot(snapshot)
    assert panel.filter_text == "codex"
    assert [row.product for row in panel.filtered] == ["Codex"]

    panel.set_filter("PROCESS")
    assert [row.product for row in panel.filtered] == ["Cursor"]
    assert panel.filtered[0].detectors == ("process",)


def test_ai_discovery_detail_toggle_and_header_omit_empty_component() -> None:
    now = datetime.now(timezone.utc)
    panel = AIDiscoveryPanelModel()
    panel.set_snapshot(
        AIUsageSnapshot(
            enabled=True,
            summary=AIUsageSummary(active_signals=1),
            signals=(
                AIUsageSignal(
                    signal_id="s1",
                    state="seen",
                    product="Cursor",
                    vendor="Anysphere",
                    detector="process",
                    runtime=AIUsageRuntime(pid=123, user="me", uptime_sec=90, comm="cursor"),
                    first_seen=now,
                    last_seen=now,
                    last_active_at=now - timedelta(minutes=4),
                ),
            ),
            fetched_at=now,
        )
    )

    panel.toggle_detail()
    assert panel.detail_open is True
    assert "Cursor -  x" not in panel.detail_header()
    assert panel.detail_header() == "seen - Cursor x 1 signal(s)"
    detail = "\n".join(panel.detail_lines(now=now))
    assert "runtime: pid=123" in detail
    assert "last active: 4m ago" in detail

    panel.toggle_detail()
    assert panel.detail_open is False


def test_ai_discovery_detail_toggle_noop_on_empty_table() -> None:
    panel = AIDiscoveryPanelModel()
    panel.set_snapshot(AIUsageSnapshot(enabled=True))
    panel.toggle_detail()
    assert panel.detail_open is False


def test_ai_discovery_groups_and_details_local_models() -> None:
    now = datetime.now(timezone.utc)
    base = dict(
        state="seen",
        category="local_model",
        product="Lemonade Server",
        vendor="Lemonade",
        first_seen=now,
        last_seen=now,
    )
    panel = AIDiscoveryPanelModel()
    panel.set_snapshot(
        AIUsageSnapshot(
            enabled=True,
            signals=(
                AIUsageSignal(
                    signal_id="installed",
                    detector="model_api",
                    model=AIUsageModel(
                        id="Qwen3-0.6B-GGUF",
                        status="installed",
                        format="gguf",
                        provider="lemonade",
                        size_bytes=400_000_000,
                        provenance=AIUsageModelProvenance(
                            publisher="Alibaba Cloud",
                            country_code="CN",
                            root_model="Qwen/Qwen3-0.6B",
                            base_models=("Qwen/Qwen3-0.6B",),
                            quantized=True,
                            quantization="Q4_K_M",
                            distilled=False,
                            derivation="quantized",
                            source="catalog_exact",
                            confidence="high",
                        ),
                    ),
                    **base,
                ),
                AIUsageSignal(
                    signal_id="loaded",
                    detector="model_runtime",
                    model=AIUsageModel(
                        id="qWEN3-0.6b-gguf",
                        status="loaded",
                        format="gguf",
                        provider="lemonade",
                        recipe="llamacpp",
                        device="gpu",
                        pinned=True,
                    ),
                    runtime=AIUsageRuntime(pid=4321),
                    **{
                        **base,
                        "state": "new",
                        "product": "Local Model Artifact",
                        "vendor": "Local",
                    },
                ),
            ),
        )
    )

    assert panel.rows == ()
    assert len(panel.model_rows) == 1
    row = panel.model_rows[0]
    assert row.state == "new"
    assert row.model == "Qwen3-0.6B-GGUF"
    assert set(row.model_statuses) == {"installed", "loaded"}
    assert row.model_formats == ("gguf",)
    assert "Model" not in panel.data_table_columns()
    assert panel.model_table_columns() == (
        "State",
        "Model",
        "Owner",
        "Modality",
        "Relevance",
        "Confidence",
        "Status",
        "Format",
    )
    model_cells = panel.model_table_rows()[0]
    assert model_cells[1] == "Qwen3-0.6B-GGUF"
    assert model_cells[2:6] == ("—", "Unknown", "Unknown", "API")

    panel.set_filter("qwen3")
    assert panel.filtered == ()
    assert len(panel.filtered_models) == 1
    panel.toggle_detail()
    detail = "\n".join(panel.detail_lines(now=now))
    assert "publisher=Alibaba Cloud" in detail
    assert "country=CN 🇨🇳" in detail
    assert "root=Qwen/Qwen3-0.6B" in detail
    assert "quantized=true" in detail
    assert "status=installed" in detail
    assert "status=loaded" in detail
    assert "recipe=llamacpp" in detail
    assert "runtime: pid=4321" in detail


def test_ai_discovery_recommends_actionable_models_and_can_show_all_artifacts() -> None:
    def model_signal(
        model_id: str,
        *,
        owner: str = "",
        modality: str = "",
        relevance: str = "",
        confidence: float | None = None,
        detector: str = "model_file",
        signal_confidence: float = 0.9,
        model_format: str = "",
    ) -> AIUsageSignal:
        return AIUsageSignal(
            signal_id=model_id,
            state="seen",
            category="local_model",
            product="Local Model Artifact",
            detector=detector,
            confidence=signal_confidence,
            model=AIUsageModel(
                id=model_id,
                owner_application=owner,
                modality=modality,
                relevance=relevance,
                discovery_confidence=confidence,
                format=model_format,
            ),
        )

    panel = AIDiscoveryPanelModel()
    panel.set_snapshot(
        AIUsageSnapshot(
            enabled=True,
            signals=(
                model_signal(
                    "Qwen3.5-4B-Q4_K_M",
                    owner="Meetily",
                    modality="generative",
                    relevance="primary",
                    confidence=0.95,
                    model_format="gguf",
                ),
                model_signal(
                    "SpeakerEmbedder",
                    owner="Superwhisper",
                    modality="speech",
                    relevance="supporting",
                    confidence=0.95,
                    model_format="coreml",
                ),
                model_signal(
                    "vad-v2",
                    owner="Superwhisper",
                    modality="audio",
                    relevance="supporting",
                    confidence=0.8,
                    model_format="onnx",
                ),
                model_signal(
                    "ownerless-speech",
                    modality="speech",
                    relevance="supporting",
                    confidence=0.95,
                ),
                model_signal(
                    "39D6225B0612C5CC",
                    owner="Chrome",
                    modality="unknown",
                    relevance="embedded",
                    confidence=0.8,
                    model_format="tflite",
                ),
                model_signal(
                    "2026.2.12.1554",
                    owner="Chrome",
                    modality="unknown",
                    relevance="embedded",
                    confidence=0.8,
                    model_format="bin",
                ),
                model_signal(
                    "unknown-helper",
                    owner="Cisco Spark",
                    modality="unknown",
                    relevance="unknown",
                    confidence=0.9,
                ),
                model_signal(
                    "low-primary",
                    owner="Meetily",
                    modality="generative",
                    relevance="primary",
                    confidence=0.79,
                ),
                model_signal(
                    "api-explicit-zero",
                    owner="Meetily",
                    modality="generative",
                    relevance="primary",
                    confidence=0,
                    detector="model_api",
                    signal_confidence=0.2,
                ),
                model_signal(
                    "qwen3.5:9b-mlx",
                    detector="model_api",
                    signal_confidence=0.2,
                    model_format="safetensors",
                ),
                model_signal(
                    "mixed-api-low",
                    detector="model_api",
                    signal_confidence=0.2,
                ),
                model_signal(
                    "mixed-api-low",
                    owner="Chrome",
                    modality="unknown",
                    relevance="embedded",
                    confidence=0.79,
                    detector="model_file",
                    signal_confidence=0.79,
                ),
            ),
        )
    )

    recommended_ids = {row.model for row in panel.filtered_models}
    assert recommended_ids == {
        "Qwen3.5-4B-Q4_K_M",
        "SpeakerEmbedder",
        "vad-v2",
        "qwen3.5:9b-mlx",
        "mixed-api-low",
    }
    assert panel.hidden_model_count == 6
    assert panel.model_scope_label() == "LOCAL MODELS — RECOMMENDED (5 of 11, 6 hidden)"

    mixed_row = next(row for row in panel.filtered_models if row.model == "mixed-api-low")
    assert mixed_row.reported_model_discovery_confidence == 0.79
    assert mixed_row.has_local_model_api_signal_without_discovery_confidence is True
    assert mixed_row.effective_model_relevance == "embedded"

    speech_row = next(row for row in panel.filtered_models if row.model == "SpeakerEmbedder")
    assert speech_row.model_owner_label == "Superwhisper"
    assert speech_row.model_modality_label == "Speech"
    assert speech_row.model_relevance_label == "Supporting"
    assert speech_row.model_confidence_label == "95%"

    panel.set_model_cursor(panel.filtered_models.index(speech_row))
    action = panel.handle_key("a")
    assert action.handled is True
    assert panel.show_all_models is True
    assert len(panel.filtered_models) == 11
    assert panel.selected_model() is not None
    assert panel.selected_model().model == "SpeakerEmbedder"
    assert panel.model_scope_label() == "LOCAL MODELS — ALL (11 of 11)"

    panel.set_filter("chrome")
    assert {row.model for row in panel.filtered_models} == {
        "39D6225B0612C5CC",
        "2026.2.12.1554",
        "mixed-api-low",
    }
    panel.set_model_cursor(0)
    panel.toggle_detail()
    assert "relevance=embedded" in "\n".join(panel.detail_lines())

    panel.clear_filter()
    action = panel.handle_key("a")
    assert action.handled is True
    assert panel.show_all_models is False
    assert {row.model for row in panel.filtered_models} == recommended_ids


def test_ai_discovery_empty_recommended_scope_uses_neutral_hidden_copy() -> None:
    panel = AIDiscoveryPanelModel()
    panel.set_snapshot(
        AIUsageSnapshot(
            enabled=True,
            signals=(
                AIUsageSignal(
                    signal_id="embedded",
                    state="seen",
                    category="local_model",
                    detector="model_file",
                    confidence=0.9,
                    model=AIUsageModel(
                        id="39D6225B0612C5CC",
                        owner_application="Chrome",
                        modality="unknown",
                        relevance="embedded",
                        discovery_confidence=0.8,
                    ),
                ),
                AIUsageSignal(
                    signal_id="unknown",
                    state="seen",
                    category="local_model",
                    detector="model_file",
                    confidence=0.9,
                    model=AIUsageModel(
                        id="2026.2.12.1554",
                        owner_application="Chrome",
                        modality="unknown",
                        relevance="unknown",
                        discovery_confidence=0.8,
                    ),
                ),
            ),
        )
    )

    assert panel.filtered_models == ()
    assert panel.empty_state() == (
        "No recommended local models. "
        "2 non-recommended local models are hidden; "
        "press a or click Show all models to review them."
    )


def test_ai_discovery_legacy_modality_only_snapshot_remains_compatible() -> None:
    panel = AIDiscoveryPanelModel()
    panel.set_snapshot(
        AIUsageSnapshot(
            enabled=True,
            signals=(
                AIUsageSignal(
                    signal_id="legacy-model",
                    state="seen",
                    category="local_model",
                    detector="model_file",
                    confidence=0.9,
                    model=AIUsageModel(id="legacy-llm", modality="text"),
                ),
            ),
        )
    )

    assert [row.model for row in panel.filtered_models] == ["legacy-llm"]
    assert panel.hidden_model_count == 0


def test_ai_discovery_detail_renders_ambiguous_multi_base_root_label() -> None:
    panel = AIDiscoveryPanelModel()
    panel.set_snapshot(
        AIUsageSnapshot(
            enabled=True,
            signals=(
                AIUsageSignal(
                    signal_id="merged-model",
                    state="seen",
                    category="local_model",
                    product="Local Model Artifact",
                    detector="model_file",
                    model=AIUsageModel(
                        id="private/merged-model",
                        provenance=AIUsageModelProvenance(
                            base_models=("acme/base-a", "acme/base-b"),
                            source="gguf_metadata",
                            confidence="medium",
                        ),
                    ),
                ),
            ),
        )
    )

    panel.set_model_cursor(0)
    panel.toggle_detail()
    detail = "\n".join(panel.detail_lines())

    assert "root=ambiguous (2)" in detail
    assert "base_models=acme/base-a,acme/base-b" in detail


def test_non_local_signal_with_model_metadata_stays_in_product_table() -> None:
    panel = AIDiscoveryPanelModel()
    panel.set_snapshot(
        AIUsageSnapshot(
            enabled=True,
            signals=(
                AIUsageSignal(
                    signal_id="desktop-model",
                    state="seen",
                    category="desktop_app",
                    product="Acme Model Studio",
                    vendor="Acme",
                    detector="application",
                    model=AIUsageModel(
                        id="acme/embedded-model",
                        status="available",
                        format="safetensors",
                    ),
                ),
            ),
        )
    )

    assert panel.model_rows == ()
    assert len(panel.rows) == 1
    row = panel.rows[0]
    assert row.product == "Acme Model Studio"
    assert row.categories == ("desktop_app",)
    assert row.model_statuses == ("available",)
    assert row.model_formats == ("safetensors",)


def test_ai_usage_model_metadata_is_safely_coerced() -> None:
    signal = AIUsageSignal.from_mapping(
        {
            "category": "local_model",
            "model": {
                "id": "private-model",
                "status": "installed",
                "size_bytes": "not-a-number",
                "pinned": "false",
                "owner_application": "Meetily",
                "relevance": "primary",
                "discovery_confidence": "82",
                "provenance": {
                    "publisher": "Acme AI",
                    "country_code": "us",
                    "root_model": "acme/root",
                    "base_models": ["acme/base-a", "acme/base-b"],
                    "quantized": "true",
                    "quantization": "Q5_K_M",
                    "derivation": "distilled+quantized",
                    "source": "model_metadata",
                    "confidence": "medium",
                },
            },
        }
    )
    assert signal.model is not None
    assert signal.model.size_bytes == 0
    assert signal.model.pinned is False
    assert signal.model.owner_application == "Meetily"
    assert signal.model.relevance == "primary"
    assert signal.model.discovery_confidence == 0.82
    assert signal.model.provenance is not None
    assert signal.model.provenance.country_code == "US"
    assert signal.model.provenance.base_models == ("acme/base-a", "acme/base-b")
    assert signal.model.provenance.root_label == "acme/root"
    assert signal.model.provenance.quantized is True
    assert signal.model.provenance.distilled is None

    ambiguous = AIUsageModelProvenance.from_mapping(
        {"base_models": ["acme/base-a", "acme/base-b"]}
    )
    assert ambiguous is not None
    assert ambiguous.root_label == "ambiguous (2)"

    numeric = AIUsageSignal.from_mapping(
        {"category": "local_model", "model": {"id": "other", "size_bytes": -42, "pinned": "true"}}
    )
    assert numeric.model is not None
    assert numeric.model.size_bytes == 0
    assert numeric.model.pinned is True


def test_ai_model_country_flag_and_optional_boolean_validation() -> None:
    assert country_flag("us") == "🇺🇸"
    assert format_model_country("us") == "US 🇺🇸"
    assert format_model_country("USA") == ""
    assert format_model_country("éx") == ""

    model = AIUsageModel.from_mapping(
        {
            "id": "model",
            "status": "installed",
            "provenance": {
                "country_code": "USA",
                "quantized": "not-known",
                "distilled": False,
            },
        }
    )
    assert model is not None
    assert model.provenance is not None
    assert model.provenance.country_code == ""
    assert model.provenance.quantized is None
    assert model.provenance.distilled is False


def test_ai_discovery_keyboard_filter_searches_products_and_model_provenance() -> None:
    panel = AIDiscoveryPanelModel()
    panel.set_snapshot(
        AIUsageSnapshot(
            enabled=True,
            signals=(
                AIUsageSignal(state="seen", product="Codex", vendor="OpenAI"),
                AIUsageSignal(
                    state="seen",
                    category="local_model",
                    product="Local Model Artifact",
                    model=AIUsageModel(
                        id="Qwen3",
                        status="installed",
                        provenance=AIUsageModelProvenance(
                            publisher="Alibaba Cloud",
                            country_code="CN",
                            root_model="Qwen/Qwen3",
                        ),
                    ),
                ),
            ),
        )
    )

    assert panel.handle_key("/").handled is True
    for character in "alibaba":
        assert panel.handle_key(character).handled is True
    assert panel.handle_key("enter").handled is True
    assert panel.filtered == ()
    assert [row.model for row in panel.filtered_models] == ["Qwen3"]
    assert panel.empty_state() == ""

    assert panel.handle_key("esc").handled is True
    assert len(panel.filtered) == 1
    assert len(panel.filtered_models) == 1


def test_ai_discovery_header_churn_rules() -> None:
    panel = AIDiscoveryPanelModel()
    panel.set_snapshot(
        AIUsageSnapshot(
            enabled=True,
            summary=AIUsageSummary(
                active_signals=755,
                new_signals=0,
                changed_signals=0,
                gone_signals=0,
                files_scanned=2103,
            ),
        )
    )
    assert panel.header_parts() == (
        "active=755",
        "files=2103",
        "model-lookup=offline",
    )

    panel.set_snapshot(
        AIUsageSnapshot.from_mapping(
            {
                "enabled": True,
                "summary": {
                    "active_signals": 4,
                    "files_scanned": 99,
                    "result": "partial",
                    "errors": 2,
                    "detector_errors": {
                        "model_file:application_support": "permission denied",
                        None: "missing detector",
                        "missing-message": None,
                    },
                },
            }
        )
    )
    assert panel.header_parts() == (
        "active=4",
        "files=99",
        "scan=partial",
        "errors=2",
        "model-lookup=offline",
    )
    assert panel.snapshot is not None
    assert dict(panel.snapshot.summary.detector_errors) == {
        "model_file:application_support": "permission denied"
    }

    panel.set_snapshot(
        AIUsageSnapshot(
            enabled=True,
            summary=AIUsageSummary(active_signals=755, new_signals=5, changed_signals=2, files_scanned=2103),
        )
    )
    assert panel.header_parts() == (
        "active=755",
        "new=5",
        "changed=2",
        "files=2103",
        "model-lookup=offline",
    )


def test_ai_discovery_normalizes_across_detectors_and_searches_aggregates() -> None:
    now = datetime.now(timezone.utc)

    def make_signal(signal_id: str, category: str, detector: str) -> AIUsageSignal:
        return AIUsageSignal(
            signal_id=signal_id,
            state="seen",
            category=category,
            product="Claude Code",
            vendor="Anthropic",
            detector=detector,
            first_seen=now,
            last_seen=now,
        )

    panel = AIDiscoveryPanelModel()
    panel.set_snapshot(
        AIUsageSnapshot(
            enabled=True,
            signals=(
                make_signal("s1", "ai_cli", "binary"),
                make_signal("s2", "active_process", "process"),
                make_signal("s3", "mcp_server", "mcp"),
                make_signal("s4", "supported_app", "config"),
                make_signal("s5", "shell_history", "shell_history"),
                make_signal("s6", "provider_history", "shell_history"),
                make_signal("s7", "desktop_app", "application"),
                AIUsageSignal(
                    signal_id="s8",
                    state="seen",
                    category="ai_cli",
                    product="Cursor",
                    vendor="Anysphere",
                    detector="binary",
                    first_seen=now,
                    last_seen=now,
                ),
            ),
            fetched_at=now,
        )
    )

    assert len(panel.filtered) == 2
    claude = next(row for row in panel.filtered if row.product == "Claude Code")
    assert claude.count == 7
    assert "desktop_app" in claude.categories
    assert "application" in claude.detectors
    claude_cells = next(row for row in panel.data_table_rows() if row[2] == "Claude Code")
    assert claude_cells[1].endswith("(+5)")

    panel.set_filter("application")
    assert [row.product for row in panel.filtered] == ["Claude Code"]


def test_ai_discovery_cursor_clamps_on_filter() -> None:
    now = datetime.now(timezone.utc)
    panel = AIDiscoveryPanelModel()
    panel.set_snapshot(
        AIUsageSnapshot(
            enabled=True,
            signals=tuple(
                AIUsageSignal(signal_id=f"s{index}", state="new", product=name, detector="binary", last_seen=now)
                for index, name in enumerate(("alpha", "beta", "gamma", "delta", "epsilon"))
            ),
        )
    )
    panel.set_cursor(4)
    panel.set_filter("alpha")

    assert panel.cursor_at() == 0
    panel.toggle_detail()
    assert panel.detail_open is True


def test_ai_discovery_model_cursor_and_scroll_use_model_viewport() -> None:
    panel = AIDiscoveryPanelModel()
    panel.set_snapshot(
        AIUsageSnapshot(
            enabled=True,
            signals=(
                AIUsageSignal(
                    signal_id="agent",
                    state="seen",
                    category="ai_cli",
                    product="Codex",
                    detector="binary",
                ),
                *(
                    AIUsageSignal(
                        signal_id=f"model-{index}",
                        state="seen",
                        category="local_model",
                        product="Local Model Artifact",
                        detector="model_file",
                        model=AIUsageModel(id=f"Model-{index:02d}"),
                    )
                    for index in range(8)
                ),
            ),
        )
    )
    panel.set_size(width=120, height=10)

    panel.set_model_cursor(7)
    assert panel.active_table == "models"
    assert panel.cursor_at() == 7
    assert panel.selected() is not None
    assert panel.selected().model == "Model-07"
    assert panel.scroll_offset() == 3

    panel.cursor_up()
    assert panel.cursor_at() == 6
    assert panel.selected() is not None
    assert panel.selected().model == "Model-06"
    assert panel.scroll_offset() == 2

    panel.set_cursor(0)
    assert panel.active_table == "agents"
    assert panel.cursor_at() == 0
    assert panel.scroll_offset() == 0


def test_ai_discovery_table_toggle_is_keyboard_reachable_and_closes_stale_detail() -> None:
    panel = AIDiscoveryPanelModel()
    panel.set_snapshot(
        AIUsageSnapshot(
            enabled=True,
            signals=(
                AIUsageSignal(signal_id="agent", state="seen", product="Codex"),
                AIUsageSignal(
                    signal_id="model",
                    state="seen",
                    category="local_model",
                    model=AIUsageModel(id="Qwen/Qwen3"),
                ),
            ),
        )
    )
    panel.toggle_detail()
    assert panel.detail_open is True

    action = panel.handle_key("t")
    assert action.handled is True
    assert action.table_changed is True
    assert panel.active_table == "models"
    assert panel.detail_open is False
    assert "Local models" in action.hint

    action = panel.handle_key("t")
    assert action.table_changed is True
    assert panel.active_table == "agents"


def test_format_confidence_state_weight_and_humanize_age() -> None:
    assert format_confidence(0.91, "high") == "high (91%)"
    assert format_confidence(0.5, "") == "50%"
    assert format_confidence(0, "") == ""
    assert state_weight("new") < state_weight("changed") < state_weight("active")
    assert state_weight("active") < state_weight("seen") < state_weight("gone")
    assert humanize_age(timedelta(milliseconds=500)) == "0s"
    assert humanize_age(timedelta(hours=3, minutes=12)) == "3h12m"
    assert humanize_age(timedelta(hours=36)) == "1d12h"
