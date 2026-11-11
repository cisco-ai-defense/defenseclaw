// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func skillReportSignal(signature, connector, parentHash string, skills ...inventory.AIEvidence) inventory.AISignal {
	return inventory.AISignal{
		SignatureID: signature, SupportedConnector: connector, Category: inventory.SignalSkill,
		Evidence: append([]inventory.AIEvidence{{Type: "skill", Basename: "skills", PathHash: parentHash}}, skills...),
	}
}

// skillRecordBodies emits components as the managed skill inventory does and
// returns each ai_component.observed body by "name/connector".
func skillRecordBodies(t *testing.T, components []endpointInventoryComponent) map[string]map[string]any {
	t.Helper()
	capture := &endpointInventoryCapture{}
	if err := emitEndpointInventorySnapshot(
		t.Context(), capture, "endpoint_skill_inventory", components, false,
		config.ObservabilityV8ManagedSkillInventoryAction, endpointInventoryCycle{},
	); err != nil {
		t.Fatal(err)
	}
	bodies := map[string]map[string]any{}
	for _, record := range capture.snapshot() {
		if record.EventName() != "ai_component.observed" {
			continue
		}
		body, _ := record.Body()
		object, err := body.Object()
		if err != nil {
			t.Fatal(err)
		}
		bodies[object[observability.TelemetryAttributeDefenseClawInventoryItemName].(string)+"/"+
			object[observability.TelemetryAttributeDefenseClawAgentDiscoveryConnector].(string)] = object
	}
	return bodies
}

func TestSkillInventoryRecordsCarryTheContentHash(t *testing.T) {
	hash := "sha256:" + strings.Repeat("c", 64)
	stale := skillReportSignal("codex", "codex", "sha256:"+strings.Repeat("1", 64),
		inventory.AIEvidence{Type: "skill_entry", Basename: "pdf", Skill: &inventory.AISkillFacts{ContentHash: "sha256:" + strings.Repeat("d", 64), ContentStatus: inventory.SkillContentOK}})
	stale.State = inventory.AIStateGone // the folder before the edit
	report := inventory.AIDiscoveryReport{Signals: []inventory.AISignal{
		stale,
		skillReportSignal("codex", "codex", "sha256:"+strings.Repeat("1", 64),
			inventory.AIEvidence{Type: "skill_entry", Basename: "pdf", Skill: &inventory.AISkillFacts{ContentHash: hash, ContentStatus: inventory.SkillContentOK}},
			inventory.AIEvidence{Type: "skill_entry", Basename: "big", Skill: &inventory.AISkillFacts{ContentStatus: inventory.SkillContentTooLarge}},
			inventory.AIEvidence{Type: "skill_entry", Basename: "legacy"},
		),
	}}
	components := discoveredEntriesFromReport(report, inventory.SignalSkill, "skill")
	if len(components) != 3 {
		t.Fatalf("a gone signal must add no rows: %d rows", len(components))
	}
	bodies := skillRecordBodies(t, components)
	hashKey := observability.TelemetryAttributeDefenseClawInventorySkillContentHash
	statusKey := observability.TelemetryAttributeDefenseClawInventorySkillContentStatus
	for key, want := range map[string][2]any{
		"pdf/codex":    {hash, "ok"},
		"big/codex":    {nil, "too_large"},
		"legacy/codex": {nil, nil},
	} {
		body, ok := bodies[key]
		if !ok {
			t.Fatalf("no record for %s in %v", key, bodies)
		}
		if body[hashKey] != want[0] || body[statusKey] != want[1] {
			t.Errorf("%s: hash %v status %v, want %v", key, body[hashKey], body[statusKey], want)
		}
	}
}

func TestSkillInventoryRecordsListEveryAgentOfASharedFolder(t *testing.T) {
	parent := "sha256:" + strings.Repeat("1", 64)
	shared := inventory.AIEvidence{Type: "skill_entry", Basename: "pdf", Skill: &inventory.AISkillFacts{
		ContentStatus: inventory.SkillContentTooLarge, Scope: inventory.SkillScopeUser, Location: "~/.agents/skills/pdf",
	}}
	bundled := inventory.AIEvidence{Type: "skill_entry", Basename: "imagegen", Skill: &inventory.AISkillFacts{
		ContentStatus: inventory.SkillContentTooLarge, Scope: inventory.SkillScopeBundled,
	}}
	bodies := skillRecordBodies(t, discoveredEntriesFromReport(inventory.AIDiscoveryReport{Signals: []inventory.AISignal{
		skillReportSignal("codex", "codex", parent, shared),
		skillReportSignal("cursor", "cursor", parent, shared),
		skillReportSignal("codex", "codex", "sha256:"+strings.Repeat("2", 64), bundled),
	}}, inventory.SignalSkill, "skill"))
	agents := observability.TelemetryAttributeDefenseClawInventorySkillAgents
	for key, want := range map[string][3]any{
		"pdf/codex":      {"user", "~/.agents/skills/pdf", []any{"codex", "cursor"}},
		"pdf/cursor":     {"user", "~/.agents/skills/pdf", []any{"codex", "cursor"}},
		"imagegen/codex": {"bundled", nil, []any{"codex"}},
	} {
		body := bodies[key]
		got := [3]any{
			body[observability.TelemetryAttributeDefenseClawInventorySkillScope],
			body[observability.TelemetryAttributeDefenseClawInventorySkillLocation], body[agents],
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %v, want %v", key, got, want)
		}
	}
	if bodies["pdf/codex"][observability.TelemetryAttributeDefenseClawAIComponentID] ==
		bodies["pdf/cursor"][observability.TelemetryAttributeDefenseClawAIComponentID] {
		t.Fatal("each agent keeps its own component id")
	}
}
