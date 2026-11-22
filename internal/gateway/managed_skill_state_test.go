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
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func stateSkill(id, hash string) endpointInventoryComponent {
	return endpointInventoryComponent{
		id: id, componentType: "skill", active: true, itemName: id, agentConnector: "codex",
		userID: "501", userName: "alice", skillContentHash: hash, skillContentStatus: "ok",
	}
}

// skillCycle runs one publish cycle of the skill collection and returns the
// state of each row; published says whether the collection reached AI Defense.
func skillCycle(t *testing.T, state *managedInventoryPublishState, now time.Time, complete, published bool,
	skills ...endpointInventoryComponent,
) map[string]endpointInventoryComponent {
	t.Helper()
	cycle := state.beginCycle("scan-"+now.Format(time.RFC3339), now, complete)
	rows := map[string]endpointInventoryComponent{}
	for _, row := range cycle.trackSkills(skills, complete) {
		rows[row.id] = row
	}
	if published {
		cycle.recordPublished(endpointSkillInventorySource, now.String(), len(rows))
	}
	cycle.commit()
	return rows
}

func TestSkillStateIsKeptOnTheEndpoint(t *testing.T) {
	state := managedPublishTestState(t)
	t1 := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	t2, t3, t4 := t1.Add(time.Hour), t1.Add(2*time.Hour), t1.Add(3*time.Hour)
	stamp := func(at time.Time) string { return at.Format(time.RFC3339) }
	want := func(rows map[string]endpointInventoryComponent, id, skillState string, first, last time.Time) {
		t.Helper()
		row, ok := rows[id]
		if !ok || row.skillState != skillState || row.skillFirstSeen != stamp(first) || row.skillLastSeen != stamp(last) {
			t.Fatalf("%s = %+v, want %s first %s last %s", id, row, skillState, stamp(first), stamp(last))
		}
	}

	rows := skillCycle(t, state, t1, true, true, stateSkill("a", "h1"), stateSkill("b", "h2"))
	want(rows, "a", skillStateNew, t1, t1)
	want(rows, "b", skillStateNew, t1, t1)

	// A publish that did not reach AI Defense keeps the change for the next cycle.
	rows = skillCycle(t, state, t2, true, false, stateSkill("a", "h1b"), stateSkill("b", "h2"))
	want(rows, "a", skillStateChanged, t1, t2)
	want(rows, "b", skillStateUnchanged, t1, t2)
	rows = skillCycle(t, state, t3, true, true, stateSkill("a", "h1b"), stateSkill("b", "h2"))
	want(rows, "a", skillStateChanged, t1, t3)

	// A complete scan sends it once as removed, inactive, with its last sighting
	// (TestSkillRemovalSurvivesAPartialScan covers a partial scan).
	rows = skillCycle(t, state, t4, true, true, stateSkill("a", "h1b"))
	want(rows, "a", skillStateUnchanged, t1, t4)
	want(rows, "b", skillStateRemoved, t1, t3)
	if removed := rows["b"]; removed.active || removed.skillContentHash != "h2" || removed.userName != "alice" {
		t.Fatalf("removed row = %+v", removed)
	}
	rows = skillCycle(t, state, t4.Add(time.Hour), true, true, stateSkill("a", "h1b"))
	if _, ok := rows["b"]; ok {
		t.Fatal("removed skill was sent twice")
	}

	// The state survives a restart.
	reloaded := loadManagedInventoryPublishFile(state.path)
	if got := reloaded.Skills["a"]; got.Hash != "h1b" || !got.FirstSeen.Equal(t1) || len(reloaded.Skills) != 1 {
		t.Fatalf("persisted skills = %+v", reloaded.Skills)
	}
	var nilCycle *managedInventoryPublishCycle
	if got := nilCycle.trackSkills([]endpointInventoryComponent{stateSkill("a", "h")}, true); got[0].skillState != "" {
		t.Fatalf("no managed state must leave rows unstamped: %+v", got)
	}
}

func TestSkillRemovalSurvivesAPartialScan(t *testing.T) {
	withManagedEnterprise(t, true)
	gate := managedPublishTestState(t)
	cfg := &config.Config{Claw: config.ClawConfig{Mode: config.ClawMode("codex")}}
	registry := connector.NewDefaultRegistry()
	cycle := func(report inventory.AIDiscoveryReport) map[string]string {
		t.Helper()
		capture := &endpointInventoryCapture{}
		if err := emitEndpointInventory(t.Context(), cfg, registry, capture, false, &report, gate); err != nil {
			t.Fatal(err)
		}
		states := map[string]string{}
		for _, record := range capture.snapshot() {
			body := canonicalBody(t, record)
			if body[observability.TelemetryAttributeDefenseClawAIDiscoverySource] == endpointSkillInventorySource {
				name, _ := body[observability.TelemetryAttributeDefenseClawInventoryItemName].(string)
				states[name], _ = body[observability.TelemetryAttributeDefenseClawInventorySkillState].(string)
			}
		}
		return states
	}
	cycle(managedGateReport("scan-1", "alpha", "beta", "gamma"))

	// Another detector's error does not hold a removal back.
	other := managedGateReport("scan-2", "alpha", "beta")
	other.Summary.DetectorErrors = map[string]string{"model_file": "permission denied"}
	if got := cycle(other); got["gamma"] != skillStateRemoved {
		t.Fatalf("removal with an unrelated detector error = %v", got)
	}

	// A failed skill scan proves nothing about beta ...
	partial := managedGateReport("scan-3", "alpha")
	partial.Summary.DetectorErrors = map[string]string{"skill": "permission denied"}
	if got := cycle(partial); got["beta"] == skillStateRemoved {
		t.Fatalf("partial scan reported a removal: %v", got)
	}
	// ... so the next complete scan sends it, then the collection settles.
	if got := cycle(managedGateReport("scan-4", "alpha")); got["beta"] != skillStateRemoved {
		t.Fatalf("held-back removal was not sent: %v", got)
	}
	if got := cycle(managedGateReport("scan-5", "alpha")); len(got) != 0 {
		t.Fatalf("collection did not settle: %v", got)
	}
}
