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
	"context"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

const endpointSkillInventorySource = "endpoint_skill_inventory"

// Skill states (defenseclaw.inventory.skill.state).
const (
	skillStateNew       = "new"
	skillStateChanged   = "changed"
	skillStateUnchanged = "unchanged"
	skillStateRemoved   = "removed"
)

// managedSkillState is what the endpoint remembers about one published skill,
// so it can say new, changed or removed without asking AI Defense.
type managedSkillState struct {
	Hash      string    `json:"hash,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// The row to send once as removed. No email is kept.
	Status     string `json:"status,omitempty"`
	Signal     string `json:"signal,omitempty"`
	Product    string `json:"product,omitempty"`
	Name       string `json:"name"`
	Connector  string `json:"connector,omitempty"`
	UserID     string `json:"user_id,omitempty"`
	UserIDKind string `json:"user_id_kind,omitempty"`
	UserName   string `json:"user_name,omitempty"`
}

// trackSkills stamps each skill with its state against the last published
// one and appends a removed row for each skill a complete scan no longer
// finds. The new state is kept only if this cycle publishes the collection
// (commit), so a failed or suppressed publish loses no change. A nil cycle
// (no managed state) leaves the rows unstamped.
func (cycle *managedInventoryPublishCycle) trackSkills(
	components []endpointInventoryComponent,
	complete bool,
) []endpointInventoryComponent {
	if cycle == nil || cycle.state == nil {
		return components
	}
	cycle.state.mu.Lock()
	prior := cycle.state.file.Skills
	cycle.state.mu.Unlock()
	now := cycle.now.UTC()
	next := make(map[string]managedSkillState, len(components))
	for i := range components {
		c := &components[i]
		entry := managedSkillState{
			Hash: c.skillContentHash, FirstSeen: now, LastSeen: now, Status: c.skillContentStatus,
			Signal: c.signal, Product: c.product, Name: c.itemName, Connector: c.agentConnector,
			UserID: c.userID, UserIDKind: c.userIDKind, UserName: c.userName,
		}
		c.skillState = skillStateNew
		if old, ok := prior[c.id]; ok {
			entry.FirstSeen = old.FirstSeen
			c.skillState = skillStateUnchanged
			if old.Hash != c.skillContentHash {
				c.skillState = skillStateChanged
			}
		}
		c.skillFirstSeen, c.skillLastSeen = entry.FirstSeen.Format(time.RFC3339), now.Format(time.RFC3339)
		next[c.id] = entry
	}
	for id, old := range prior {
		if _, ok := next[id]; ok {
			continue
		}
		if !complete {
			// A partial scan proves nothing about a missing skill.
			next[id] = old
			continue
		}
		installed := true
		if cycle.skillRemovalCandidates == nil {
			cycle.skillRemovalCandidates = map[string]managedSkillState{}
		}
		cycle.skillRemovalCandidates[id] = old
		components = append(components, endpointInventoryComponent{
			id: id, componentType: "skill", signal: old.Signal, product: old.Product, itemName: old.Name,
			agentConnector: old.Connector, agentInstalled: &installed,
			userID: old.UserID, userIDKind: old.UserIDKind, userName: old.UserName,
			skillContentHash: old.Hash, skillContentStatus: old.Status, skillState: skillStateRemoved,
			skillFirstSeen: old.FirstSeen.Format(time.RFC3339), skillLastSeen: old.LastSeen.Format(time.RFC3339),
		})
	}
	cycle.skills = next
	return components
}

// A turnover can have a supported current collection but too many rows once
// removals are included. Deliver a bounded removal batch first. Until every
// removal is accepted, leave the current rows unpublished and retain all other
// prior state so a failed batch cannot turn new rows into unchanged ones.
// action is the collection's action in this product (managed on a Secure
// Client endpoint, the operator action elsewhere); limits are the same.
func prepareManagedSkillSnapshot(ctx context.Context, emitter sidecarRuntimeEmitter, components []endpointInventoryComponent, complete bool, publish endpointInventoryCycle, action observability.ProducerKey) ([]endpointInventoryComponent, error) {
	if !complete || managedInventorySnapshotEligible(endpointSkillInventorySource, action, components) {
		return components, nil
	}
	current := make([]endpointInventoryComponent, 0, len(components))
	var removed []endpointInventoryComponent
	for _, row := range components {
		if row.skillState == skillStateRemoved {
			removed = append(removed, row)
		} else {
			current = append(current, row)
		}
	}
	if len(removed) == 0 || !managedInventorySnapshotEligible(endpointSkillInventorySource, action, current) {
		return components, nil
	}
	sort.Slice(removed, func(i, j int) bool { return removed[i].id < removed[j].id })
	batch := removed[:min(len(removed), managedInventoryLimit(action))]
	accepted, err := emitEndpointInventoryComponents(ctx, emitter, endpointSkillInventorySource, batch, action, publish)
	if publish.cycle != nil {
		if publish.cycle.skillRemovals == nil {
			publish.cycle.skillRemovals = map[string]managedSkillState{}
		}
		for id := range accepted {
			if prior, ok := publish.cycle.skillRemovalCandidates[id]; ok {
				publish.cycle.skillRemovals[id] = prior
			}
		}
	}
	if err != nil || len(accepted) != len(removed) {
		publish.cycle.markDegraded()
		return components, err
	}
	return current, nil
}

// skillScanComplete reports whether a skill missing from report can be
// trusted as removed: the skill detector and every per-user scan finished and
// no skill folder was cut short. Explicit model-file errors do not hold skill
// removals back; global, aggregate and unclassified errors remain incomplete.
func skillScanComplete(report *inventory.AIDiscoveryReport) bool {
	if report == nil || strings.TrimSpace(report.Summary.ScanID) == "" ||
		strings.TrimSpace(report.Summary.Result) == "" {
		return false
	}
	// A partial result without a detector-specific cause does not establish
	// that skills were fully enumerated. Explicit errors in unrelated detectors
	// may still leave this collection complete, unlike the whole daily bundle.
	if !aiDiscoveryReportComplete(report) && len(report.Summary.DetectorErrors) == 0 {
		return false
	}
	for name := range report.Summary.DetectorErrors {
		// runScan measures model_file separately after the skill detectors and
		// may also report an error scoped to one model root. Other keys may
		// describe missing homes/sandboxes or a global scan/state failure.
		if name == "model_file" {
			continue
		}
		if root, ok := strings.CutPrefix(name, "model_file:"); ok && strings.TrimSpace(root) != "" {
			continue
		}
		return false
	}
	for _, signal := range report.Signals {
		if signal.Category == inventory.SignalSkill && signal.Partial {
			return false
		}
	}
	return true
}

// hasRemovedSkill reports a removed row, which is published even when the
// rows still present are unchanged.
func hasRemovedSkill(components []endpointInventoryComponent) bool {
	for _, component := range components {
		if component.skillState == skillStateRemoved {
			return true
		}
	}
	return false
}
