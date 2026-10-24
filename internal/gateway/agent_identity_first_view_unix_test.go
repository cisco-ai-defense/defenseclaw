// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

func TestQualifiedAgentInventoryRefreshesHolderBeforeFiltering(t *testing.T) {
	oldIncarnation, oldToken, oldVerified, oldHistory := agentIdentityIncarnation, agentIdentityAccountToken, agentIdentityVerifiedAccountToken, agentIdentityHolderHistory
	t.Cleanup(func() {
		agentIdentityIncarnation, agentIdentityAccountToken, agentIdentityVerifiedAccountToken, agentIdentityHolderHistory = oldIncarnation, oldToken, oldVerified, oldHistory
	})
	refreshed := false
	agentIdentityIncarnation = func(string) string { refreshed = true; return "new-holder" }
	agentIdentityAccountToken = func(string) string { return "new-holder" }
	agentIdentityVerifiedAccountToken = func(string) string { return "new-holder" }
	agentIdentityHolderHistory = func(string) (string, bool) { return "new-holder", refreshed }
	id := "41700"
	incarnation, changed := adminViewAccountProvenance([]string{id}, "")
	if !changed {
		t.Fatal("first qualified view did not refresh holder history")
	}
	filter := inventory.AgentIdentityFilter{User: `OTHER\alice`, UserIDs: []string{id}, UserIncarnation: incarnation, HolderChanged: changed}
	legacy := inventory.AgentIdentityRecord{UserID: id, UserName: "alice", Connector: "codex"}
	current := legacy
	current.UserIncarnation = "new-holder"
	if agentIdentityMatches(legacy, filter) || !agentIdentityMatches(current, filter) {
		t.Fatal("qualified new-holder view exposed a tokenless prior row or hid its proven row")
	}
}

func TestQualifiedAgentInventoryWithUnprovenHolderSelectsNoUIDRows(t *testing.T) {
	oldIncarnation, oldToken, oldVerified, oldHistory := agentIdentityIncarnation, agentIdentityAccountToken, agentIdentityVerifiedAccountToken, agentIdentityHolderHistory
	t.Cleanup(func() {
		agentIdentityIncarnation, agentIdentityAccountToken, agentIdentityVerifiedAccountToken, agentIdentityHolderHistory = oldIncarnation, oldToken, oldVerified, oldHistory
	})
	agentIdentityIncarnation = func(string) string { return "" }
	agentIdentityAccountToken = func(string) string { return "old-holder" }
	agentIdentityVerifiedAccountToken = func(string) string { return "" }
	agentIdentityHolderHistory = func(string) (string, bool) { return "old-holder", false }
	id := "41701"
	incarnation, changed := adminViewAccountProvenance([]string{id}, "")
	filter := inventory.AgentIdentityFilter{User: `OTHER\alice`, UserIDs: []string{id}, UserIncarnation: incarnation, HolderChanged: changed}
	for _, row := range []inventory.AgentIdentityRecord{
		{UserID: id, UserName: "alice"},
		{UserID: id, UserName: "alice", UserIncarnation: "old-holder"},
		{UserID: "41709", UserName: `OTHER\alice`, UserIncarnation: "old-holder"},
	} {
		if agentIdentityMatches(row, filter) {
			t.Fatalf("unproven holder selected row %+v", row)
		}
	}
}

func TestQualifiedAgentInventoryRejectsUnrecordedHolderHandoff(t *testing.T) {
	oldIncarnation, oldVerified, oldHistory := agentIdentityIncarnation, agentIdentityVerifiedAccountToken, agentIdentityHolderHistory
	t.Cleanup(func() {
		agentIdentityIncarnation, agentIdentityVerifiedAccountToken, agentIdentityHolderHistory = oldIncarnation, oldVerified, oldHistory
	})
	agentIdentityIncarnation = func(string) string { return "" } // bounded holder history could not save
	agentIdentityVerifiedAccountToken = func(string) string { return "new-holder" }
	agentIdentityHolderHistory = func(string) (string, bool) { return "old-holder", false }
	incarnation, changed := adminViewAccountProvenance([]string{"41702"}, "")
	if incarnation != "" || !changed {
		t.Fatalf("unrecorded handoff returned incarnation=%q changed=%v; want fail closed", incarnation, changed)
	}
}
