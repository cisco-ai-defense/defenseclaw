// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The live policy and the definition are read after an admission starts. A
// decision the policy makes before any scan (a block, an allow) belongs to the
// definition the snapshot named, so a rewrite while the policy is read decides
// nothing and leaves the earlier protection as it was.

func policyBindingEvent(server config.MCPServerEntry) InstallEvent {
	return InstallEvent{Type: InstallMCP, Name: server.Name, Path: MCPEventPath(server), Connector: server.Connector}
}

// A policy block found on another definition is not the verdict of the
// ordinary definition the snapshot named: the sidecar disables a server on a
// blocked verdict, so the admission must decide nothing.
func TestPolicyBlockOnAnotherDefinitionDoesNotDisableTheOrdinaryOne(t *testing.T) {
	h := newDefinitionChangeHarness(t, enrolledMCPServer(t.TempDir(), "1001", "."))
	h.w.cfg.Guardrail.RulePack = "balanced"
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictClean {
		t.Fatalf("initial ordinary admission: %+v", got)
	}
	server := &h.servers[0]
	server.Args = []string{"-y", "ordinary-new"}
	evt := policyBindingEvent(*server)
	snap, err := h.w.snapshotForEvent(evt)
	if err != nil {
		t.Fatal(err)
	}
	h.w.cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{Name: server.Name, Command: "npx", ArgsPrefix: []string{"-y", "other"}, Reason: "other definition"}}
	h.w.SetAdmissionPolicySource(func() AdmissionPolicySnapshot {
		server.Args = []string{"-y", "other"}
		return AdmissionPolicySnapshot{Config: h.w.cfg}
	})
	res := h.w.runAdmission(context.Background(), evt.admittingSnapshot(snap))
	server.Args = []string{"-y", "ordinary-new"}
	if !res.Interrupted || res.Verdict == VerdictBlocked || res.Verdict == VerdictRejected {
		t.Fatalf("a policy block on another definition decided the ordinary one: %+v", res)
	}
}

// A policy block pinned to the definition the snapshot named still blocks it.
func TestPolicyBlockOnTheSnapshottedDefinitionStillBlocksIt(t *testing.T) {
	h := newDefinitionChangeHarness(t, enrolledMCPServer(t.TempDir(), "1001", "."))
	h.w.cfg.Guardrail.RulePack = "balanced"
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictClean {
		t.Fatalf("initial ordinary admission: %+v", got)
	}
	server := &h.servers[0]
	server.Args = []string{"-y", "ordinary-new"}
	evt := policyBindingEvent(*server)
	snap, err := h.w.snapshotForEvent(evt)
	if err != nil {
		t.Fatal(err)
	}
	h.w.cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{Name: server.Name, Command: "npx", ArgsPrefix: []string{"-y", "ordinary-new"}, Reason: "denied definition"}}
	h.w.SetAdmissionPolicySource(func() AdmissionPolicySnapshot { return AdmissionPolicySnapshot{Config: h.w.cfg} })
	res := h.w.runAdmission(context.Background(), evt.admittingSnapshot(snap))
	if res.Interrupted || (res.Verdict != VerdictBlocked && res.Verdict != VerdictRejected) {
		t.Fatalf("a policy block on the snapshotted definition did not block it: %+v", res)
	}
}

// A policy allow found on another definition does not lift the finding block
// of the dangerous definition the snapshot named.
func TestPolicyAllowOnAnotherDefinitionKeepsThePriorFindingBlock(t *testing.T) {
	h := newDefinitionChangeHarness(t, enrolledMCPServer(t.TempDir(), "1001", "decoy"))
	h.w.cfg.Guardrail.RulePack = "balanced"
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictRejected {
		t.Fatalf("initial high finding: %+v", got)
	}
	server := &h.servers[0]
	if state := h.journal(*server); state.Runtime != "disable" || state.Install != "block" {
		t.Fatalf("initial finding not blocked: %+v", state)
	}
	server.Args = []string{"-y", "decoy-new"}
	evt := policyBindingEvent(*server)
	baseline, err := h.w.mcpSnapshotForEvent(evt)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := h.w.snapshotForEvent(evt)
	if err != nil {
		t.Fatal(err)
	}
	h.w.cfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: server.Name, Command: "npx", ArgsPrefix: []string{"-y", "ordinary"}, Reason: "reviewed other definition"}}
	h.w.SetAdmissionPolicySource(func() AdmissionPolicySnapshot {
		server.Args = []string{"-y", "ordinary"}
		return AdmissionPolicySnapshot{Config: h.w.cfg}
	})
	h.w.readmitChanged(context.Background(), evt, baseline, snap, nil, "rescan", "rescan")
	server.Args = []string{"-y", "decoy-new"}
	if state := h.journal(*server); state.Runtime != "disable" || state.Install != "block" {
		t.Fatalf("an allow for another definition lifted the finding block: status=%+v journal=%+v", statusOf(h, *server), state)
	}
	if status := statusOf(h, *server); !status.Pending && !status.Failed {
		t.Fatalf("the unscanned definition reads as admitted: %+v", status)
	}
}

// A policy allow for the definition the snapshot named still lifts the block
// its predecessor left.
func TestPolicyAllowOnTheSnapshottedDefinitionStillLiftsThePriorBlock(t *testing.T) {
	h := newDefinitionChangeHarness(t, enrolledMCPServer(t.TempDir(), "1001", "decoy"))
	h.w.cfg.Guardrail.RulePack = "balanced"
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictRejected {
		t.Fatalf("initial high finding: %+v", got)
	}
	server := &h.servers[0]
	server.Args = []string{"-y", "ordinary"}
	evt := policyBindingEvent(*server)
	baseline, err := h.w.mcpSnapshotForEvent(evt)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := h.w.snapshotForEvent(evt)
	if err != nil {
		t.Fatal(err)
	}
	h.w.cfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: server.Name, Command: "npx", ArgsPrefix: []string{"-y", "ordinary"}, Reason: "reviewed definition"}}
	h.w.SetAdmissionPolicySource(func() AdmissionPolicySnapshot { return AdmissionPolicySnapshot{Config: h.w.cfg} })
	h.w.readmitChanged(context.Background(), evt, baseline, snap, nil, "rescan", "rescan")
	if state := h.journal(*server); state.Runtime == "disable" || state.Install == "block" {
		t.Fatalf("an allow for the snapshotted definition left the old block: %+v", state)
	}
}

// A definition rewritten after the verdict, before its baseline is written,
// keeps the block of the definition it replaced: the release goes with the
// baseline, and the baseline is not written for a definition it does not name.
func TestDefinitionChangeAfterTheVerdictKeepsThePriorFindingBlock(t *testing.T) {
	h := newDefinitionChangeHarness(t, enrolledMCPServer(t.TempDir(), "1001", "decoy"))
	h.w.cfg.Guardrail.RulePack = "balanced"
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictRejected {
		t.Fatalf("initial high finding: %+v", got)
	}
	server := &h.servers[0]
	server.Args = []string{"-y", "ordinary"}
	evt := policyBindingEvent(*server)
	h.w.onAdmit = func(res AdmissionResult) {
		if res.Verdict == VerdictClean {
			server.Args = []string{"-y", "decoy-new"}
		}
	}
	if got := h.w.rescanTarget(context.Background(), evt, nil); got != rescanScanned {
		t.Fatalf("changed-server rescan = %v", got)
	}
	if status := statusOf(h, *server); !status.Pending && !status.Failed {
		t.Fatalf("the new definition inherited the earlier clean verdict: %+v", status)
	}
	if state := h.journal(*server); state.Runtime != "disable" || state.Install != "block" {
		t.Fatalf("a clean verdict on another definition lifted the finding block: status=%+v journal=%+v", statusOf(h, *server), state)
	}
}
