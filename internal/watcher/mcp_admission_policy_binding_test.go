// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
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

// The policy is read again after the scan, and that read reaches the
// definition of the server too. A decision it yields belongs to the definition
// that was scanned, so a definition found at that read decides nothing.

// A clean scan of an ordinary definition is not a blocked verdict because the
// definition read after the scan matches a deny rule.
func TestPostScanPolicyBlockOnAnotherDefinitionDoesNotBlockTheOrdinaryOne(t *testing.T) {
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
	reads := 0
	h.w.SetAdmissionPolicySource(func() AdmissionPolicySnapshot {
		reads++
		if reads == 2 {
			server.Args = []string{"-y", "other"}
		}
		return AdmissionPolicySnapshot{Config: h.w.cfg}
	})
	res := h.w.runAdmission(context.Background(), evt.admittingSnapshot(snap))
	server.Args = []string{"-y", "ordinary-new"}
	if reads < 2 {
		t.Fatalf("post-scan policy source not read: %d", reads)
	}
	if !res.Interrupted || res.Verdict == VerdictBlocked || res.Verdict == VerdictRejected {
		t.Fatalf("a post-scan policy block on another definition decided the ordinary one: %+v", res)
	}
	if state := h.journal(*server); state.Runtime == "disable" || state.Install == "block" || state.File != "" {
		t.Fatalf("a post-scan policy block on another definition disabled the ordinary server: %+v", state)
	}
}

// Its twin: a deny rule pinned to the scanned definition still blocks it.
func TestPostScanPolicyBlockOnTheScannedDefinitionStillBlocksIt(t *testing.T) {
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
	reads := 0
	h.w.SetAdmissionPolicySource(func() AdmissionPolicySnapshot {
		reads++
		if reads == 2 {
			h.w.cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{Name: server.Name, Command: "npx", ArgsPrefix: []string{"-y", "ordinary-new"}, Reason: "denied definition"}}
		}
		return AdmissionPolicySnapshot{Config: h.w.cfg}
	})
	res := h.w.runAdmission(context.Background(), evt.admittingSnapshot(snap))
	if reads < 2 {
		t.Fatalf("post-scan policy source not read: %d", reads)
	}
	if res.Interrupted || (res.Verdict != VerdictBlocked && res.Verdict != VerdictRejected) {
		t.Fatalf("a post-scan policy block on the scanned definition did not block it: %+v", res)
	}
}

// A high finding on one definition does not disable the ordinary definition
// the server has by the time the post-scan policy is read.
func TestPostScanFindingDoesNotDisableAnotherOrdinaryDefinition(t *testing.T) {
	h := newDefinitionChangeHarness(t, enrolledMCPServer(t.TempDir(), "1001", "."))
	h.w.cfg.Guardrail.RulePack = "balanced"
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictClean {
		t.Fatalf("initial ordinary admission: %+v", got)
	}
	server := &h.servers[0]
	server.Args = []string{"-y", "decoy-new"}
	evt := policyBindingEvent(*server)
	snap, err := h.w.snapshotForEvent(evt)
	if err != nil {
		t.Fatal(err)
	}
	reads := 0
	h.w.SetAdmissionPolicySource(func() AdmissionPolicySnapshot {
		reads++
		if reads == 2 {
			server.Args = []string{"-y", "ordinary-new"}
		}
		return AdmissionPolicySnapshot{Config: h.w.cfg}
	})
	res := h.w.runAdmission(context.Background(), evt.admittingSnapshot(snap))
	if reads < 2 {
		t.Fatalf("post-scan policy source not read: %d", reads)
	}
	if !res.Interrupted || res.Verdict == VerdictBlocked || res.Verdict == VerdictRejected {
		t.Fatalf("a finding on one definition decided another: %+v", res)
	}
	if state := h.journal(*server); state.Runtime == "disable" || state.Install == "block" || state.File != "" {
		t.Fatalf("a finding on one definition disabled another ordinary server: %+v", state)
	}
}

// Its twin: the same finding on a stable definition still rejects and
// disables it.
func TestPostScanFindingOnAStableDefinitionStillDisablesIt(t *testing.T) {
	h := newDefinitionChangeHarness(t, enrolledMCPServer(t.TempDir(), "1001", "."))
	h.w.cfg.Guardrail.RulePack = "balanced"
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictClean {
		t.Fatalf("initial ordinary admission: %+v", got)
	}
	server := &h.servers[0]
	server.Args = []string{"-y", "decoy-new"}
	evt := policyBindingEvent(*server)
	snap, err := h.w.snapshotForEvent(evt)
	if err != nil {
		t.Fatal(err)
	}
	h.w.SetAdmissionPolicySource(func() AdmissionPolicySnapshot { return AdmissionPolicySnapshot{Config: h.w.cfg} })
	res := h.w.runAdmission(context.Background(), evt.admittingSnapshot(snap))
	if res.Interrupted || res.Verdict != VerdictRejected {
		t.Fatalf("a finding on a stable definition did not reject it: %+v", res)
	}
	if state := h.journal(*server); state.Runtime != "disable" || state.Install != "block" {
		t.Fatalf("a finding on a stable definition did not disable it: %+v", state)
	}
}

// A block an earlier failed scan left belongs to the definition that failed.
// It is released only when the admission that releases it has settled on the
// definition it was started for: a definition that changes again while the
// policy is read decides nothing, and the block stays.

// failedJudgeScanner is a scanner whose judge failed, so the scan ends as a
// failure that blocks the server.
func failedJudgeScanner() scanner.Scanner {
	return &countingScanner{name: "mcp-scanner", findings: []scanner.Finding{{
		RuleID: scanner.RuleLLMAnalysisFailed, Severity: scanner.SeverityHigh, Title: "judge unavailable",
	}}}
}

// blockedByFailedScan returns a harness whose server a failed scan blocked.
func blockedByFailedScan(t *testing.T) *definitionChangeHarness {
	t.Helper()
	h := newDefinitionChangeHarness(t, enrolledMCPServer(t.TempDir(), "1001", "faulty"))
	h.w.cfg.Guardrail.RulePack = "balanced"
	h.w.scannerFactory = func(InstallEvent) scanner.Scanner { return failedJudgeScanner() }
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictBlocked {
		t.Fatalf("initial failed scan: %+v", got)
	}
	if state := h.journal(h.servers[0]); state.Install != "block" || state.Runtime != "disable" {
		t.Fatalf("initial scan failure not blocked: %+v", state)
	}
	return h
}

// A clean scan of a changed definition releases the earlier block when the
// definition stays as it was scanned.
func TestCleanScanOfTheSnapshottedDefinitionReleasesTheScanFailureBlock(t *testing.T) {
	h := blockedByFailedScan(t)
	h.w.scannerFactory = func(InstallEvent) scanner.Scanner { return &countingScanner{name: "mcp-scanner"} }
	server := &h.servers[0]
	server.Args = []string{"-y", "ordinary-new"}
	evt := policyBindingEvent(*server)
	snap, err := h.w.snapshotForEvent(evt)
	if err != nil {
		t.Fatal(err)
	}
	res := h.w.runAdmission(context.Background(), evt.admittingSnapshot(snap))
	if res.Interrupted || res.Verdict != VerdictClean {
		t.Fatalf("clean scan of a stable definition: %+v", res)
	}
	if state := h.journal(*server); state.Install == "block" || state.Runtime == "disable" {
		t.Fatalf("a clean scan of the snapshotted definition kept the block: %+v", state)
	}
}

// A clean scan whose definition changes again at the post-scan policy read
// releases nothing: the definition now in the file is unscanned.
func TestCleanScanDoesNotReleaseTheScanFailureBlockOfAMovedDefinition(t *testing.T) {
	h := blockedByFailedScan(t)
	h.w.scannerFactory = func(InstallEvent) scanner.Scanner { return &countingScanner{name: "mcp-scanner"} }
	server := &h.servers[0]
	server.Args = []string{"-y", "ordinary-new"}
	evt := policyBindingEvent(*server)
	snap, err := h.w.snapshotForEvent(evt)
	if err != nil {
		t.Fatal(err)
	}
	reads := 0
	h.w.SetAdmissionPolicySource(func() AdmissionPolicySnapshot {
		reads++
		if reads == 2 {
			server.Args = []string{"-y", "unscanned-new"}
		}
		return AdmissionPolicySnapshot{Config: h.w.cfg}
	})
	res := h.w.runAdmission(context.Background(), evt.admittingSnapshot(snap))
	if reads < 2 || !res.Interrupted {
		t.Fatalf("post-scan change not interrupted: reads=%d result=%+v", reads, res)
	}
	if state := h.journal(*server); state.Install != "block" || state.Runtime != "disable" {
		t.Fatalf("the unscanned definition lost the scan-failure block: status=%+v journal=%+v", statusOf(h, *server), state)
	}
}

// A server the scanner refuses releases the earlier block when the definition
// stays as it was scanned: the balanced tier keeps it with a warning.
func TestRefusedDefinitionReleasesTheScanFailureBlockWhenStable(t *testing.T) {
	h := blockedByFailedScan(t)
	server := &h.servers[0]
	server.Command, server.Args = "node", []string{"server.js"}
	evt := policyBindingEvent(*server)
	snap, err := h.w.snapshotForEvent(evt)
	if err != nil {
		t.Fatal(err)
	}
	h.w.scannerFactory = func(InstallEvent) scanner.Scanner {
		return &scriptedMCPScanner{h: h, fail: errors.New(nodeRefusal)}
	}
	res := h.w.runAdmission(context.Background(), evt.admittingSnapshot(snap))
	if res.Interrupted || res.Verdict != VerdictScanError {
		t.Fatalf("refused stable definition: %+v", res)
	}
	if state := h.journal(*server); state.Install == "block" || state.Runtime == "disable" {
		t.Fatalf("a kept, refused definition left the scan-failure block of the one it replaced: %+v", state)
	}
}

// A refusal whose definition changes at the policy read that decides to keep
// it releases nothing.
func TestRefusedDefinitionDoesNotReleaseTheScanFailureBlockOfAMovedDefinition(t *testing.T) {
	h := blockedByFailedScan(t)
	server := &h.servers[0]
	server.Command, server.Args = "node", []string{"server.js"}
	evt := policyBindingEvent(*server)
	snap, err := h.w.snapshotForEvent(evt)
	if err != nil {
		t.Fatal(err)
	}
	h.w.scannerFactory = func(InstallEvent) scanner.Scanner {
		return &scriptedMCPScanner{h: h, fail: errors.New(nodeRefusal)}
	}
	reads := 0
	h.w.SetAdmissionPolicySource(func() AdmissionPolicySnapshot {
		reads++
		if reads == 2 {
			server.Command, server.Args = "npx", []string{"-y", "decoy-new"}
		}
		return AdmissionPolicySnapshot{Config: h.w.cfg}
	})
	res := h.w.runAdmission(context.Background(), evt.admittingSnapshot(snap))
	if reads < 2 || !res.Interrupted {
		t.Fatalf("policy-read change not interrupted: reads=%d result=%+v", reads, res)
	}
	if state := h.journal(*server); state.Install != "block" || state.Runtime != "disable" {
		t.Fatalf("an unscanned definition lost the scan-failure block: status=%+v journal=%+v", statusOf(h, *server), state)
	}
}
