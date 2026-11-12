// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0088: the rescan's drift scan read an MCP baseline that holds no
// completed scan as a target to diff. Its scan of a loopback server failed
// ("rescan could not scan it"), and it wrote the baseline again without the
// mark that said why the server had no scan, or wrote none where it had none:
// the hook then read the plain baseline as a decided admission, so a server
// whose allow rule was gone, or whose block was released, ran on, also after
// a gateway restart. Every MCP baseline without a completed scan goes through
// admission, which applies the failure in the tier that fails closed.

// noScanBaseline gives the managed fixture's server a baseline with no scan,
// fingerprint ending in mark, and no block.
func (f *allowRemovalFixture) noScanBaseline(mark string) {
	f.t.Helper()
	evt := InstallEvent{Type: InstallMCP, Name: f.server.Name, Path: MCPEventPath(f.server), Connector: f.server.Connector}
	snap, err := f.w.snapshotForEvent(evt)
	if err != nil {
		f.t.Fatal(err)
	}
	if !f.w.persistSnapshot(evt, snap, "", f.w.cachedFingerprint(evt, nil)+mark) {
		f.t.Fatal("baseline not written")
	}
	f.w.firstCycleDone.Store(true)
}

func TestGAP0088RescanBlocksAFailedMCPBaselineWhoseBlockWasReleased(t *testing.T) {
	f := newManagedAllowRemovalFixture(t)
	f.noScanBaseline(mcpScanFailedMark)
	f.w.runRescanCycle(context.Background())
	if status := f.status(); !status.Failed || !f.blocked() {
		t.Fatalf("after the rescan: %+v blocked=%v, want the failed admission blocked", status, f.blocked())
	}
}

// The same for a server kept unverified whose definition the scanner refuses:
// its mark is kept, and the managed tier blocks it.
func TestGAP0088RescanKeepsTheMarkOfAnUnverifiedMCPBaseline(t *testing.T) {
	f := newManagedAllowRemovalFixture(t)
	f.noScanBaseline(unverifiedMCPMark)
	for range 2 {
		f.w.runRescanCycle(context.Background())
	}
	if status := f.status(); !status.Failed || !f.blocked() {
		t.Fatalf("after the rescans: %+v blocked=%v, want the failed admission blocked", status, f.blocked())
	}
}

// The discovery poll admits again, within its interval, a server whose allow
// without a scan is gone, so the block is back before any call or the hourly
// rescan.
func TestGAP0088DiscoveryPollBlocksALapsedAdmissionWithoutACall(t *testing.T) {
	f := newManagedAllowRemovalFixture(t)
	f.managedAdmittedThenRuleRemoved(true)
	f.w.firstCycleDone.Store(true)
	f.w.discoverAddedMCPServers()
	f.admitQueued()
	if !f.blocked() {
		t.Fatal("after the discovery poll: not blocked, want the revoked admission blocked again")
	}
}

// Benign twins: the OSS default tier keeps a server it cannot scan with a
// warning, and a standing allow admits it without a scan.
func TestGAP0088DefaultTierKeepsAnUnscannableMCPServerWithAWarning(t *testing.T) {
	f := newManagedAllowRemovalFixture(t)
	f.cfg.DeploymentMode, f.cfg.Enterprise.Profile = "", ""
	f.noScanBaseline(mcpScanFailedMark)
	f.w.runRescanCycle(context.Background())
	if status := f.status(); f.blocked() || !status.Failed {
		t.Fatalf("default tier: %+v blocked=%v, want it kept with a warning and its failed scan visible", status, f.blocked())
	}
}

func TestGAP0088StandingAllowAdmitsAFailedMCPBaseline(t *testing.T) {
	f := newManagedAllowRemovalFixture(t)
	f.noScanBaseline(mcpScanFailedMark)
	f.cfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: f.server.Name, URL: f.server.URL}}
	f.w.runRescanCycle(context.Background())
	if status := f.status(); status.Failed || status.Pending || f.blocked() {
		t.Fatalf("with the rule standing: %+v blocked=%v, want it admitted", status, f.blocked())
	}
}
