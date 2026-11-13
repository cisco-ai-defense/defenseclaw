// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A 1.0.9 store can hold an MCP baseline without a scan that the rescan wrote
// plain (gas-ux-r2:GAP-0088): the hook reads it as a decided admission, so
// after the upgrade the server ran whatever the policy said. The first start
// on 1.0.10 marks every such stored baseline as owing an admission, whatever
// the servers listed then, records the pass once in the audit log, and the
// rescan or the discovery poll admits each server again under the current
// policy.

func (f *allowRemovalFixture) healDone() bool {
	f.t.Helper()
	_, err := f.w.store.GetTargetSnapshot(mcpNoScanHealType, mcpNoScanHealVersion)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		f.t.Fatal(err)
	}
	return err == nil
}

func countRows(rows []string, needle string) int {
	n := 0
	for _, row := range rows {
		if strings.Contains(row, needle) {
			n++
		}
	}
	return n
}

// start is a gateway start on 1.0.10 over the fixture store.
func (f *allowRemovalFixture) start() { f.w.markMCPNoScanAdmissionsOwed() }

func TestNoScanHealRefusesAnUnscannableManagedServerA109StoreRecordedPlain(t *testing.T) {
	f := newManagedAllowRemovalFixture(t)
	rows := auditRows(t, f.w.logger)
	f.noScanBaseline("") // as 1.0.9 left it: plain, no scan id, no block
	if status := f.status(); status.Failed || status.Pending || f.blocked() {
		t.Fatalf("precondition: the 1.0.9-shaped baseline reads as admitted: %+v blocked=%v", status, f.blocked())
	}
	f.start()
	if status := f.status(); !status.Failed {
		t.Fatalf("right after the start: %+v, want the owed admission read as failed before any cycle", status)
	}
	f.w.runRescanCycle(context.Background())
	if status := f.status(); !status.Failed || !f.blocked() {
		t.Fatalf("after the first cycle: %+v blocked=%v, want the unscannable server refused and blocked", status, f.blocked())
	}
	if !f.healDone() {
		t.Fatal("the pass was not recorded done")
	}
	if n := countRows(rows(), "noscan-baseline-heal"); n != 1 {
		t.Fatalf("upgrade audit rows for the pass = %d, want 1", n)
	}
}

// On a managed host the server list comes from the hooks and is empty at the
// start: the pass still marks the stored baseline, and the discovery poll
// admits the server once a hook reports it.
func TestNoScanHealMarksAServerNoHookReportedYet(t *testing.T) {
	f := newManagedAllowRemovalFixture(t)
	f.noScanBaseline("")
	listed := false
	server := f.server
	f.w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) {
		if !listed {
			return nil, nil
		}
		return []config.MCPServerEntry{server}, nil
	})
	f.start()
	f.w.runRescanCycle(context.Background())
	if !f.healDone() {
		t.Fatal("the pass was not recorded done")
	}
	row, err := mcpSnapshotForServer(f.w.store, server)
	if err != nil || !mcpAdmissionOwed(row) {
		t.Fatalf("unlisted at the start: baseline %+v err=%v, want the owed admission marked", row, err)
	}
	listed = true
	f.w.discoverAddedMCPServers()
	f.admitQueued()
	if status := f.status(); !status.Failed || !f.blocked() {
		t.Fatalf("after the hook reported it: %+v blocked=%v, want refused and blocked", status, f.blocked())
	}
}

func TestNoScanHealKeepsAnAllowedServerAndTheDefaultTierWarns(t *testing.T) {
	allowed := newManagedAllowRemovalFixture(t)
	allowed.cfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: allowed.server.Name, URL: allowed.server.URL, Reason: "reviewed"}}
	allowed.noScanBaseline("")
	allowed.start()
	allowed.w.runRescanCycle(context.Background())
	if status := allowed.status(); status.Failed || status.Pending || allowed.blocked() {
		t.Fatalf("allowed: %+v blocked=%v, want it admitted without a scan", status, allowed.blocked())
	}

	oss := newManagedAllowRemovalFixture(t)
	oss.cfg.DeploymentMode, oss.cfg.Enterprise.Profile = "", ""
	oss.noScanBaseline("")
	oss.start()
	oss.w.runRescanCycle(context.Background())
	if status := oss.status(); oss.blocked() || !status.Failed {
		t.Fatalf("OSS default: %+v blocked=%v, want it kept with a warning and its failed scan visible", status, oss.blocked())
	}
}

// The pass runs once: a later start marks nothing, and writes no second
// audit row; a plain baseline written after it is left as it was written.
func TestNoScanHealRunsOnce(t *testing.T) {
	f := newManagedAllowRemovalFixture(t)
	rows := auditRows(t, f.w.logger)
	f.noScanBaseline("")
	f.start()
	f.noScanBaseline("")
	f.start()
	row, err := mcpSnapshotForServer(f.w.store, f.server)
	if err != nil || row == nil || mcpAdmissionOwed(row) {
		t.Fatalf("baseline %+v err=%v, want the later plain baseline left unmarked", row, err)
	}
	if n := countRows(rows(), "noscan-baseline-heal"); n != 1 {
		t.Fatalf("upgrade audit rows = %d, want 1", n)
	}
}

// Bounded: a store with more records than one start reads is marked in part
// and not recorded done, so the next start goes on.
func TestNoScanHealIsBoundedPerStart(t *testing.T) {
	previous := mcpNoScanHealMaxRows
	t.Cleanup(func() { mcpNoScanHealMaxRows = previous })
	mcpNoScanHealMaxRows = 1
	f := newManagedAllowRemovalFixture(t)
	first, second := f.server, config.MCPServerEntry{Name: "v2probe-b", URL: "http://127.0.0.1:19556/mcp", Transport: "http", Connector: "claudecode", Home: "/home/u1"}
	f.noScanBaseline("")
	f.server = second
	f.noScanBaseline("")
	f.start()
	if f.healDone() {
		t.Fatal("the pass was recorded done with records left unread")
	}
	mcpNoScanHealMaxRows = 10
	f.start()
	if !f.healDone() {
		t.Fatal("the pass was not recorded done after the start that finished it")
	}
	for _, server := range []config.MCPServerEntry{first, second} {
		row, err := mcpSnapshotForServer(f.w.store, server)
		if err != nil || !mcpAdmissionOwed(row) {
			t.Fatalf("%s: baseline %+v err=%v, want the owed admission", server.Name, row, err)
		}
	}
}
