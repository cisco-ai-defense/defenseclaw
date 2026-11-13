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
// after the upgrade the server ran whatever the policy said. The first
// complete cycle on 1.0.10 admits such a server again under the current
// policy, once, bounded per cycle, and records the pass in the audit log.

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

func TestNoScanHealRefusesAnUnscannableManagedServerA109StoreRecordedPlain(t *testing.T) {
	f := newManagedAllowRemovalFixture(t)
	rows := auditRows(t, f.w.logger)
	f.noScanBaseline("") // as 1.0.9 left it: plain, no scan id, no block
	if status := f.status(); status.Failed || status.Pending || f.blocked() {
		t.Fatalf("precondition: the 1.0.9-shaped baseline reads as admitted: %+v blocked=%v", status, f.blocked())
	}
	f.w.runRescanCycle(context.Background())
	if status := f.status(); !status.Failed || !f.blocked() {
		t.Fatalf("after the first 1.0.10 cycle: %+v blocked=%v, want the unscannable server refused and blocked", status, f.blocked())
	}
	if !f.healDone() {
		t.Fatal("the pass was not recorded done")
	}
	if n := countRows(rows(), "noscan-baseline-heal"); n != 1 {
		t.Fatalf("upgrade audit rows for the pass = %d, want 1", n)
	}
}

func TestNoScanHealKeepsAnAllowedServerAndTheDefaultTierWarns(t *testing.T) {
	allowed := newManagedAllowRemovalFixture(t)
	allowed.cfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: allowed.server.Name, URL: allowed.server.URL, Reason: "reviewed"}}
	allowed.noScanBaseline("")
	allowed.w.runRescanCycle(context.Background())
	if status := allowed.status(); status.Failed || status.Pending || allowed.blocked() {
		t.Fatalf("allowed: %+v blocked=%v, want it admitted without a scan", status, allowed.blocked())
	}

	oss := newManagedAllowRemovalFixture(t)
	oss.cfg.DeploymentMode, oss.cfg.Enterprise.Profile = "", ""
	oss.noScanBaseline("")
	oss.w.runRescanCycle(context.Background())
	if status := oss.status(); oss.blocked() || !status.Failed {
		t.Fatalf("OSS default: %+v blocked=%v, want it kept with a warning and its failed scan visible", status, oss.blocked())
	}
}

// The pass runs once: a later cycle and a restart admit nothing again and
// write no second audit row.
func TestNoScanHealRunsOnce(t *testing.T) {
	f := newManagedAllowRemovalFixture(t)
	f.cfg.DeploymentMode, f.cfg.Enterprise.Profile = "", ""
	rows := auditRows(t, f.w.logger)
	f.noScanBaseline("")
	f.w.runRescanCycle(context.Background())
	// A plain baseline written after the pass (a later 0.8.x bridge) is left
	// as the bridge wrote it.
	f.noScanBaseline("")
	var admitted []AdmissionResult
	f.w.onAdmit = func(r AdmissionResult) { admitted = append(admitted, r) }
	for range 2 {
		f.w.runRescanCycle(context.Background())
	}
	if len(admitted) != 0 {
		t.Fatalf("cycles after the pass admitted %+v, want none", admitted)
	}
	if n := countRows(rows(), "noscan-baseline-heal"); n != 1 {
		t.Fatalf("upgrade audit rows = %d, want 1", n)
	}
}

// Bounded: past the per-cycle limit the rest waits for the next cycle, and
// the pass is recorded done only after the cycle that finished it.
func TestNoScanHealIsBoundedPerCycle(t *testing.T) {
	previous := mcpNoScanHealPerCycle
	t.Cleanup(func() { mcpNoScanHealPerCycle = previous })
	mcpNoScanHealPerCycle = 1
	f := newManagedAllowRemovalFixture(t)
	second := config.MCPServerEntry{Name: "v2probe-b", URL: "http://127.0.0.1:19556/mcp", Transport: "http", Connector: "claudecode", Home: "/home/u1"}
	first := f.server
	f.w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return []config.MCPServerEntry{first, second}, nil })
	f.noScanBaseline("")
	f.server = second
	f.noScanBaseline("")
	f.server = first
	f.w.runRescanCycle(context.Background())
	if f.healDone() {
		t.Fatal("the pass was recorded done with a server left")
	}
	f.w.runRescanCycle(context.Background())
	if !f.healDone() {
		t.Fatal("the pass was not recorded done after the cycle that finished it")
	}
	for _, server := range []config.MCPServerEntry{first, second} {
		f.server = server
		if status := f.status(); !status.Failed || !f.blocked() {
			t.Fatalf("%s: %+v blocked=%v, want refused and blocked", server.Name, status, f.blocked())
		}
	}
}
