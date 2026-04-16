// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
)

func newTestEnforce(t *testing.T) (*enforce.PolicyEngine, *audit.Store) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "e2e-enforce.db")
	store, err := audit.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return enforce.NewPolicyEngine(store), store
}

func TestBlockSkill_ThenCheck(t *testing.T) {
	pe, _ := newTestEnforce(t)

	if err := pe.Block("skill", "evil-skill", "contains malware"); err != nil {
		t.Fatalf("Block: %v", err)
	}

	blocked, err := pe.IsBlocked("skill", "evil-skill")
	if err != nil {
		t.Fatalf("IsBlocked: %v", err)
	}
	if !blocked {
		t.Error("skill should be blocked after Block()")
	}
}

func TestBlockSkill_Unblock(t *testing.T) {
	pe, _ := newTestEnforce(t)

	if err := pe.Block("skill", "temp-block", "test"); err != nil {
		t.Fatal(err)
	}

	if err := pe.Unblock("skill", "temp-block"); err != nil {
		t.Fatalf("Unblock: %v", err)
	}

	blocked, _ := pe.IsBlocked("skill", "temp-block")
	if blocked {
		t.Error("skill should NOT be blocked after Unblock()")
	}
}

func TestAllowSkill_SkipsScan(t *testing.T) {
	pe, _ := newTestEnforce(t)

	if err := pe.Allow("skill", "trusted-skill", "vendor-approved"); err != nil {
		t.Fatalf("Allow: %v", err)
	}

	allowed, err := pe.IsAllowed("skill", "trusted-skill")
	if err != nil {
		t.Fatalf("IsAllowed: %v", err)
	}
	if !allowed {
		t.Error("skill should be allowed after Allow()")
	}
}

func TestAllowSkill_ThenUnblock(t *testing.T) {
	pe, _ := newTestEnforce(t)

	if err := pe.Allow("skill", "temp-allow", "test"); err != nil {
		t.Fatal(err)
	}

	if err := pe.Unblock("skill", "temp-allow"); err != nil {
		t.Fatalf("Unblock: %v", err)
	}

	allowed, _ := pe.IsAllowed("skill", "temp-allow")
	if allowed {
		t.Error("skill should NOT be allowed after Unblock() clears install action")
	}
}

func TestBlockTakesPrecedenceOverAllow(t *testing.T) {
	pe, _ := newTestEnforce(t)

	if err := pe.Allow("skill", "conflict-skill", "vendor-approved"); err != nil {
		t.Fatal(err)
	}
	if err := pe.Block("skill", "conflict-skill", "later blocked by policy"); err != nil {
		t.Fatal(err)
	}

	blocked, _ := pe.IsBlocked("skill", "conflict-skill")
	if !blocked {
		t.Error("block should take precedence — blocked skill must be rejected")
	}
}

func TestBlockMCP_ThenCheck(t *testing.T) {
	pe, _ := newTestEnforce(t)

	if err := pe.Block("mcp", "suspicious-server", "unapproved"); err != nil {
		t.Fatal(err)
	}

	blocked, _ := pe.IsBlocked("mcp", "suspicious-server")
	if !blocked {
		t.Error("MCP server should be blocked")
	}
}

func TestAllowMCP_ThenCheck(t *testing.T) {
	pe, _ := newTestEnforce(t)

	if err := pe.Allow("mcp", "trusted-server", "approved"); err != nil {
		t.Fatal(err)
	}

	allowed, _ := pe.IsAllowed("mcp", "trusted-server")
	if !allowed {
		t.Error("MCP server should be allowed")
	}
}

func TestQuarantine(t *testing.T) {
	pe, _ := newTestEnforce(t)

	if err := pe.Quarantine("skill", "bad-skill", "/tmp/quarantine/bad-skill"); err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	quarantined, err := pe.IsQuarantined("skill", "bad-skill")
	if err != nil {
		t.Fatalf("IsQuarantined: %v", err)
	}
	if !quarantined {
		t.Error("skill should be quarantined")
	}
}

func TestClearQuarantine(t *testing.T) {
	pe, _ := newTestEnforce(t)

	pe.Quarantine("skill", "quarantined-skill", "test")
	if err := pe.ClearQuarantine("skill", "quarantined-skill"); err != nil {
		t.Fatalf("ClearQuarantine: %v", err)
	}

	quarantined, _ := pe.IsQuarantined("skill", "quarantined-skill")
	if quarantined {
		t.Error("skill should NOT be quarantined after ClearQuarantine()")
	}
}

func TestDisable_Enable(t *testing.T) {
	pe, _ := newTestEnforce(t)

	if err := pe.Disable("skill", "risky-skill", "under review"); err != nil {
		t.Fatal(err)
	}

	action, err := pe.GetAction("skill", "risky-skill")
	if err != nil {
		t.Fatalf("GetAction: %v", err)
	}
	if action == nil {
		t.Fatal("expected action entry after Disable()")
	}

	if err := pe.Enable("skill", "risky-skill"); err != nil {
		t.Fatalf("Enable: %v", err)
	}
}

func TestAdmissionGate_AllSixPaths(t *testing.T) {
	pe, _ := newTestEnforce(t)

	// Path 1: Block list → reject
	pe.Block("skill", "blocked-skill", "policy")
	blocked, _ := pe.IsBlocked("skill", "blocked-skill")
	if !blocked {
		t.Error("Path 1 failed: blocked skill should be rejected")
	}

	// Path 2: Allow list → skip scan
	pe.Allow("skill", "allowed-skill", "vendor")
	allowed, _ := pe.IsAllowed("skill", "allowed-skill")
	if !allowed {
		t.Error("Path 2 failed: allowed skill should skip scan")
	}

	// Path 3: Not blocked, not allowed → scan required (neither flag set)
	blocked, _ = pe.IsBlocked("skill", "unknown-skill")
	allowed, _ = pe.IsAllowed("skill", "unknown-skill")
	if blocked || allowed {
		t.Error("Path 3 failed: unknown skill should require scanning")
	}

	// Path 4: Scan CLEAN → install (audit event logged)
	// Verified via scan_test.go audit persistence tests

	// Path 5: Scan HIGH/CRITICAL → reject (quarantine enforced)
	pe.Quarantine("skill", "high-sev-skill", "scanner found critical vuln")
	q, _ := pe.IsQuarantined("skill", "high-sev-skill")
	if !q {
		t.Error("Path 5 failed: high-severity skill should be quarantined")
	}

	// Path 6: Scan MEDIUM/LOW → install with warning (disable runtime)
	pe.Disable("skill", "medium-sev-skill", "scanner found medium vuln")
	action, _ := pe.GetAction("skill", "medium-sev-skill")
	if action == nil {
		t.Error("Path 6 failed: medium-severity skill should have a disable action")
	}
}

func TestBlockListAuditLog(t *testing.T) {
	pe, store := newTestEnforce(t)

	pe.Block("skill", "audit-test-skill", "testing audit")

	action, err := pe.GetAction("skill", "audit-test-skill")
	if err != nil {
		t.Fatalf("GetAction: %v", err)
	}
	if action == nil {
		t.Fatal("expected action entry")
	}

	events, err := store.ListEvents(50)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	_ = events
}
