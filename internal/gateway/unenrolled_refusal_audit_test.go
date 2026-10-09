// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/managed/refusalpipe"
)

// GAP-1242: a call the Windows standalone hook refuses for an excluded or
// not-yet-enrolled account is written as a block row naming the account the
// pipe client token identified, the connector, the event, the tool and the
// reason; a refusal loop is coalesced to one row a window per account and
// connector, with the count of the refusals that followed.
func TestUnenrolledRefusalWritesACoalescedBlockRowForTheAccount(t *testing.T) {
	sid := "S-1-5-21-1111-2222-3333-1042"
	report := refusalpipe.Report{
		Connector: "claudecode", Reason: refusalpipe.ReasonSIDUnregistered, Event: "PreToolUse", Tool: "Bash",
	}
	var rows []unenrolledRefusalRow
	auditor := newUnenrolledRefusalAuditor(func(row unenrolledRefusalRow) { rows = append(rows, row) })
	now := time.Unix(1_800_000_000, 0)
	auditor.now = func() time.Time { return now }
	for range 50 {
		auditor.record(sid, report)
	}
	auditor.record(sid, refusalpipe.Report{Connector: "codex", Reason: refusalpipe.ReasonSIDUnregistered})
	auditor.flush()
	if len(rows) != 2 || rows[0].Attempts != 1 || rows[0].Report != report || rows[1].Report.Connector != "codex" {
		t.Fatalf("rows in the first window = %+v, want one claudecode and one codex row", rows)
	}
	now = now.Add(unenrolledRefusalWindow)
	auditor.flush()
	if len(rows) != 3 || rows[2].Attempts != 49 || rows[2].SID != sid || len(auditor.entries) != 0 {
		t.Fatalf("rows after the window = %+v entries = %d, want the 49 coalesced refusals", rows, len(auditor.entries))
	}

	// The rows audit export reads: a hook decision and a connector-hook block
	// naming the account, with the tool and the coalesced count.
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	api := &APIServer{store: fixture.store, logger: fixture.logger}
	fixture.sidecar.setAPIServer(api)
	if bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, fixture.raw); err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	api.auditUnenrolledRefusal(context.Background(), rows[2])
	var decision, block *audit.Event
	for wait := time.Now().Add(5 * time.Second); (decision == nil || block == nil) && time.Now().Before(wait); time.Sleep(10 * time.Millisecond) {
		events, err := fixture.store.ListEvents(50)
		if err != nil {
			t.Fatal(err)
		}
		for i := range events {
			switch events[i].Action {
			case "hook_decision":
				decision = &events[i]
			case string(audit.ActionConnectorHook):
				block = &events[i]
			}
		}
	}
	if decision == nil || block == nil {
		t.Fatalf("hook decision row %v, connector-hook row %v", decision != nil, block != nil)
	}
	if decision.Structured["user.id"] != sid || decision.Structured["defenseclaw.guardrail.effective_action"] != "block" ||
		decision.Structured["defenseclaw.guardrail.reason"] != refusalpipe.ReasonSIDUnregistered || decision.Connector != "claudecode" {
		t.Fatalf("hook decision row connector=%q structured=%v", decision.Connector, decision.Structured)
	}
	extra, _ := block.Structured["extra"].(map[string]any)
	if block.Structured[auditUserIDKey] != sid || block.Structured["action"] != "block" ||
		block.Structured["reason"] != refusalpipe.ReasonSIDUnregistered || extra["tool"] != "Bash" || extra["attempts"] != "49" {
		t.Fatalf("connector-hook row connector=%q structured=%v", block.Connector, block.Structured)
	}
}
