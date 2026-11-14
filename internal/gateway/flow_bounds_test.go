// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func flowBoundsRequest(cmd string, strict bool) trustedActionRequest {
	return trustedActionRequest{
		Input:     actionfacts.Input{Tool: "Bash", Command: cmd, CWD: "/home/u/p", ActiveHome: "/home/u"},
		Connector: "claudecode", EnforcementCapable: true, StrictPolicy: strict,
	}
}

func resetFlowLaneBoundStats() {
	flowLaneDropped.Store(0)
	for i := range flowLaneCapHits {
		flowLaneCapHits[i].Store(0)
	}
}

// TestFlowLaneBoundSkipsAnOversizedCommand: a command past the input bound is
// not read: nothing is recorded, the cap is counted, and the answer is nil.
func TestFlowLaneBoundSkipsAnOversizedCommand(t *testing.T) {
	withSecretFlowGeneration(t, "shadow", "shadow")
	resetFlowLaneBoundStats()
	ctx := ContextWithSessionID(context.Background(), "bounds-size")
	big := "cat .env > /tmp/x; " + strings.Repeat("echo a; ", flowLaneMaxBytes/8+8)
	if got := runSecretFlowShadow(ctx, flowBoundsRequest(big, true)); got != nil {
		t.Fatalf("shadow answered findings for a skipped run: %v", got)
	}
	stats := flowLaneBoundStats()
	if hits, _ := stats["cap_hits"].(map[string]int64); hits["bytes"] != 1 {
		t.Fatalf("cap_hits = %v, want one bytes hit", stats["cap_hits"])
	}
	if v := secretFlowSessions.view("bounds-size"); len(v.Hits) != 0 {
		t.Fatalf("a skipped run recorded hits: %+v", v.Hits)
	}
	if len(flowLaneSlots) != 0 {
		t.Fatalf("the run kept its slot")
	}
}

// TestFlowLaneBoundSlotCap: with every slot taken a run is skipped and counted,
// never queued.
func TestFlowLaneBoundSlotCap(t *testing.T) {
	withSecretFlowGeneration(t, "shadow", "shadow")
	resetFlowLaneBoundStats()
	for i := 0; i < flowLaneMaxConcurrent; i++ {
		flowLaneSlots <- struct{}{}
	}
	defer func() {
		for i := 0; i < flowLaneMaxConcurrent; i++ {
			<-flowLaneSlots
		}
	}()
	ctx := ContextWithSessionID(context.Background(), "bounds-slots")
	start := time.Now()
	if got := runSecretFlowShadow(ctx, flowBoundsRequest("cat .env", false)); got != nil {
		t.Fatalf("a dropped run answered findings: %v", got)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("a dropped run waited for a slot")
	}
	if flowLaneDropped.Load() != 1 {
		t.Fatalf("slot_drops = %d, want 1", flowLaneDropped.Load())
	}
}

// TestFlowLaneBoundDeadline: a run that misses its deadline does not step the
// state and counts the time cap.
func TestFlowLaneBoundDeadline(t *testing.T) {
	withSecretFlowGeneration(t, "shadow", "shadow")
	resetFlowLaneBoundStats()
	before := flowLaneTimeCap
	flowLaneTimeCap = time.Nanosecond
	defer func() { flowLaneTimeCap = before }()
	ctx := ContextWithSessionID(context.Background(), "bounds-time")
	if got := runSecretFlowShadow(ctx, flowBoundsRequest("cat .env > /tmp/x", false)); got != nil {
		t.Fatalf("findings from a run past its deadline: %v", got)
	}
	stats := flowLaneBoundStats()
	if hits, _ := stats["cap_hits"].(map[string]int64); hits["time"] != 1 {
		t.Fatalf("cap_hits = %v, want one time hit", stats["cap_hits"])
	}
}

// TestFlowLaneBoundOnModeFloors: when the lane is on (a promotion path that
// validation refuses in 1.0.10) a truncated run adds the bound finding, so a
// truncated input is never a silent allow.
func TestFlowLaneBoundOnModeFloors(t *testing.T) {
	withSecretFlowGeneration(t, "on", "on")
	resetFlowLaneBoundStats()
	ctx := ContextWithSessionID(context.Background(), "bounds-on")
	big := "echo " + strings.Repeat("a", flowLaneMaxBytes+16)
	got := runSecretFlowShadow(ctx, flowBoundsRequest(big, false))
	if len(got) != 1 || !strings.Contains(got[0].Title, "bytes") {
		t.Fatalf("on-mode truncated run findings = %+v, want the bound finding naming bytes", got)
	}
}

// TestFlowLaneBoundResultTooBigIsNotIndexed: a tool result past the byte bound
// is not indexed.
func TestFlowLaneBoundResultTooBigIsNotIndexed(t *testing.T) {
	withSecretFlowGeneration(t, "shadow", "shadow")
	resetFlowLaneBoundStats()
	sid := "bounds-result"
	addSecretFlowResultValues(context.Background(), agentHookRequest{
		ConnectorName: "claudecode", HookEventName: "PostToolUse", SessionID: sid, ToolName: "Bash",
		ToolArgs: []byte(`{"command":"cat .env"}`), CWD: "/home/u/p",
		Payload: map[string]interface{}{"tool_response": map[string]interface{}{"stdout": strings.Repeat("KEY=abcdefghijklmnop0123456789\n", secretFlowResultMaxBytes/20)}},
	})
	if st, ok := secretFlowSessions.lookup(sid); ok && st != nil {
		if v := secretFlowSessions.view(sid); v.ValueDigests != 0 {
			t.Fatalf("an oversized result was indexed: %d digests", v.ValueDigests)
		}
	}
}
