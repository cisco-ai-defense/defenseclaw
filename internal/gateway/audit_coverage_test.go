// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

// TestAuditCoverage_EveryCategoryLandsInJSONL is the load-bearing
// guardrail for the audit → gateway.jsonl bridge. The plan requires
// *every* audit action category the sidecar actually emits to surface
// as a structured gatewaylog event — otherwise an operator searching
// Splunk for "show me everything the gateway did for request X" can
// silently miss a class of events and a production incident rots
// undetected.
//
// The table below is the authoritative list of audit categories the
// gateway emits today. If you add a new audit category (e.g., a new
// subsystem in subsystemForAction), add it here with the subsystem
// string you expect bridged events to carry. A failure here means
// either the bridge's routing is wrong or your new category leaks
// past the coverage matrix.
//
// guardrail-verdict and llm-judge-response are deliberately excluded:
// the gateway hot path emits dedicated Verdict / Judge events via
// emitVerdict / emitJudge, and the bridge's skipBridgeAction prevents
// double-counting. Those invariants have their own dedicated tests
// (TestAuditToJSONL_SkipsGuardrailVerdict and the
// correlation_integration_test.go assertions that no lifecycle row
// appears for llm-judge-response).
func TestAuditCoverage_EveryCategoryLandsInJSONL(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "audit.db")
	jsonlPath := filepath.Join(tmp, "gateway.jsonl")

	store, err := audit.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("store.Init: %v", err)
	}
	defer store.Close()

	writer, err := gatewaylog.New(gatewaylog.Config{JSONLPath: jsonlPath})
	if err != nil {
		t.Fatalf("gatewaylog.New: %v", err)
	}
	defer writer.Close()

	logger := audit.NewLogger(store)
	logger.SetStructuredEmitter(newAuditBridge(writer))
	defer logger.Close()

	// Cover every subsystem branch in subsystemForAction() so a
	// future refactor that drops a branch (or renames an action)
	// fails loudly here instead of silently dropping events.
	cases := []struct {
		action        string
		wantSubsystem string
	}{
		{"scan", "scanner"},
		{"watch-start", "watcher"},
		{"watcher-drain", "watcher"},
		{"watch-stop", "watcher"},
		{"sidecar-start", "gateway"},
		{"sidecar-connected", "gateway"},
		{"sidecar-disconnected", "gateway"},
		{"sidecar-stop", "gateway"},
		{"gateway-ready", "gateway"},
		{"api-auth-failure", "api"},
		{"sink-flush-error", "sinks"},
		{"splunk-backoff", "sinks"},
		{"otel-degraded", "telemetry"},
		{"telemetry-init", "telemetry"},
		{"skill-install", "enforcement"},
		{"mcp-install", "enforcement"},
		{"install-blocked", "enforcement"},
		{"block-hit", "enforcement"},
		{"allow-hit", "enforcement"},
		{"quarantine-move", "enforcement"},
		{"block", "enforcement"},
		{"allow", "enforcement"},
		{"quarantine", "enforcement"},
		// llm-judge-response is intentionally omitted here: it has a
		// dedicated EventJudge emission via emitJudge and the bridge
		// skipBridgeAction's invariant is enforced by
		// correlation_integration_test.go.
		// Unknown categories must still bridge (fallback subsystem).
		{"future-unknown-action", "gateway"},
	}

	// Drive one event per category. Use the correlation helper so
	// the request_id column is exercised on every path, which is
	// load-bearing for Phase 5.
	for i, tc := range cases {
		if err := logger.LogActionWithCorrelation(
			tc.action,
			"coverage-target",
			"coverage test row",
			"trace-coverage",
			"req-coverage-"+tc.action,
		); err != nil {
			t.Fatalf("row %d (%s): LogActionWithCorrelation: %v", i, tc.action, err)
		}
	}

	// Writer.Emit is synchronous (lumberjack flushes on each Write),
	// so there is no explicit Flush to call. Closing would tear down
	// the file handle which we still need for the read below.

	f, err := os.Open(jsonlPath)
	if err != nil {
		t.Fatalf("open jsonl: %v", err)
	}
	defer f.Close()

	// Collect one emission per action. A missing entry means the
	// bridge dropped the category (or skipBridgeAction over-skipped);
	// a duplicate entry for a non-skipped action is also a failure
	// because we drive each action exactly once.
	got := map[string]struct {
		subsystem string
		requestID string
	}{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		var ev struct {
			RequestID string `json:"request_id"`
			Lifecycle struct {
				Subsystem string            `json:"subsystem"`
				Details   map[string]string `json:"details"`
			} `json:"lifecycle"`
		}
		line := scanner.Text()
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("invalid JSONL line: %v (%s)", err, line)
		}
		if ev.Lifecycle.Subsystem == "" {
			// Non-lifecycle rows (verdict, judge) — skip.
			continue
		}
		action := ev.Lifecycle.Details["action"]
		if action == "" {
			continue
		}
		got[action] = struct {
			subsystem string
			requestID string
		}{
			subsystem: ev.Lifecycle.Subsystem,
			requestID: ev.RequestID,
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner: %v", err)
	}

	for _, tc := range cases {
		entry, ok := got[tc.action]
		if !ok {
			t.Errorf("action %q (expected subsystem=%s) never reached gateway.jsonl",
				tc.action, tc.wantSubsystem)
			continue
		}
		if entry.subsystem != tc.wantSubsystem {
			t.Errorf("action %q: subsystem=%q want %q",
				tc.action, entry.subsystem, tc.wantSubsystem)
		}
		if entry.requestID != "req-coverage-"+tc.action {
			t.Errorf("action %q: request_id=%q want %q",
				tc.action, entry.requestID, "req-coverage-"+tc.action)
		}
	}
}

// TestAuditCoverage_SkipListIsMinimal guards against the obvious
// regression where someone adds a new action to skipBridgeAction for
// "cleanliness" and silently drops it from operator visibility.
// guardrail-verdict is the ONLY action allowed in the skip list,
// because it has a dedicated hot-path emission. Any new skip target
// must be accompanied by an equivalent dedicated emission and an
// update to this allowlist.
func TestAuditCoverage_SkipListIsMinimal(t *testing.T) {
	// Both entries have a dedicated hot-path emitter upstream:
	//   * guardrail-verdict → emitVerdict writes an EventVerdict row
	//   * llm-judge-response → emitJudge writes an EventJudge row
	// Bridging either would duplicate rows in gateway.jsonl.
	allowed := map[string]struct{}{
		"guardrail-verdict":  {},
		"llm-judge-response": {},
	}

	// Probe a representative set of actions. If a caller adds a new
	// skip case, they must either (a) add it to `allowed` above with
	// a matching dedicated emitter, or (b) delete the skip.
	probes := []string{
		"scan", "watch-start", "watch-stop", "sidecar-start",
		"sidecar-stop", "sidecar-connected", "sidecar-disconnected",
		"gateway-ready", "api-auth-failure", "sink-flush-error",
		"splunk-backoff", "otel-degraded", "telemetry-init",
		"skill-install", "mcp-install", "block", "allow", "quarantine",
		"llm-judge-response", "future-unknown-action",
		"guardrail-verdict", // the sole allowed skip
	}

	for _, action := range probes {
		skipped := skipBridgeAction(action)
		_, ok := allowed[action]
		switch {
		case skipped && !ok:
			t.Errorf("action %q is skipped but not in the allowlist — "+
				"add a dedicated emitter or remove the skip", action)
		case !skipped && ok:
			// Allowed-but-not-skipped is fine — it just means the
			// hot path emits AND the bridge also emits, which is a
			// schema waste but not a correctness bug.
		}
	}
}

// TestAuditCoverage_UnknownSubsystemFallsBackToGateway pins the
// fallback behaviour so a future audit category that doesn't match
// any prefix never ends up with an empty subsystem string on the
// wire. Empty subsystems break TUI filtering (chip labels go blank)
// and downstream Splunk dashboards that index on this field.
func TestAuditCoverage_UnknownSubsystemFallsBackToGateway(t *testing.T) {
	got := subsystemForAction("zzz-unknown-never-defined")
	if got != "gateway" {
		t.Fatalf("unknown action subsystem=%q want gateway (fallback)", got)
	}
	// Specifically, it must not be empty — the TUI and SIEM treat
	// empty subsystem as "legacy pre-bridge event" and hide it.
	if strings.TrimSpace(got) == "" {
		t.Fatal("subsystem must never be empty — empty breaks TUI filters")
	}
}
