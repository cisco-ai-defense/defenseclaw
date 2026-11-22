// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/local"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// The SIEM note of the ACTION-OPERAND-BOUND retirement, end to end on the
// JSONL sink: a hook call past the operand bound reaches the sink with the
// rule id ACTION-COMPOUND-LIMIT and "bounded_truncated cap=items" in the
// finding title, as a CRITICAL finding whose answer is an alert in the
// default pack, and the retired id appears nowhere (rel-1-0-10:GAP-0313,
// review P3-3).
func TestBoundedReasonReachesTheJSONLSinkInTheTitle(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("POSIX home fixture requires an unprivileged Unix user")
	}
	sinkPath := filepath.Join(t.TempDir(), "sink", "audit.jsonl")
	sink, err := local.NewJSONL(local.DefaultJSONLConfig(sinkPath))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close(context.Background()) })
	fixture := newSidecarRuntimeFixtureExportingTo(t, nil, sink)
	fingerprints, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	logger := audit.NewLogger(fixture.store)
	logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime, redactionEngine: fingerprints})
	installToolCallCorpusProfileConnector(t, "claudecode", "default")
	_, cwd := shellProtectedFileHome(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
	api := &APIServer{store: fixture.store, logger: logger, scannerCfg: cfg, health: NewSidecarHealth()}
	body, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse", "session_id": "bounded-sink", "tool_name": "Bash", "cwd": cwd,
		"tool_input": map[string]any{"command": "echo " + operandWords(1500)},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handleAgentHook("claudecode").ServeHTTP(w, req)
	var answer struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil || answer.Action != guardrailActionAlert {
		t.Fatalf("answer=%.300s err=%v, want alert", w.Body.String(), err)
	}
	title := boundedTruncatedTitle + " (" + bounded.Of(bounded.Items).Reason() + ")"
	var line string
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline) && line == ""; time.Sleep(100 * time.Millisecond) {
		line = boundedSinkLine(t, sinkPath, evaluationLimitRuleID)
	}
	if line == "" {
		t.Fatalf("no %s record reached the JSONL sink", evaluationLimitRuleID)
	}
	var record struct {
		Body       map[string]any    `json:"body"`
		FieldClass map[string]string `json:"field_classes"`
	}
	if err := json.Unmarshal([]byte(line), &record); err != nil {
		t.Fatalf("sink record: %v: %.500s", err, line)
	}
	if got := record.Body["defenseclaw.finding.title"]; got != title {
		t.Errorf("finding title %q, want %q", got, title)
	}
	if got := record.Body["defenseclaw.finding.rule_id"]; got != evaluationLimitRuleID {
		t.Errorf("rule id %q", got)
	}
	if got := record.Body["defenseclaw.security.severity"]; got != "CRITICAL" {
		t.Errorf("severity %q, want CRITICAL (the 1.0.9 alert was MEDIUM)", got)
	}
	// What the SIEM note says about redaction: the rule id is an identifier
	// (kept by every profile), the title and the evidence summary are
	// evidence (removed or replaced whole by the content and strict
	// profiles).
	if record.FieldClass["/defenseclaw.finding.rule_id"] != "identifier" ||
		record.FieldClass["/defenseclaw.finding.title"] != "evidence" {
		t.Errorf("field classes changed, update the SIEM note: %v", record.FieldClass)
	}
	if all, _ := os.ReadFile(sinkPath); bytes.Contains(all, []byte("ACTION-OPERAND-BOUND")) {
		t.Error("the retired id ACTION-OPERAND-BOUND reached the sink")
	}
}

// boundedSinkLine is the first sink record that names ruleID.
func boundedSinkLine(t *testing.T, path, ruleID string) string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 1<<16), 1<<24)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), ruleID) {
			return scanner.Text()
		}
	}
	return ""
}
