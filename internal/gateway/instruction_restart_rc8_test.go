// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Records written by 1.0.0-1.0.3 may contain a session-wide uncertainty
// bit. Keep their proved files, but do not resurrect that broad fallback.
func TestInstructionLoadsLegacyRecordDoesNotRestoreUncertainty(t *testing.T) {
	api := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
	api.scannerCfg.DataDir = t.TempDir()
	loaded := writeActiveAgentTestFile(t, t.TempDir(), "SOUL.md")
	dir := api.instructionLoadDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		session string
		files   []string
	}{
		{"legacy-with-file", []string{loaded}},
		{"legacy-uncertainty-only", nil},
	} {
		key, ok := validActiveAgentContextKey("claudecode", tc.session)
		if !ok {
			t.Fatal("invalid test session")
		}
		data, err := json.Marshal(map[string]interface{}{
			"connector": "claudecode", "session": tc.session, "files": tc.files,
			"uncertain": true, "case_insensitive_uncertain": true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(instructionLoadRecordPath(dir, key), data, 0o600); err != nil {
			t.Fatal(err)
		}
		api.restoreInstructionLoads(key)
		if snapshot := api.activeAgentContext.snapshot("claudecode", tc.session); snapshot.uncertain ||
			len(snapshot.files) != len(tc.files) {
			t.Fatalf("legacy record restored broad uncertainty or lost proof: %+v", snapshot)
		}
	}
}

// A restart retains exact loaded paths and identities, but an unprovable
// load in the same session must not turn an unrelated matching basename into
// a protected file.
func TestInstructionLoadsRestartDoesNotRestoreGlobalUncertainty(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	loaded := writeActiveAgentTestFile(t, filepath.Join(root, "persona"), "SOUL.md")
	ordinary := writeActiveAgentTestFile(t, filepath.Join(root, "ordinary"), "MEMORY.md")
	unknown := filepath.Join(root, "unreadable", "MEMORY.md")
	dataDir := t.TempDir()
	newGateway := func() *APIServer {
		api := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
		api.scannerCfg.DataDir = dataDir
		return api
	}
	before := newGateway()
	ctx := authenticatedClaudeCodeTestContext()
	for _, file := range []string{loaded, unknown} {
		before.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
			HookEventName: "InstructionsLoaded", SessionID: "running", CWD: project, FilePath: file,
		})
	}
	if !before.activeAgentContext.snapshot("claudecode", "running").uncertain {
		t.Fatal("the unprovable load did not mark the live session uncertain")
	}
	after := newGateway()
	write := func(file string) (string, []string) {
		response := after.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", SessionID: "running", CWD: project,
			ToolName: "Write", ToolInput: map[string]interface{}{"file_path": file, "content": "changed"},
		})
		return response.Action, response.Findings
	}
	if action, findings := write(ordinary); action == guardrailActionBlock {
		t.Fatalf("unrelated MEMORY.md blocked after restart: findings=%v", findings)
	}
	if action, findings := write(loaded); action != guardrailActionBlock || !findingStringHasRuleID(findings, "COG-SOUL") {
		t.Fatalf("proved loaded file lost protection after restart: action=%q findings=%v", action, findings)
	}
}
