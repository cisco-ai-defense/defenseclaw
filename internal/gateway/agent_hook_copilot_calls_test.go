// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// copilotParallelCorpusInput is the hook input of one corpus row.
func copilotParallelCorpusInput(t *testing.T, id string) map[string]any {
	t.Helper()
	f, err := os.Open("testdata/copilot-native-benign.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		var item struct {
			ID    string         `json:"id"`
			Input map[string]any `json:"input"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &item); err != nil {
			t.Fatal(err)
		}
		if item.ID == id {
			return item.Input
		}
	}
	t.Fatalf("corpus row %s not found", id)
	return nil
}

// copilotParallelOnHost moves a captured Windows envelope into project on
// this host: every path argument keeps its place under the session cwd.
func copilotParallelOnHost(t *testing.T, input map[string]any, project string) map[string]any {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		out["cwd"] = project
	}
	cwd, _ := out["cwd"].(string)
	move := func(value any) any {
		text, ok := value.(string)
		if !ok || !strings.HasPrefix(strings.ToLower(text), strings.ToLower(cwd)) {
			return value
		}
		rel := strings.TrimLeft(strings.ReplaceAll(text[len(cwd):], `\`, "/"), "/")
		return filepath.Join(project, filepath.FromSlash(rel))
	}
	for _, entry := range out["toolCalls"].([]any) {
		args, ok := entry.(map[string]any)["args"].(map[string]any)
		if !ok {
			continue
		}
		for _, key := range []string{"path", "paths"} {
			if value, present := args[key]; present {
				args[key] = move(value)
			}
		}
	}
	out["cwd"] = project
	return out
}

func postCopilotParallel(t *testing.T, mode string, input map[string]any) (string, string) {
	t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Guardrail.Mode = mode
	cfg.Guardrail.Connector = "copilot"
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
	// The header the registered hook sends for this envelope.
	if header := hookpaths.ResolveConnector("copilot", "", "preToolUse", body); header != "" {
		req.Header.Set(hookpaths.Header, header)
	}
	w := httptest.NewRecorder()
	api.handleAgentHook("copilot").ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d: %s", w.Code, w.Body.String())
	}
	var verdict struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &verdict); err != nil {
		t.Fatalf("not a verdict: %v: %s", err, w.Body.String())
	}
	return verdict.Action, w.Body.String()
}

// GAP-1016: a model's parallel tool calls reach the native Copilot CLI
// preToolUse as one toolCalls envelope of several calls. Ordinary project
// file creation and reads (real Copilot CLI hook inputs) are allowed in
// observe and action and are never HOOK-TOOL-CALL-UNPARSED.
func TestCopilotParallelToolCallsAreJudgedNotUnparsed(t *testing.T) {
	for _, id := range []string{
		"windows-native-parallel-create",
		"windows-native-parallel-create-seven",
		"windows-native-parallel-read-tools",
	} {
		for _, mode := range []string{"observe", "action"} {
			t.Run(id+"/"+mode, func(t *testing.T) {
				input := copilotParallelOnHost(t, copilotParallelCorpusInput(t, id), t.TempDir())
				action, response := postCopilotParallel(t, mode, input)
				if action != "allow" || strings.Contains(response, hookToolCallUnparsedRuleID) {
					t.Fatalf("benign parallel calls: action=%s: %s", action, response)
				}
			})
		}
	}
}

// One answer covers every call: a protected write among ordinary parallel
// creations gets the block it gets alone, wherever it sits in the envelope.
func TestCopilotParallelToolCallsTakeTheMostRestrictiveVerdict(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(home, ".ssh", "authorized_keys")
	input := copilotParallelOnHost(t, copilotParallelCorpusInput(t, "windows-native-parallel-create"), t.TempDir())
	calls := input["toolCalls"].([]any)
	decoy := map[string]any{"id": "call_protected", "name": "create",
		"args": map[string]any{"path": protected, "file_text": "ssh-ed25519 AAAA decoy\n"}}
	for _, at := range []int{0, len(calls)} {
		withDecoy := append(append(append([]any(nil), calls[:at]...), decoy), calls[at:]...)
		input["toolCalls"] = withDecoy
		action, response := postCopilotParallel(t, "action", input)
		alone := map[string]any{"sessionId": input["sessionId"], "cwd": input["cwd"], "toolCalls": []any{decoy}}
		want, aloneResponse := postCopilotParallel(t, "action", alone)
		if want != "block" {
			t.Fatalf("control: the protected create alone was not blocked: %s", aloneResponse)
		}
		if action != want || strings.Contains(response, hookToolCallUnparsedRuleID) {
			t.Fatalf("decoy at %d: action=%s, want %s: %s", at, action, want, response)
		}
	}
}
