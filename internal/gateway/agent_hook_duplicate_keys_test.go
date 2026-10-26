// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Duplicate keys, missing write targets, and unknown write aliases leave a
// Copilot tool call's target set unproven. Refuse the call before it can be
// judged as an empty or ordinary project write.
func TestAgentHookRefusesUnprovenCopilotWriteCalls(t *testing.T) {
	for _, row := range []struct {
		name, body string
		block      bool
	}{
		{"ordinary write", `{"sessionId":"s","timestamp":1790483549431,"toolName":"create_file","toolArgs":{"filePath":"notes.txt","content":"ok"}}`, false},
		{"duplicate tool name", `{"sessionId":"s","timestamp":1790483549431,"toolName":"view","toolName":"create_file","toolArgs":{"filePath":"notes.txt","content":"ok"}}`, true},
		{"duplicate argument object", `{"sessionId":"s","timestamp":1790483549431,"toolName":"create_file","toolArgs":{"filePath":"notes.txt","content":"ok"},"toolArgs":{"filePath":"notes.txt","content":"ok"}}`, true},
		{"duplicate nested target", `{"sessionId":"s","timestamp":1790483549431,"toolName":"create_file","toolArgs":{"filePath":"other.txt","filePath":"notes.txt","content":"ok"}}`, true},
		{"duplicate JSON string target", `{"sessionId":"s","timestamp":1790483549431,"toolName":"create_file","toolArgs":"{\"filePath\":\"other.txt\",\"filePath\":\"notes.txt\",\"content\":\"ok\"}"}`, true},
		{"missing write args", `{"sessionId":"s","timestamp":1790483549431,"toolName":"create_file"}`, true},
		{"array write args", `{"sessionId":"s","timestamp":1790483549431,"toolName":"create_file","toolArgs":[]}`, true},
		{"missing target", `{"sessionId":"s","timestamp":1790483549431,"toolName":"create_file","toolArgs":{"content":"ok"}}`, true},
		{"malformed patch", `{"sessionId":"s","timestamp":1790483549431,"toolName":"apply_patch","toolArgs":"not a patch"}`, true},
		{"unknown write alias", `{"sessionId":"s","timestamp":1790483549431,"toolName":"createFile","toolArgs":{"filePath":"notes.txt","content":"ok"}}`, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "copilot"
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(row.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
			recorder := httptest.NewRecorder()
			api.handleAgentHook("copilot").ServeHTTP(recorder, req)
			var verdict struct {
				Action   string   `json:"action"`
				Findings []string `json:"findings"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &verdict); err != nil {
				t.Fatalf("response is not a verdict: %v", err)
			}
			want := "allow"
			if row.block {
				want = "block"
			}
			if verdict.Action != want {
				t.Fatalf("action = %q, want %q; findings = %v", verdict.Action, want, verdict.Findings)
			}
			if row.block && !strings.Contains(recorder.Body.String(), "HOOK-TOOL-CALL-UNPARSED") {
				t.Fatalf("ambiguous call did not name its reason: %v", verdict.Findings)
			}
		})
	}
}

// postHookDecision posts body to connectorName's hook in action mode and
// returns its decision ("allow" or "block") and the response body. surface
// is "" for the Copilot CLI or the VS Code Local surface name.
func postHookDecision(t *testing.T, connectorName, surface, body string) (string, string) {
	t.Helper()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connectorName
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+connectorName+"/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if connectorName == "copilot" {
		req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
		if surface != "" {
			req.Header.Set("X-DefenseClaw-Copilot-Event", "PreToolUse")
			req.Header.Set(connector.HookDialectHeader, surface)
		}
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connectorName).ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var verdict struct {
		Action     string `json:"action"`
		HookOutput struct {
			Specific struct {
				Decision string `json:"permissionDecision"`
			} `json:"hookSpecificOutput"`
		} `json:"hook_output"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &verdict); err != nil {
		t.Fatalf("response is not a verdict: %v: %s", err, recorder.Body.String())
	}
	action := verdict.Action
	if verdict.HookOutput.Specific.Decision == "deny" {
		action = "block"
	}
	if action == "" {
		action = "allow"
	}
	return action, recorder.Body.String()
}

// The whole class of a call DefenseClaw cannot read as one: a key repeated
// at any depth of the body or of an object-encoded Copilot toolArgs string
// (a map decoder keeps one value silently), trailing data after the body,
// and, for a Copilot write, arguments that do not name every target the
// tool writes (missing, not an object, an unknown argument, a target of
// the wrong type, a patch with no file, a write tool spelled another way).
// Each is refused with HOOK-TOOL-CALL-UNPARSED; the same calls written
// plainly, on both Copilot surfaces, still run, and so does a Claude Code
// write.
func TestAgentHookRefusesEveryUnreadCall(t *testing.T) {
	// A Copilot CLI call names an existing cwd absolute on its host; a patch
	// target is placed under it, and on Windows "/tmp" is not absolute.
	cli := `{"sessionId":"s","timestamp":1790483549431,"cwd":"/tmp",`
	if runtime.GOOS == "windows" {
		cli = `{"sessionId":"s","timestamp":1790483549431,"cwd":"` + filepath.ToSlash(t.TempDir()) + `",`
	}
	const local = `{"timestamp":"2026-09-30T00:00:00Z","hook_event_name":"PreToolUse","session_id":"s1","tool_use_id":"t1","cwd":"/tmp",`
	const claude = `{"session_id":"s","hook_event_name":"PreToolUse","cwd":"/tmp",`
	large := strings.Repeat("a", 300<<10)
	for _, row := range []struct {
		name, connector, surface, body string
		block                          bool
	}{
		// Plain calls run.
		{"cli create", "copilot", "", cli + `"toolName":"create","toolArgs":{"path":"notes.txt","file_text":"ok"}}`, false},
		{"cli create as a JSON string", "copilot", "", cli + `"toolName":"create","toolArgs":"{\"path\":\"notes.txt\",\"file_text\":\"ok\"}"}`, false},
		{"cli edit with a description", "copilot", "", cli + `"toolName":"edit","toolArgs":{"path":"notes.txt","old_str":"a","new_str":"b","description":"fix"}}`, false},
		{"cli apply_patch", "copilot", "", cli + `"toolName":"apply_patch","toolArgs":"*** Begin Patch\n*** Add File: notes.txt\n+ok\n*** End Patch\n"}`, false},
		{"cli over-limit create", "copilot", "", cli + `"toolName":"create","toolArgs":{"path":"notes.txt","file_text":"` + large + `"}}`, false},
		{"cli view", "copilot", "", cli + `"toolName":"view","toolArgs":{"path":"notes.txt"}}`, false},
		{"local create_file", "copilot", connector.CopilotHookSurfaceVSCodeLocal, local + `"tool_name":"create_file","tool_input":{"filePath":"/tmp/notes.txt","content":"ok"}}`, false},
		{"claude code write", "claudecode", "", claude + `"tool_name":"Write","tool_input":{"file_path":"/tmp/notes.txt","content":"ok"}}`, false},
		// Repeated keys, at any depth. (Claude Code and Codex bodies are
		// judged by their own decoders, not this path.)
		{"cli repeated top-level key", "copilot", "", cli + `"cwd":"/tmp","toolName":"create","toolArgs":{"path":"notes.txt","file_text":"ok"}}`, true},
		{"cli repeated key in a JSON string", "copilot", "", cli + `"toolName":"create","toolArgs":"{\"path\":\"notes.txt\",\"path\":\"other.txt\",\"file_text\":\"ok\"}"}`, true},
		{"cli repeated nested key in a JSON string", "copilot", "", cli + `"toolName":"view","toolArgs":"{\"path\":\"notes.txt\",\"x\":{\"a\":1,\"a\":2}}"}`, true},
		{"cli repeated key in an array in a JSON string", "copilot", "", cli + `"toolName":"create","toolArgs":"[{\"path\":\"a\",\"path\":\"b\"}]"}`, true},
		{"cli repeated key under a non-write tool", "copilot", "", cli + `"toolName":"bash","toolArgs":{"command":"echo ok","command":"echo ok"}}`, true},
		{"local repeated target", "copilot", connector.CopilotHookSurfaceVSCodeLocal, local + `"tool_name":"create_file","tool_input":{"filePath":"/tmp/notes.txt","filePath":"/tmp/other.txt","content":"ok"}}`, true},
		{"local repeated tool name", "copilot", connector.CopilotHookSurfaceVSCodeLocal, local + `"tool_name":"read_file","tool_name":"create_file","tool_input":{"filePath":"/tmp/notes.txt","content":"ok"}}`, true},
		{"trailing data after the body", "copilot", "", cli + `"toolName":"create","toolArgs":{"path":"notes.txt","file_text":"ok"}} {"toolName":"view"}`, true},
		// Copilot writes whose targets are not all named.
		{"cli null args", "copilot", "", cli + `"toolName":"create","toolArgs":null}`, true},
		{"cli number args", "copilot", "", cli + `"toolName":"create","toolArgs":7}`, true},
		{"cli invalid JSON string args", "copilot", "", cli + `"toolName":"create","toolArgs":"{\"path\":"}`, true},
		{"cli create without a path", "copilot", "", cli + `"toolName":"create","toolArgs":{"file_text":"ok"}}`, true},
		{"cli create with an unknown argument", "copilot", "", cli + `"toolName":"create","toolArgs":{"path":"notes.txt","file_text":"ok","target":"other.txt"}}`, true},
		{"cli create with a numeric path", "copilot", "", cli + `"toolName":"create","toolArgs":{"path":7,"file_text":"ok"}}`, true},
		{"cli edit with an empty path", "copilot", "", cli + `"toolName":"edit","toolArgs":{"path":"","old_str":"a","new_str":"b"}}`, true},
		{"cli patch with no file", "copilot", "", cli + `"toolName":"apply_patch","toolArgs":"*** Begin Patch\n*** End Patch\n"}`, true},
		{"cli patch object without a patch", "copilot", "", cli + `"toolName":"apply_patch","toolArgs":{"input":"x"}}`, true},
		{"cli write tool spelled another way", "copilot", "", cli + `"toolName":"Create_File","toolArgs":{"filePath":"notes.txt","content":"ok"}}`, true},
		{"local create_file without a target", "copilot", connector.CopilotHookSurfaceVSCodeLocal, local + `"tool_name":"create_file","tool_input":{"content":"ok"}}`, true},
		{"local create_file with a numeric target", "copilot", connector.CopilotHookSurfaceVSCodeLocal, local + `"tool_name":"create_file","tool_input":{"filePath":7,"content":"ok"}}`, true},
		{"local create_file with an unknown argument", "copilot", connector.CopilotHookSurfaceVSCodeLocal, local + `"tool_name":"create_file","tool_input":{"filePath":"/tmp/notes.txt","content":"ok","path":"/tmp/other.txt"}}`, true},
		{"local replace_string_in_file without args", "copilot", connector.CopilotHookSurfaceVSCodeLocal, local + `"tool_name":"replace_string_in_file"}`, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			action, body := postHookDecision(t, row.connector, row.surface, row.body)
			want := "allow"
			if row.block {
				want = "block"
			}
			if action != want {
				t.Fatalf("decision = %q, want %q: %s", action, want, body)
			}
			if row.block && !strings.Contains(body, "HOOK-TOOL-CALL-UNPARSED") && !strings.Contains(body, "could not read the tool call") {
				t.Fatalf("an unread call did not name its reason: %s", body)
			}
		})
	}
}
