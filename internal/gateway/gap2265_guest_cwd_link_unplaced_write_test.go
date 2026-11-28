// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// TestGAP2265GuestCWDLinkUnplacedWriteKeepsLinuxAnswer: a copy-mode actor
// that changes folder to its bare own cwd link and then writes a name a
// runtime-expanded word chooses gets the answer a Linux gateway gives, with
// the keys-persistence rule, on every gateway OS. The placement of the cwd
// link (rel-1-0-10:GAP-2265) only adds a proof: a write it does not prove
// protected keeps the reading of the link as written (parity with
// rel/1.0.11; the macOS gateway had dropped the rule).
func TestGAP2265GuestCWDLinkUnplacedWriteKeepsLinuxAnswer(t *testing.T) {
	link := "/" + strings.Join([]string{"proc", "self", "cwd"}, "/")
	runtimeWrite := "eval " + "'" + "x=f; " + "echo m > " + "$" + "x" + "'"
	command := "cd " + link + " && " + runtimeWrite
	const rule = "persistence.ssh_authorized_keys_command"
	for _, pack := range []string{"default", "strict"} {
		t.Run(pack, func(t *testing.T) {
			api, actor, _, _ := gap0545API(t, "claudecode", pack)
			body, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "gap2265u",
				"cwd": sandboxauth.SandboxHome + "/app", "tool_name": "Bash", "tool_input": map[string]any{"command": command},
				"tool_use_id": t.Name()})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			api.handleAgentHook("claudecode").ServeHTTP(rec, req.WithContext(gap0545Actor(actor, "claudecode", "PreToolUse", body, nil)))
			var out struct {
				Action string   `json:"action"`
				Rules  []string `json:"rule_ids"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			if out.Action == "allow" || !slices.Contains(out.Rules, rule) {
				t.Errorf("copy-mode actor %s %v, want the Linux answer with %s", out.Action, out.Rules, rule)
			}
			if pack == "strict" && out.Action != "block" {
				t.Errorf("strict copy-mode actor %s %v, want block", out.Action, out.Rules)
			}
		})
	}
}
