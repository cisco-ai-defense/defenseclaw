// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestGAP0574HermesBlockTextStartsWithRuleAndReason(t *testing.T) {
	home, project := hermesPatchHome(t)
	cases := []struct {
		name, path, wantAction string
	}{
		{"protected", filepath.Join(home, ".ssh", "authorized_keys"), "block"},
		{"ordinary", filepath.Join(project, "notes.txt"), "allow"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := hermesPatchBody(t, project, "write_file", map[string]any{"path": tc.path, "content": "# k\n"})
			var answer struct {
				Action     string            `json:"action"`
				Reason     string            `json:"reason"`
				HookOutput map[string]string `json:"hook_output"`
			}
			if err := json.Unmarshal([]byte(hermesPatchHostHook(t, home, project, body)), &answer); err != nil {
				t.Fatal(err)
			}
			if answer.Action != tc.wantAction {
				t.Fatalf("action=%q, want %q", answer.Action, tc.wantAction)
			}
			if tc.wantAction == "allow" {
				if answer.HookOutput["reason"] != "" {
					t.Fatalf("ordinary call has block text: %q", answer.HookOutput["reason"])
				}
				return
			}
			want := "DefenseClaw blocked this call: " + hermesPatchAuthorizedKeysRule + ": "
			if !strings.HasPrefix(answer.HookOutput["reason"], want) ||
				len(strings.TrimPrefix(answer.HookOutput["reason"], want)) == 0 {
				t.Fatalf("hook text=%q, want prefix %q and a reason", answer.HookOutput["reason"], want)
			}
			if answer.Reason == "" || strings.HasPrefix(answer.Reason, "DefenseClaw blocked this call: ") ||
				!strings.Contains(answer.HookOutput["reason"], answer.Reason) {
				t.Fatalf("canonical reason=%q, hook text=%q", answer.Reason, answer.HookOutput["reason"])
			}
		})
	}
}

func TestGAP0574HermesBlockTextVariants(t *testing.T) {
	t.Run("bounded-review", func(t *testing.T) {
		profile := connector.HookProfile{
			Name:         "hermes",
			Capabilities: connector.HookCapability{CanBlock: true, BlockEvents: []string{"pre_tool_call"}},
		}
		req := agentHookRequest{ConnectorName: "hermes", HookEventName: "pre_tool_call", ToolName: "terminal"}
		answer := oversizeUninspectedHookResponse(profile, req, "action", agentHookResponse{Action: "allow", RawAction: "allow"})
		if answer.Action != "block" {
			t.Fatalf("action=%q, want block", answer.Action)
		}
		message, _ := answer.HookOutput["reason"].(string)
		if !strings.HasPrefix(message, "DefenseClaw blocked this call: "+hookOversizeUninspectedRuleID+": ") {
			t.Fatalf("bounded-review block text=%q", message)
		}
		if answer.Reason != oversizeUninspectedReason {
			t.Fatalf("bounded-review canonical reason changed: %q", answer.Reason)
		}
		secure := oversizeUninspectedHookResponse(profile, req, "action", agentHookResponse{Action: "allow", RawAction: "allow"}, true)
		if secure.Reason != oversizeUninspectedReason || secure.HookOutput["reason"] != oversizeUninspectedReason {
			t.Fatalf("Secure Client bounded-review text changed: %q / %v", secure.Reason, secure.HookOutput["reason"])
		}
	})
	t.Run("conflicting-event", func(t *testing.T) {
		api := &APIServer{}
		body := `{"hook_event_name":"post_tool_call","event":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"echo hello"}}`
		request := httptest.NewRequest(http.MethodPost, "/api/v1/hermes/hook", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		out := httptest.NewRecorder()
		api.handleAgentHook("hermes")(out, request)
		var answer struct {
			Action     string            `json:"action"`
			HookOutput map[string]string `json:"hook_output"`
		}
		if err := json.Unmarshal(out.Body.Bytes(), &answer); err != nil {
			t.Fatal(err)
		}
		if answer.Action != "block" {
			t.Fatalf("action=%q, want block", answer.Action)
		}
		if !strings.HasPrefix(answer.HookOutput["message"], "DefenseClaw blocked this call: ") {
			t.Fatalf("event-conflict block text=%q", answer.HookOutput["message"])
		}
	})
}
