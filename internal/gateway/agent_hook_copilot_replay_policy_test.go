// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1050 and GAP-1510: the same Copilot tool call (same toolUseId) sent
// again within the replay window after the policy changed is decided under
// the new policy: a live tool block or an observe-to-action switch is not
// answered with the earlier allow.
func TestCopilotReplayAfterPolicyChangeIsDecidedAgain(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command string
		change  func(*config.Config)
	}{
		{"tool block", "printf r27", func(cfg *config.Config) {
			cfg.AssetPolicy.Tool.Denied = append(cfg.AssetPolicy.Tool.Denied,
				config.AssetPolicyToolRule{Name: "bash", Connector: "copilot"})
		}},
		{"observe to action", "printf marker >> ~/.ssh/authorized_keys", func(cfg *config.Config) {
			cfg.Guardrail.Mode = "action"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := &config.Config{}
			before.Guardrail.Mode = "observe"
			before.Guardrail.Connector = "copilot"
			after := *before
			tc.change(&after)
			var live atomic.Pointer[Generation]
			live.Store(&Generation{N: 6, Digest: "sha256:before", Config: before})
			api := &APIServer{scannerCfg: before, health: NewSidecarHealth()}
			api.SetGenerationSource(func() *Generation { return live.Load() })
			args, _ := json.Marshal(map[string]string{"command": tc.command})
			body, _ := json.Marshal(map[string]any{"sessionId": "r27-session", "cwd": t.TempDir(),
				"toolUseId": "r27-call-a", "toolName": "bash", "toolArgs": string(args)})
			post := func() (string, string, string) {
				req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(string(body)))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
				w := httptest.NewRecorder()
				api.handleAgentHook("copilot").ServeHTTP(w, req)
				var verdict struct {
					Action    string `json:"action"`
					RawAction string `json:"raw_action"`
				}
				_ = json.Unmarshal(w.Body.Bytes(), &verdict)
				return verdict.Action, verdict.RawAction, w.Body.String()
			}
			if action, raw, response := post(); action != "allow" || raw == "block" && tc.name == "tool block" {
				t.Fatalf("control under the first policy: %s", response)
			}
			live.Store(&Generation{N: 7, Digest: "sha256:after", Config: &after})
			// The new policy decides: the block list blocks (an observe
			// install reports it as would-block), action mode blocks.
			action, raw, response := post()
			if raw != "block" || after.Guardrail.Mode == "action" && action != "block" {
				t.Fatalf("replay after the policy change kept the earlier verdict: %s", response)
			}
		})
	}
}
