// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The overlay models a share whose identity reads do not answer within the
// hook budget. The ordinary spelling uses the balanced verdict; strict keeps
// the unknown identity closed. An explicit protected name is closed in both.
func TestGAP0482UnansweredShareVerdicts(t *testing.T) {
	if os.Getenv("R482_OVERLAY") != "1" {
		t.Skip("requires the slow-share test overlay")
	}
	for _, row := range []struct {
		name, command string
		alias         bool
		wants         map[string]string
	}{
		{"ordinary", "echo marker >> ordinary.txt", false, map[string]string{"default": "allow", "strict": "block"}},
		{"protected-name", "echo marker >> ~/.ssh/authorized_keys", false, map[string]string{"default": "block", "strict": "block"}},
		{"protected-alias-strict", "echo marker >> ordinary.txt", true, map[string]string{"strict": "block"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			for _, profile := range []string{"default", "strict"} {
				want, present := row.wants[profile]
				if !present {
					continue
				}
				for _, mode := range []string{"root-pending", "file-pending"} {
					t.Run(profile+"/"+mode, func(t *testing.T) {
						root := t.TempDir()
						home := filepath.Join(root, "home")
						project := filepath.Join(root, "project")
						for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
							if err := os.MkdirAll(dir, 0o700); err != nil {
								t.Fatal(err)
							}
						}
						keys := filepath.Join(home, ".ssh", "authorized_keys")
						if err := os.WriteFile(keys, []byte("placeholder\n"), 0o600); err != nil {
							t.Fatal(err)
						}
						target := filepath.Join(project, "ordinary.txt")
						if row.alias {
							if err := os.Link(keys, target); err != nil {
								t.Skipf("hard links unavailable: %v", err)
							}
						} else if err := os.WriteFile(target, []byte("notes\n"), 0o600); err != nil {
							t.Fatal(err)
						}
						t.Setenv("R482_FAKE_SHARE", root)
						t.Setenv("R482_FAKE_SHARE_UNANSWERED", "1")
						if mode == "file-pending" {
							t.Setenv("R482_FAKE_SHARE_ROOT_FAST", "1")
						}
						t.Setenv("HOME", home)
						t.Setenv("USERPROFILE", home)
						payload := mustJSON(t, map[string]any{
							"session_id": "gap0482-share", "hook_event_name": "PreToolUse",
							"tool_name": "Bash", "tool_use_id": "toolu_gap0482_share",
							"cwd": project, "permission_mode": "default",
							"tool_input": map[string]any{"command": row.command},
						})
						start := time.Now()
						got := gap0482ProfileVerdict(t, payload, profile)
						if took := time.Since(start); took > time.Second {
							t.Errorf("share verdict took %v, want within one second", took)
						}
						if got != want {
							t.Errorf("share verdict = %s, want %s", got, want)
						}
					})
				}
			}
		})
	}
}

func gap0482ProfileVerdict(t *testing.T, payload []byte, profile string) string {
	t.Helper()
	installToolCallCorpusProfileConnector(t, "claudecode", profile)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile)
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
	recorder := httptest.NewRecorder()
	api.handleAgentHook("claudecode").ServeHTTP(recorder, req)
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK {
		t.Fatalf("share verdict status=%d body=%.300s", recorder.Code, body)
	}
	switch {
	case strings.HasPrefix(body, `{"action":"block"`):
		return "block"
	case strings.HasPrefix(body, `{"action":"allow"`):
		if os.Getenv("R482_FAKE_SHARE_UNANSWERED") == "1" && strings.Contains(string(payload), "ordinary.txt") {
			var notice struct {
				AdditionalContext string         `json:"additional_context"`
				HookOutput        map[string]any `json:"claude_code_output"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &notice); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(notice.AdditionalContext, "could not confirm") {
				t.Errorf("allowed uncertain path has no visible warning: %.300s", body)
			}
			if message, _ := notice.HookOutput["systemMessage"].(string); !strings.Contains(message, "could not confirm") {
				t.Errorf("allowed uncertain path has no native warning: %.300s", body)
			}
		}
		return "allow"
	}
	t.Fatalf("share verdict body=%.300s", body)
	return ""
}
