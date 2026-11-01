// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
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

// GAP-2180: the Copilot CLI (and Codex) send an apply_patch call as
// {"input": "<patch>"}, as an object or as a JSON string of one. On a
// managed gateway that cannot look into the home (ProtectHome; the
// mode-zero parent stands in for it) the patch text was read as a command
// line whose "***" words are globs that might select authorized_keys, so a
// benign project create raised persistence.ssh_authorized_keys_command and
// action mode denied it. The create is allowed with no finding in observe
// and in action, as the raw patch string is; the same forms that add
// ~/.ssh/authorized_keys still block.
func TestManagedCopilotApplyPatchInputFormIsThePatch(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway walk")
	}
	root := t.TempDir()
	homes := filepath.Join(root, "homes")
	home := filepath.Join(homes, "alice")
	project := filepath.Join(home, "pcc8-proj")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	benign := "*** Begin Patch\n*** Add File: notes08-action.txt\n+T9 action benign edit\n*** End Patch\n"
	decoy := "*** Begin Patch\n*** Add File: " + filepath.Join(home, ".ssh", "authorized_keys") +
		"\n+ssh-rsa AAAAdecoy\n*** End Patch\n"
	forms := []struct {
		name string
		args func(string) any
	}{
		{"raw-string", func(p string) any { return p }},
		{"json-input-string", func(p string) any { return string(mustJSON(t, map[string]string{"input": p})) }},
		{"json-input-object", func(p string) any { return map[string]any{"input": p} }},
	}
	post := func(t *testing.T, mode, name, patch string, args func(string) any) (string, string) {
		t.Helper()
		if err := os.Chmod(homes, 0o700); err != nil {
			t.Fatal(err)
		}
		body := mustJSON(t, map[string]any{
			"sessionId": "gap2180-" + name, "timestamp": 1790483549431, "cwd": project,
			"toolCalls": []any{map[string]any{"id": "c1", "name": "apply_patch", "args": args(patch)}},
		})
		header := hookpaths.ResolveConnector("copilot", "", "preToolUse", body)
		if err := os.Chmod(homes, 0); err != nil {
			t.Fatal(err)
		}
		cfg := &config.Config{}
		cfg.Guardrail.Mode = mode
		cfg.Guardrail.Connector = "copilot"
		api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
		if header != "" {
			req.Header.Set(hookpaths.Header, header)
		}
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
		recorder := httptest.NewRecorder()
		api.handleAgentHook("copilot").ServeHTTP(recorder, req)
		var verdict map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &verdict); err != nil {
			t.Fatalf("verdict %q: %v", recorder.Body.String(), err)
		}
		action, _ := verdict["action"].(string)
		return action, recorder.Body.String()
	}
	for _, form := range forms {
		for _, mode := range []string{"observe", "action"} {
			t.Run(form.name+"/"+mode+"/benign", func(t *testing.T) {
				action, response := post(t, mode, form.name, benign, form.args)
				if action != "allow" || strings.Contains(response, "persistence.") ||
					strings.Contains(response, hookToolCallUnparsedRuleID) {
					t.Fatalf("benign create: action=%s: %.800s", action, response)
				}
			})
		}
		t.Run(form.name+"/action/protected", func(t *testing.T) {
			action, response := post(t, "action", form.name, decoy, form.args)
			if action != "block" || !strings.Contains(response, "persistence.ssh_authorized_keys_command") {
				t.Fatalf("protected create: action=%s: %.800s", action, response)
			}
		})
	}
}
