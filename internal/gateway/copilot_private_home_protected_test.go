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

// GAP-1461: a native Copilot patch to the managed user's own authorized_keys,
// named by absolute or home-form path inside a private home the gateway
// cannot traverse, must reach the protected-target check: the persistence
// rule blocks in action and is the recorded finding in observe, never a
// plain unparsed warning.
func TestNativeCopilotProtectedPatchInPrivateManagedHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix private-home permissions")
	}
	private := filepath.Join(t.TempDir(), "private")
	project := filepath.Join(private, "project")
	keys := filepath.Join(private, ".ssh", "authorized_keys")
	for _, dir := range []string{project, filepath.Dir(keys)} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(keys, []byte("ssh-ed25519 AAAA old\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "notes.txt"), []byte("old\n"), 0600); err != nil {
		t.Fatal(err)
	}
	update := func(path string) string {
		return "*** Begin Patch\n*** Update File: " + path + "\n@@\n-ssh-ed25519 AAAA old\n+ssh-ed25519 AAAA attacker\n*** End Patch\n"
	}
	const rule = "persistence.ssh_authorized_keys_command"
	type testCase struct {
		name, mode, patch string
		// trusted gives the request the managed caller; evidence sends
		// the user-side hook's complete patch evidence.
		trusted, evidence bool
		wantBlock         bool
	}
	cases := []testCase{
		{"action absolute", "action", update(keys), true, true, true},
		{"action home form", "action", update("~/.ssh/authorized_keys"), true, true, true},
		{"action relative escape", "action", update("../.ssh/authorized_keys"), true, true, true},
		{"action behind a benign file", "action", "*** Begin Patch\n*** Add File: " + filepath.Join(project, "a.txt") + "\n+a\n*** Update File: " + keys + "\n@@\n-x\n+y\n*** End Patch\n", true, true, true},
		{"observe absolute", "observe", update(keys), true, true, false},
		{"observe home form", "observe", update("~/.ssh/authorized_keys"), true, true, false},
		{"observe relative escape", "observe", update("../.ssh/authorized_keys"), true, true, false},
		// Without the hook evidence the gateway cannot prove the call; the
		// unparsed answer must still run the protected-target check.
		{"observe absolute without evidence", "observe", update(keys), true, false, false},
		{"observe home form without evidence", "observe", update("~/.ssh/authorized_keys"), true, false, false},
		{"observe relative escape without evidence", "observe", update("../.ssh/authorized_keys"), true, false, false},
		{"observe behind a benign file without evidence", "observe", "*** Begin Patch\n*** Add File: a.txt\n+a\n*** Update File: " + keys + "\n@@\n-x\n+y\n*** End Patch\n", true, false, false},
		{"action absolute without evidence", "action", update(keys), true, false, true},
		{"action absolute without the managed caller", "action", update(keys), false, true, true},
	}
	type request struct {
		body   []byte
		header string
	}
	requests := make([]request, 0, len(cases))
	// The native hook runs as the user, whose home is the private directory.
	t.Setenv("HOME", private)
	for _, tc := range cases {
		body, err := json.Marshal(map[string]any{
			"sessionId": "private-home-keys", "cwd": project,
			"toolCalls": []any{map[string]any{"id": "custom_call_keys", "name": "apply_patch", "args": tc.patch}},
		})
		if err != nil {
			t.Fatal(err)
		}
		header := hookpaths.ResolveConnector("copilot", "", "preToolUse", body)
		if evidence, ok := hookpaths.Decode(header); !ok || evidence[hookpaths.PatchCompleteKey] != "1" {
			t.Fatalf("%s client patch evidence incomplete: %v", tc.name, evidence)
		}
		requests = append(requests, request{body, header})
	}
	if err := os.Chmod(private, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(private, 0700) })
	if _, err := os.Stat(project); err == nil {
		t.Skip("test process can still traverse a private directory")
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Guardrail.Mode = tc.mode
			cfg.Guardrail.Connector = "copilot"
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(string(requests[i].body)))
			req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
			if tc.evidence {
				req.Header.Set(hookpaths.Header, requests[i].header)
			}
			if tc.trusted {
				req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: private}))
			}
			w := httptest.NewRecorder()
			api.handleAgentHook("copilot").ServeHTTP(w, req)
			body := w.Body.String()
			blocked := strings.Contains(body, `"action":"block"`)
			if blocked != tc.wantBlock {
				t.Fatalf("%s: block=%v want %v: %s", tc.name, blocked, tc.wantBlock, body)
			}
			if !tc.wantBlock && !strings.Contains(body, `"severity":"CRITICAL"`) {
				t.Fatalf("%s observe lost the critical alert: %s", tc.name, body)
			}
			if tc.trusted {
				if !strings.Contains(body, rule) {
					t.Fatalf("%s skipped the protected-target check: %s", tc.name, body)
				}
			}
		})
	}
}
