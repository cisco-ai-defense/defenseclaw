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

func TestNativeCopilotPatchInPrivateManagedHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix private-home permissions")
	}
	private := filepath.Join(t.TempDir(), "private")
	project := filepath.Join(private, "project")
	if err := os.MkdirAll(project, 0700); err != nil {
		t.Fatal(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(project, "keylink")); err != nil {
		t.Fatal(err)
	}
	type testCase struct {
		name, patch, want, rule string
		managed                 bool
	}
	cases := []testCase{
		{"ordinary project file", "*** Begin Patch\n*** Add File: notes.txt\n+ordinary project edit\n*** End Patch\n", "allow", "", true},
		{"protected link", "*** Begin Patch\n*** Update File: keylink\n@@\n-old\n+new\n*** End Patch\n", "block", "persistence.ssh_authorized_keys_command", true},
		{"untrusted client proof", "*** Begin Patch\n*** Add File: notes.txt\n+ordinary project edit\n*** End Patch\n", "block", hookToolCallUnparsedRuleID, false},
	}
	type request struct {
		body   []byte
		header string
	}
	requests := make([]request, 0, len(cases))
	// The native hook runs as the user and can resolve its private project.
	// The managed gateway runs under a service account that cannot stat it.
	for _, tc := range cases {
		body, err := json.Marshal(map[string]any{
			"sessionId": "private-home", "cwd": project,
			"toolCalls": []any{map[string]any{"id": "custom_call_private", "name": "apply_patch", "args": tc.patch}},
		})
		if err != nil {
			t.Fatal(err)
		}
		header := hookpaths.ResolveConnector("copilot", "", "preToolUse", body)
		evidence, ok := hookpaths.Decode(header)
		if !ok || evidence[hookpaths.PatchCompleteKey] != "1" {
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
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "copilot"
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(string(requests[i].body)))
			req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
			req.Header.Set(hookpaths.Header, requests[i].header)
			if tc.managed {
				req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
			}
			w := httptest.NewRecorder()
			api.handleAgentHook("copilot").ServeHTTP(w, req)
			if !strings.Contains(w.Body.String(), `"action":"`+tc.want+`"`) ||
				(tc.rule == "" && strings.Contains(w.Body.String(), hookToolCallUnparsedRuleID)) {
				t.Fatalf("private-home %s: %s", tc.name, w.Body.String())
			}
			if tc.rule != "" && !strings.Contains(w.Body.String(), tc.rule) {
				t.Fatalf("private-home %s lost its rule: %s", tc.name, w.Body.String())
			}
		})
	}
}
