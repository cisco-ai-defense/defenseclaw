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

// copilotNoChangePermission is the permissionRequest real Copilot CLI
// 1.0.105 sends for an apply_patch of context lines only (managed AD RHEL,
// GAP-1832): an edit of its file whose diff has one empty hunk.
func copilotNoChangePermission(t *testing.T, session, cwd, path string) string {
	t.Helper()
	// Copilot names the file in git form with one leading slash on every OS
	// (a/C:/Users/... on Windows, a/home/... on Linux).
	g := "/" + strings.TrimPrefix(filepath.ToSlash(path), "/")
	diff := "\ndiff --git a" + g + " b" + g + "\nindex 0000000..0000000 100644\n--- a" + g +
		"\n+++ b" + g + "\n@@ -0,0 +0,0 @@\n\n"
	body, err := json.Marshal(map[string]any{"hookName": "permissionRequest", "sessionId": session, "timestamp": 1793162766166,
		"cwd": cwd, "toolName": "edit", "toolInput": map[string]any{"file_path": path, "diff": diff}, "permissionSuggestions": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func copilotNoChangeVerdict(t *testing.T, api *APIServer, body, header string, managedHome string) (string, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(body))
	req.Header.Set("X-DefenseClaw-Copilot-Event", "permissionRequest")
	if header != "" {
		req.Header.Set(hookpaths.Header, header)
	}
	if managedHome != "" {
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: managedHome}))
	}
	w := httptest.NewRecorder()
	api.handleAgentHook("copilot").ServeHTTP(w, req)
	var verdict struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &verdict); err != nil {
		t.Fatalf("%v: %s", err, w.Body.String())
	}
	return verdict.Action, w.Body.String()
}

// A permission callback for an edit that changes no line names its file, so
// it is judged as that file's edit: an ordinary project file is allowed in
// action mode (it was HOOK-TOOL-CALL-UNPARSED and blocked), and the same
// callback for authorized_keys is still refused as a protected write.
func TestNativeCopilotNoChangeEditPermissionIsJudgedNotUnparsed(t *testing.T) {
	keys := copilotRebindHome(t)
	project := t.TempDir()
	notes := filepath.Join(project, "b.txt")
	if err := os.WriteFile(notes, []byte("beta\npatched\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "copilot"
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}

	action, body := copilotNoChangeVerdict(t, api, copilotNoChangePermission(t, "no-change-1832", project, notes), "", "")
	if action != "allow" || strings.Contains(body, hookToolCallUnparsedRuleID) {
		t.Fatalf("no-change edit of a project file: %s", body)
	}
	action, body = copilotNoChangeVerdict(t, api, copilotNoChangePermission(t, "no-change-1832-keys", project, keys), "", "")
	if action != "block" || strings.Contains(body, hookToolCallUnparsedRuleID) {
		t.Fatalf("no-change edit of authorized_keys must be refused as a protected write: %s", body)
	}
}

// In a private managed home the gateway cannot traverse, the managed hook's
// evidence for the same callback proves its file (hookpaths reads the
// projected edit), so the benign callback is allowed there too.
func TestNativeCopilotNoChangeEditPermissionInPrivateManagedHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix private-home permissions")
	}
	private := filepath.Join(t.TempDir(), "private")
	project := filepath.Join(private, "project")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	notes := filepath.Join(project, "b.txt")
	if err := os.WriteFile(notes, []byte("beta\npatched\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	permission := copilotNoChangePermission(t, "no-change-private-1832", project, notes)
	header := hookpaths.ResolveConnector("copilot", "", "permissionRequest", []byte(permission))
	if err := os.Chmod(private, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(private, 0o700) })
	if _, err := os.Stat(project); err == nil {
		t.Skip("test process can still traverse a private directory")
	}
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "copilot"
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
	if action, body := copilotNoChangeVerdict(t, api, permission, header, home); action != "allow" ||
		strings.Contains(body, hookToolCallUnparsedRuleID) {
		t.Fatalf("no-change edit in a private managed home: %s", body)
	}
}
