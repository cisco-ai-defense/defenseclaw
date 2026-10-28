// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// GAP-1990 (T1b, the GAP-1481 live fixture): in action mode an unreadable
// sibling directory must not turn a benign glob copy into an SSH
// authorized_keys mutation. ~/dec2 holds a/keylink -> authorized_keys,
// a/payload-note, b/ (mode 000), c/ (empty) and payload: `cp payload */payl*`
// copies onto a/payload-note and is allowed; `cp payload */keyl*` still
// blocks. Same class and fix as GAP-1739 (29fd4b25a4).
func TestR105GAP1990UnreadableSiblingGlobCopy(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory")
	}
	home := t.TempDir()
	dec := filepath.Join(home, "dec2")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(dec, "a"), filepath.Join(dec, "b"), filepath.Join(dec, "c")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for _, file := range []string{keys, filepath.Join(dec, "a", "payload-note"), filepath.Join(dec, "payload")} {
		if err := os.WriteFile(file, []byte("marker\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(keys, filepath.Join(dec, "a", "keylink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dec, "b"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(dec, "b"), 0o700) })
	t.Setenv("HOME", home)
	for _, tc := range []struct {
		command string
		block   bool
	}{
		{"cp payload */payl*", false},
		{"cp payload */keyl*", true},
	} {
		t.Run(tc.command, func(t *testing.T) {
			body := string(mustJSON(t, map[string]any{"session_id": "gap1990", "hook_event_name": "PreToolUse",
				"tool_name": "Bash", "cwd": dec, "tool_input": map[string]any{"command": tc.command}}))
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "codex"
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", strings.NewReader(body))
			req.Header.Set(hookpaths.Header, hookpaths.Resolve([]byte(body)))
			setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
			req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
			recorder := httptest.NewRecorder()
			api.handleAgentHook("codex").ServeHTTP(recorder, req)
			got := recorder.Body.String()
			if blocked := strings.HasPrefix(got, `{"action":"block"`); blocked != tc.block {
				t.Fatalf("blocked = %t, want %t: %.600s", blocked, tc.block, got)
			}
			if tc.block && !strings.Contains(got, "persistence.ssh_authorized_keys_command:") {
				t.Fatalf("protected copy without the SSH rule: %.600s", got)
			}
		})
	}
}
