// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// rel-1-0-10:GAP-2178, the managed Windows path: a Claude Code Bash touch of
// 300 operands that ends in a hard-linked second name of the keys file. The
// per-user gateway blocks it from its own walk. A managed gateway that cannot
// read the user's links has only the hook client's decision, which the
// Windows client did not send. "hidden" removes the link after the client
// header is made, so the gateway's view of the folder lacks it, as a managed
// gateway behind the user's folder sees it: only the client decision can
// block then. The ordinary twin is never blocked.
func TestGAP2178WindowsManagedLongTouchKeepsTheClientDecision(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{cwd, filepath.Join(home, ".ssh")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("k\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "plain.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(cwd, "output")
	if err := os.Link(keys, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	words := make([]string, 300)
	for i := range words {
		words[i] = fmt.Sprintf("h%04d", i)
	}
	operands := strings.Join(words, " ")
	verdict := func(t *testing.T, last string, managed, hidden bool) string {
		t.Helper()
		payload := mustJSON(t, map[string]any{"session_id": "gap2178", "hook_event_name": "PreToolUse",
			"cwd": cwd, "permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_gap2178",
			"tool_input": map[string]any{"command": "touch " + operands + " " + last}})
		header := hookpaths.Resolve(payload)
		if hidden {
			if err := os.Remove(link); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := os.Link(keys, link); err != nil {
					t.Fatal(err)
				}
			}()
		}
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.Connector = "claudecode"
		store, logger := testStoreAndLogger(t)
		api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(hookpaths.Header, header)
		if managed {
			req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
		}
		recorder := httptest.NewRecorder()
		api.handleAgentHook("claudecode").ServeHTTP(recorder, req)
		body := recorder.Body.String()
		for _, action := range []string{"block", "alert", "allow"} {
			if strings.HasPrefix(body, `{"action":"`+action+`"`) {
				return action
			}
		}
		return fmt.Sprintf("status %d body %.200s", recorder.Code, body)
	}
	for _, row := range []struct {
		name            string
		last            string
		managed, hidden bool
		block           bool
	}{
		{"per-user second name", "output", false, false, true},
		{"managed second name", "output", true, false, true},
		{"managed second name the gateway cannot see", "output", true, true, true},
		{"per-user ordinary twin", "plain.txt", false, false, false},
		{"managed ordinary twin", "plain.txt", true, false, false},
	} {
		got := verdict(t, row.last, row.managed, row.hidden)
		if row.block && got != "block" || !row.block && got != "allow" && got != "alert" {
			t.Errorf("%s: verdict %s, want block=%v", row.name, got, row.block)
		}
	}
}
