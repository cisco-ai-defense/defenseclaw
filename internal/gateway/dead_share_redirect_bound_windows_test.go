// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// rel-1-0-6:GAP-0482 on a real Windows host: a redirect to a UNC path on a
// share that does not answer (RFC 5737 TEST-NET-1, which nothing answers)
// is judged within the share bound, by the hook client and by the gateway,
// in every spelling, and never waits for the SMB connect timeout. Each
// spelling names a fresh address, so no earlier probe answers for it. The
// write to the local keys file still blocks; a local redirect is allowed.
func TestGAP0482DeadShareRedirectIsJudgedWithinTheBound(t *testing.T) {
	home := t.TempDir()
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(keys), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keys, []byte("k\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	first := 10 + rand.IntN(200)
	rows := []struct {
		command string
		block   bool
	}{
		{fmt.Sprintf("echo hi > //192.0.2.%d/share/w2.txt", first), false},
		{fmt.Sprintf(`echo hi > '\\?\UNC\192.0.2.%d\share\w.txt'`, first+1), false},
		{fmt.Sprintf(`echo hi > '\\192.0.2.%d\share\w4.txt'`, first+2), false},
		{"echo hi > notes.txt", false},
		{"echo k >> ~/.ssh/authorized_keys", true},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for i, row := range rows {
			if i < 3 && connector == "codex" {
				// A fresh address per call: the first contact is the case.
				row.command = strings.Replace(row.command, fmt.Sprintf("192.0.2.%d", first+i), fmt.Sprintf("192.0.2.%d", first+3+i), 1)
			}
			t.Run(connector+"/"+row.command, func(t *testing.T) {
				payload := mustJSON(t, map[string]any{"session_id": "gap0482", "hook_event_name": "PreToolUse",
					"cwd": home, "permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_gap0482",
					"tool_input": map[string]any{"command": row.command}})
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = connector
				store, logger := testStoreAndLogger(t)
				api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
				start := time.Now()
				req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set(hookpaths.Header, hookpaths.Resolve(payload))
				if connector == "codex" {
					setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
				}
				recorder := httptest.NewRecorder()
				api.handleAgentHook(connector).ServeHTTP(recorder, req)
				took := time.Since(start)
				got := recorder.Body.String()
				blocked := strings.HasPrefix(got, `{"action":"block"`)
				if !blocked && !strings.HasPrefix(got, `{"action":"allow"`) {
					t.Fatalf("status %d body %.300s", recorder.Code, got)
				}
				if took > 2*time.Second {
					t.Fatalf("hook client and gateway took %v, want the share bound (first contact under 1 s)", took)
				}
				if blocked != row.block {
					t.Fatalf("blocked = %v, want %v (%v): %.300s", blocked, row.block, took, got)
				}
			})
		}
	}
}
