// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// POSIX permissions make the unreadable directory.

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

// hermesClientHook is hermesPatchHostHook with the evidence header the
// Hermes hook client sends (hookpaths.ResolveConnector for "hermes").
func hermesClientHook(t *testing.T, home, body string) string {
	t.Helper()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "hermes"
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hermes/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hookpaths.Header, hookpaths.ResolveConnector("hermes", "", "", []byte(body)))
	req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
	recorder := httptest.NewRecorder()
	api.handleAgentHook("hermes").ServeHTTP(recorder, req)
	return recorder.Body.String()
}

// rel-1-0-2 GAP-0680: a Hermes patch in replace mode gets the hook client's
// resolution of its path, as write_file does, so a target in a directory
// the hook cannot read (a managed gateway behind ProtectHome reads it no
// better) is judged as write_file judges it, not allowed. A replace in an
// ordinary project file stays allowed.
func TestHermesReplacePatchGetsTheClientResolutionOfWriteFile(t *testing.T) {
	home, project := hermesPatchHome(t)
	locked := filepath.Join(filepath.Dir(home), "locked")
	if err := os.MkdirAll(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	if _, err := os.ReadDir(locked); err == nil {
		t.Skip("the test runs with permission to read any directory")
	}
	targets := []string{filepath.Join(locked, "x")}
	if _, err := os.ReadDir("/etc/sudoers.d"); err != nil && !os.IsNotExist(err) {
		targets = append(targets, "/etc/sudoers.d/x")
	}
	for _, target := range targets {
		want := hermesOutcome(t, hermesClientHook(t, home,
			hermesPatchBody(t, project, "write_file", map[string]any{"path": target, "content": "# k\n"})))
		if want.action == "allow" {
			t.Fatalf("write_file %s = %s; the case needs a target write_file blocks", target, want)
		}
		for name, args := range map[string]map[string]any{
			"replace":       {"path": target, "old_string": "# base", "new_string": "# k"},
			"explicit mode": {"mode": "replace", "path": target, "old_string": "# base", "new_string": "# k"},
			"replace all":   {"path": target, "old_string": "# base", "new_string": "# k", "replace_all": true},
		} {
			got := hermesOutcome(t, hermesClientHook(t, home, hermesPatchBody(t, project, "patch", args)))
			if got.action != want.action {
				t.Errorf("patch %s of %s = %s, write_file = %s", name, target, got, want)
			}
		}
	}
	benign := hermesOutcome(t, hermesClientHook(t, home, hermesPatchBody(t, project, "patch",
		map[string]any{"path": "notes.txt", "old_string": "# base", "new_string": "# k"})))
	if benign.action != "allow" {
		t.Fatalf("replace in a project file = %s, want allow", benign)
	}
}
