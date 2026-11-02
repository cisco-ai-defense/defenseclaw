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

// The sourced assignment replaces an earlier value. Both hook connectors
// must allow the ordinary file and block the protected link in per-user and
// managed installations.
func TestCertfixGAP0481SourcedFileFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	for _, name := range []string{"a.txt", "out.txt"} {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"setf.sh": "f=keylink\n", "setf2.sh": "f=out.txt\n"} {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	forms := []struct{ name, command, benign string }{
		{"source", `f=a.txt; . ./setf.sh; echo m >> "$f"`, `f=a.txt; . ./setf2.sh; echo m >> "$f"`},
	}
	var calls []*hookCall
	for _, form := range forms {
		for _, row := range []struct{ name, command, want string }{{"protected", form.command, "block"}, {"benign", form.benign, "allow"}} {
			payload := f.payload(t, row.command)
			header := f.clientHeader(t, payload)
			calls = append(calls, everyMode(form.name+"/"+row.name+"/want="+row.want, payload, header)...)
		}
	}
	f.answerAll(t, calls)
	for _, call := range calls {
		want := "allow"
		if strings.Contains(call.name, "/want=block") {
			want = "block"
		}
		if call.verdict != want {
			t.Errorf("%s: %s, want %s: %.250s", call.name, call.verdict, want, call.body)
		}
	}
}

// The hook client resolves paths before the managed gateway receives a
// Hermes call. Hiding the home from the gateway reproduces ProtectHome.
func TestCertfixGAP0488HermesV4AHiddenHome(t *testing.T) {
	home, project := hermesPatchHome(t)
	parent := filepath.Dir(home)
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.Symlink(keys, filepath.Join(project, "keylink")); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ name, target, mode, want string }{
		{"update-ordinary", "notes.txt", "update", "allow"},
		{"add-ordinary", "new.txt", "add", "allow"},
		{"update-link", "keylink", "update", "block"},
		{"add-keys", keys, "add", "block"},
	} {
		t.Run(row.name, func(t *testing.T) {
			patch := hermesV4AUpdate(row.target)
			if row.mode == "add" {
				patch = "*** Begin Patch\n*** Add File: " + row.target + "\n+# k\n*** End Patch\n"
			}
			body := hermesPatchBody(t, project, "patch", map[string]any{"mode": "patch", "patch": patch})
			header := hookpaths.ResolveConnector("hermes", "", "pre_tool_call", []byte(body))
			if err := os.Chmod(parent, 0); err != nil {
				t.Fatal(err)
			}
			defer os.Chmod(parent, 0o700)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "hermes"
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/hermes/hook", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(hookpaths.Header, header)
			req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
			recorder := httptest.NewRecorder()
			api.handleAgentHook("hermes").ServeHTTP(recorder, req)
			got := hermesOutcome(t, recorder.Body.String())
			if got.action != row.want {
				t.Fatalf("%s = %s, want %s", row.name, got, row.want)
			}
		})
	}
}

// Hermes refuses a patch with no executable V4A operation. The managed
// gateway still checks a named target before permitting that refusal.
func TestCertfixGAP0488HermesNoEffectPatchHiddenHome(t *testing.T) {
	home, project := hermesPatchHome(t)
	parent := filepath.Dir(home)
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.Symlink(keys, filepath.Join(project, "keylink")); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name string
		args map[string]any
		want string
	}{
		{"plain-text", map[string]any{"mode": "patch", "patch": "hello world"}, "allow"},
		{"empty", map[string]any{"mode": "patch", "patch": ""}, "allow"},
		{"mode-only", map[string]any{"mode": "patch"}, "allow"},
		{"empty-envelope", map[string]any{"mode": "patch", "patch": "*** Begin Patch\n*** End Patch\n"}, "allow"},
		{"unified-diff", map[string]any{"mode": "patch", "patch": "--- a/report.txt\n+++ b/report.txt\n@@ -1 +1 @@\n-a\n+b\n"}, "allow"},
		{"no-hunk-update", map[string]any{"mode": "patch", "patch": "*** Begin Patch\n*** Update File: report.txt\n*** End Patch"}, "allow"},
		{"no-mode-v4a", map[string]any{"patch": hermesV4AUpdate("report.txt")}, "allow"},
		{"plain-protected-name", map[string]any{"mode": "patch", "patch": "hello authorized_keys"}, "block"},
		{"no-hunk-link", map[string]any{"mode": "patch", "patch": "*** Begin Patch\n*** Update File: keylink\n*** End Patch"}, "block"},
		{"no-mode-link", map[string]any{"patch": hermesV4AUpdate("keylink")}, "block"},
	} {
		t.Run(row.name, func(t *testing.T) {
			body := hermesPatchBody(t, project, "patch", row.args)
			header := hookpaths.ResolveConnector("hermes", "", "pre_tool_call", []byte(body))
			if err := os.Chmod(parent, 0); err != nil {
				t.Fatal(err)
			}
			defer os.Chmod(parent, 0o700)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "hermes"
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/hermes/hook", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(hookpaths.Header, header)
			req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
			recorder := httptest.NewRecorder()
			api.handleAgentHook("hermes").ServeHTTP(recorder, req)
			got := hermesOutcome(t, recorder.Body.String())
			if got.action != row.want {
				t.Fatalf("%s = %s, want %s", row.name, got, row.want)
			}
		})
	}
}
