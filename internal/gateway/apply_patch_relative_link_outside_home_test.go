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

// A managed agent may work in a private project outside its home. The gateway
// can neither see that project nor trust it as a place to walk, but the hook
// client ran the call there and keyed its link evidence by the placed
// spelling of each path. A relative apply_patch path that reaches a protected
// file through a link there gets the block the protected file gets by name,
// in the shell form of Codex and of Claude Code, and an ordinary relative
// path or a link to an ordinary file stays allowed.
func TestManagedRelativeApplyPatchInProjectOutsideHomeGetsDirectVerdict(t *testing.T) {
	installSandboxMarkerRules(t)
	store, logger := testStoreAndLogger(t)
	fixtureHome := newB36ManagedHookFixture(t)
	fixture := filepath.Join(t.TempDir(), "home", "fixture", ".netrc")
	if err := os.MkdirAll(filepath.Dir(fixture), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture, []byte("machine example.invalid login dummy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "private")
	project := filepath.Join(root, "project")
	if err := os.MkdirAll(filepath.Join(project, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) })
	if err := os.WriteFile(filepath.Join(project, "notes.txt"), []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{
		"netlink": fixture, "twohop": "netlink", "oklink": "notes.txt",
	} {
		if err := os.Symlink(target, filepath.Join(project, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(project, filepath.Join(project, "sub", "parentlink")); err != nil {
		t.Fatal(err)
	}
	relativeFixture, err := filepath.Rel(project, fixture)
	if err != nil {
		t.Fatal(err)
	}
	envelope := func(directives string) string {
		return "apply_patch <<\x27PATCH\x27\n*** Begin Patch\n" + directives + "*** End Patch\nPATCH\n"
	}
	forms := map[string]func(path string) string{
		"Update File": func(p string) string { return envelope("*** Update File: " + p + "\n@@\n-a\n+b\n") },
		"Add File":    func(p string) string { return envelope("*** Add File: " + p + "\n+b\n") },
		"Move to": func(p string) string {
			return envelope("*** Update File: notes.txt\n*** Move to: " + p + "\n@@\n-a\n+b\n")
		},
	}
	send := func(t *testing.T, connector string, payload []byte, header string) string {
		t.Helper()
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.Connector = connector
		api := &APIServer{scannerCfg: cfg, store: store, logger: logger, health: NewSidecarHealth()}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
		req.Header.Set(hookpaths.Header, header)
		if connector == "codex" {
			setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
		}
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: fixtureHome.home}))
		recorder := httptest.NewRecorder()
		api.handleAgentHook(connector).ServeHTTP(recorder, req)
		body := recorder.Body.String()
		switch {
		case strings.HasPrefix(body, `{"action":"block"`):
			return "block"
		case strings.HasPrefix(body, `{"action":"allow"`):
			return "allow"
		}
		return "status " + body
	}
	rows := []struct {
		name, target, want string
	}{
		{"one-hop link", "netlink", "block"},
		{"dot link", "./netlink", "block"},
		{"two-hop link", "twohop", "block"},
		{"linked parent", "sub/parentlink/netlink", "block"},
		{"credentials file by name", fixture, "block"},
		{"credentials file by relative name", relativeFixture, "block"},
		{"ordinary file", "notes.txt", "allow"},
		{"link to an ordinary file", "oklink", "allow"},
	}
	for _, connector := range []string{"codex", "claudecode"} {
		for formName, form := range forms {
			for _, row := range rows {
				t.Run(connector+"/"+formName+"/"+row.name, func(t *testing.T) {
					payload := mustJSON(t, map[string]any{"session_id": "g831o", "hook_event_name": "PreToolUse", "cwd": project,
						"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_g831o",
						"tool_input": map[string]any{"command": form(row.target)}})
					// The client runs as the user and sees the project; the
					// gateway does not.
					header := hookpaths.Resolve(payload)
					if err := os.Chmod(root, 0); err != nil {
						t.Fatal(err)
					}
					defer func() { _ = os.Chmod(root, 0o700) }()
					if got := send(t, connector, payload, header); got != row.want {
						t.Fatalf("%s: verdict %s, want %s", row.target, got, row.want)
					}
				})
			}
		}
	}
}
