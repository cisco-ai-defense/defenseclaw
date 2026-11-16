// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

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

// Behind ProtectHome a managed gateway cannot resolve the project directory,
// so it receives no working directory of its own; the hook client carries the
// directory the agent runs in. A relative apply_patch path is placed in that
// directory, so a project link named relatively gets the verdict of the
// protected file it reaches, as it does for a per-user gateway and as the
// absolute spelling does. A relative path to an ordinary file or to a link to
// one stays allowed. A typed file tool that names its file relatively is
// placed the same way.
func TestManagedRelativeApplyPatchThroughLinkMatchesPerUser(t *testing.T) {
	envelope := func(directives string) string {
		return "apply_patch <<\x27PATCH\x27\n*** Begin Patch\n" + directives + "*** End Patch\nPATCH\n"
	}
	forms := []struct {
		name string
		body func(path string) string
	}{
		{"Update File", func(p string) string { return envelope("*** Update File: " + p + "\n@@\n-a\n+b\n") }},
		{"Add File", func(p string) string { return envelope("*** Add File: " + p + "\n+b\n") }},
		{"Move to", func(p string) string {
			return envelope("*** Update File: notes.txt\n*** Move to: " + p + "\n@@\n-a\n+b\n")
		}},
		{"two files", func(p string) string {
			return envelope("*** Update File: notes.txt\n@@\n-a\n+b\n*** Add File: " + p + "\n+b\n")
		}},
	}
	installSandboxMarkerRules(t)
	store, logger := testStoreAndLogger(t)
	// send is one hook request; a managed home makes it a call of the managed
	// hook peer of that home.
	send := func(t *testing.T, connector string, payload []byte, header, managedHome string) string {
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
		if managedHome != "" {
			req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: managedHome}))
		}
		recorder := httptest.NewRecorder()
		api.handleAgentHook(connector).ServeHTTP(recorder, req)
		body := recorder.Body.String()
		switch {
		case strings.HasPrefix(body, `{"action":"block"`):
			return "block"
		case strings.HasPrefix(body, `{"action":"allow"`):
			return "allow"
		}
		return fmt.Sprintf("status %d body %.200s", recorder.Code, body)
	}
	const direct = "<credentials file>"
	const relativeDirect = "<relative credentials file>"
	verdicts := func(t *testing.T, connector, tool string, input map[string]string) (perUser, managed string) {
		t.Helper()
		f := newB36ManagedHookFixture(t)
		// The credentials file is outside the home, as in the managed
		// lanes: only the hook client can see the link that reaches it.
		fixture := filepath.Join(t.TempDir(), "home", "fixture", ".netrc")
		if err := os.MkdirAll(filepath.Dir(fixture), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixture, []byte("machine example.invalid login dummy\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		for name, content := range map[string]string{"notes.txt": "x\n", "README.md": "x\n"} {
			if err := os.WriteFile(filepath.Join(f.project, name), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		for name, target := range map[string]string{"netlink": fixture, "readlink": "README.md"} {
			if err := os.Symlink(target, filepath.Join(f.project, name)); err != nil {
				t.Fatal(err)
			}
		}
		relative, err := filepath.Rel(f.project, fixture)
		if err != nil {
			t.Fatal(err)
		}
		fields := map[string]any{}
		for key, value := range input {
			value = strings.ReplaceAll(value, relativeDirect, relative)
			fields[key] = strings.ReplaceAll(value, direct, fixture)
		}
		payload := mustJSON(t, map[string]any{"session_id": "g831m", "hook_event_name": "PreToolUse", "cwd": f.project,
			"permission_mode": "default", "tool_name": tool, "tool_use_id": "toolu_g831m", "tool_input": fields})
		header := f.clientHeader(t, payload)
		perUser = send(t, connector, payload, header, "")
		if err := os.Chmod(f.homes, 0); err != nil {
			t.Fatal(err)
		}
		managed = send(t, connector, payload, header, f.home)
		if err := os.Chmod(f.homes, 0o700); err != nil {
			t.Fatal(err)
		}
		return perUser, managed
	}
	shellInput := func(command string) map[string]string { return map[string]string{"command": command} }
	for _, connector := range []string{"codex", "claudecode"} {
		for _, form := range forms {
			t.Run(connector+"/"+form.name+"/direct", func(t *testing.T) {
				perUser, managed := verdicts(t, connector, "Bash", shellInput(form.body(direct)))
				if perUser != "block" || managed != "block" {
					t.Fatalf("the credentials file by name: per-user %s, managed %s, want block", perUser, managed)
				}
			})
			t.Run(connector+"/"+form.name+"/relative direct", func(t *testing.T) {
				perUser, managed := verdicts(t, connector, "Bash", shellInput(form.body(relativeDirect)))
				if perUser != "block" || managed != "block" {
					t.Fatalf("the credentials file by a relative name: per-user %s, managed %s, want block", perUser, managed)
				}
			})
			for _, spelled := range []string{"netlink", "./netlink", "ordinary/../netlink", "../project/netlink"} {
				t.Run(connector+"/"+form.name+"/"+spelled, func(t *testing.T) {
					perUser, managed := verdicts(t, connector, "Bash", shellInput(form.body(spelled)))
					if perUser != "block" || managed != "block" {
						t.Fatalf("link to the credentials file: per-user %s, managed %s, want block", perUser, managed)
					}
				})
			}
			for _, ordinary := range []string{"notes.txt", "./readlink", "ordinary/../README.md"} {
				t.Run(connector+"/"+form.name+"/benign/"+ordinary, func(t *testing.T) {
					perUser, managed := verdicts(t, connector, "Bash", shellInput(form.body(ordinary)))
					if perUser != "allow" || managed != "allow" {
						t.Fatalf("ordinary path: per-user %s, managed %s, want allow", perUser, managed)
					}
				})
			}
		}
	}
	for _, tool := range []string{"Write", "Edit"} {
		for _, spelled := range []string{"netlink", "./netlink", "ordinary/../netlink", relativeDirect} {
			t.Run("claudecode/"+tool+"/"+spelled, func(t *testing.T) {
				perUser, managed := verdicts(t, "claudecode", tool, map[string]string{"file_path": spelled, "content": "x", "old_string": "a", "new_string": "b"})
				if perUser != "block" || managed != "block" {
					t.Fatalf("typed tool on the credentials file: per-user %s, managed %s, want block", perUser, managed)
				}
			})
		}
		for _, ordinary := range []string{"notes.txt", "./readlink", "ordinary/../README.md"} {
			t.Run("claudecode/"+tool+"/benign/"+ordinary, func(t *testing.T) {
				perUser, managed := verdicts(t, "claudecode", tool, map[string]string{"file_path": ordinary, "content": "x", "old_string": "a", "new_string": "b"})
				if perUser != "allow" || managed != "allow" {
					t.Fatalf("typed tool on an ordinary path: per-user %s, managed %s, want allow", perUser, managed)
				}
			})
		}
	}
}
