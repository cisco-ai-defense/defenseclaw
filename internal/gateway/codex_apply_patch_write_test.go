// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
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

// A Codex apply_patch edit names its files in the patch envelope. Each one is
// a write target with the same protected-path decision as a shell redirect,
// also through a symlink, a hard link or a move, and in every wrapper shape
// (GAP-1416), also behind a command wrapper such as env (GAP-1428).
func TestCodexApplyPatchWriteTargets(t *testing.T) {
	root := t.TempDir()
	home, project, external := filepath.Join(root, "home"), filepath.Join(root, "home", "proj"), filepath.Join(root, "external")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project, external} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	symlink, hardLink := filepath.Join(external, "kfile"), filepath.Join(project, "hard.cfg")
	for _, file := range []string{keys, filepath.Join(project, "notes.txt")} {
		if err := os.WriteFile(file, []byte("marker\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	links := map[string]func() error{
		symlink:  func() error { return os.Symlink(keys, symlink) },
		hardLink: func() error { return os.Link(keys, hardLink) },
	}
	symlinks := links[symlink]() == nil
	if !symlinks && runtime.GOOS != "windows" {
		t.Fatal("symlink")
	}
	if err := links[hardLink](); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Chdir(project)
	envelope := func(body string) string { return "*** Begin Patch\n" + body + "*** End Patch" }
	update := func(path string) string { return "*** Update File: " + path + "\n@@\n marker\n+dccert-block-marker\n" }
	var hundred strings.Builder
	for i := range 100 {
		fmt.Fprintf(&hundred, "*** Add File: f%03d.txt\n+x\n", i)
	}
	// Staged patch files: the hook reads their directives (classifier refix 1).
	for name, body := range map[string]string{
		"draft.patch":  envelope(update(keys)),
		"staged.patch": envelope(update("hard.cfg")),
		"benign.patch": envelope(update("notes.txt")),
	} {
		if err := os.WriteFile(filepath.Join(project, name), []byte(body+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	command := func(text string) map[string]any { return map[string]any{"command": text} }
	nativeCommand := func(text string) map[string]any { return map[string]any{"cmd": text} }
	for _, row := range []struct {
		name, tool string
		input      map[string]any
		alias      string
		block      bool
	}{
		{"direct", "apply_patch", command(envelope(update(keys))), "", true},
		{"symlink", "apply_patch", command(envelope(update(symlink))), symlink, true},
		{"hard link", "apply_patch", command(envelope(update("hard.cfg"))), hardLink, true},
		{"move to", "apply_patch", command(envelope("*** Update File: notes.txt\n*** Move to: " + keys + "\n@@\n marker\n+x\n")), "", true},
		{"protected last", "apply_patch", command(envelope("*** Add File: a.txt\n+x\n" + update("notes.txt") + update(keys))), "", true},
		{"hard link absolute", "apply_patch", command(envelope(update(hardLink))), hardLink, true},
		{"hundred benign first", "apply_patch", command(envelope(hundred.String() + update(hardLink))), hardLink, true},
		// No readable envelope and no protected-named word: not the SSH rule
		// (TGT-0194, GAP-0781/GAP-1106 round 2).
		{"truncated", "apply_patch", command("*** Begin Patch\n" + update("notes.txt")), "", false},
		{"edit tool path", "apply_patch", map[string]any{"path": symlink, "content": "x"}, symlink, true},
		{"bash -c heredoc", "Bash", command("bash -lc \"apply_patch <<'PATCH'\n" + envelope(update("~/.ssh/authorized_keys")) + "\nPATCH\""), "", true},
		// A staged patch file is judged by its directives (classifier refix 1):
		// draft.patch updates authorized_keys, staged.patch its hard link.
		{"env wrapper", "Bash", command("env apply_patch < draft.patch"), "", true},
		{"inert envelope then staged redirect", "Bash", command("echo '" + envelope(update("notes.txt")) + "'\napply_patch < staged.patch"), "", true},
		{"inert envelope then staged pipe", "Bash", command("printf '" + envelope(update("notes.txt")) + "'\ncat staged.patch | apply_patch"), "", true},
		{"printed envelope with stdin override", "Bash", command("printf '" + envelope(update("notes.txt")) + "' | apply_patch < staged.patch"), "", true},
		{"inert envelope then same-line staged pipe", "Bash", command("printf '" + envelope(update("notes.txt")) + "'; cat staged.patch | apply_patch"), "", true},
		{"benign staged redirect", "Bash", command("apply_patch < benign.patch"), "", false},
		{"benign staged pipe after an inert envelope", "Bash", command("printf '" + envelope(update("notes.txt")) + "'; cat benign.patch | apply_patch"), "", false},
		// A staged file the hook cannot read stays TGT-0194.
		{"missing staged file", "Bash", command("apply_patch < missing.patch"), "", false},
		{"here-string", "Bash", command("apply_patch <<< '" + envelope(update("hard.cfg")) + "'"), hardLink, true},
		{"powershell wrapper", "shell", command("powershell -NoProfile -Command \"apply_patch @'\n" + envelope(update("$HOME/.ssh/authorized_keys")) + "\n'@\""), "", true},
		// The protected path compares case-insensitively (Windows case forms).
		{"case form", "apply_patch", command(envelope(update(strings.ToUpper(keys)))), "", true},
		{"benign patch", "apply_patch", command(envelope(update("notes.txt"))), "", false},
		{"benign unquoted heredoc", "Bash", command("apply_patch <<PATCH\n" + envelope(update("notes.txt")) + "\nPATCH"), "", false},
		{"benign unquoted heredoc literal escape", "Bash", command("apply_patch <<PATCH\n" + envelope(update("notes.txt")+`+printf("a\n");`+"\n") + "\nPATCH"), "", false},
		{"benign heredoc", "Bash", command("apply_patch <<'PATCH'\n" + envelope(update("notes.txt")) + "\nPATCH"), "", false},
		{"GAP-0781 native conditional project patch", "exec_command", nativeCommand("if [ -f notes.txt ]; then rg -Fx -- 'marker' notes.txt >/dev/null || apply_patch <<'PATCH'\n" + envelope(update("notes.txt")) + "\nPATCH\nelse\napply_patch <<'PATCH'\n" + envelope("*** Add File: notes.txt\n+marker\n") + "\nPATCH\nfi\nrg -n -Fx -- 'marker' notes.txt"), "", false},
		{"benign search", "Bash", command(`grep -rn "*** Begin Patch" .`), "", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			if row.alias == symlink && !symlinks {
				t.Skip("no symlink privilege")
			}
			if runtime.GOOS == "windows" && row.name == "benign staged pipe after an inert envelope" {
				// Codex runs PowerShell on Windows. The plain (cmd) reading,
				// which a PowerShell hint keeps (GAP-1504), splits the
				// single-quoted envelope and its *** is a glob that reaches
				// hard.cfg, the hard link to authorized_keys here: a lead
				// ruling on that reading is pending (GAP-1717 IN file).
				t.Skip("plain reading of a quoted PowerShell envelope: lead ruling pending (GAP-1717)")
			}
			body := string(mustJSON(t, map[string]any{"session_id": "patch-session", "hook_event_name": "PreToolUse",
				"tool_name": row.tool, "cwd": project, "tool_input": row.input}))
			header := hookpaths.Resolve([]byte(body))
			if row.alias != "" {
				// The managed gateway may not see the caller's link: keep only
				// the hook client's header evidence.
				if err := os.Remove(row.alias); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := links[row.alias](); err != nil {
						t.Error(err)
					}
				})
			}
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "codex"
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", strings.NewReader(body))
			req.Header.Set(hookpaths.Header, header)
			setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
			req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
			recorder := httptest.NewRecorder()
			api.handleAgentHook("codex").ServeHTTP(recorder, req)
			got := recorder.Body.String()
			if !row.block {
				if !strings.HasPrefix(got, `{"action":"allow"`) {
					t.Fatalf("benign edit = %.600s", got)
				}
				return
			}
			if !strings.HasPrefix(got, `{"action":"block"`) ||
				!strings.Contains(got, `"severity":"CRITICAL"`) ||
				!strings.Contains(got, "persistence.ssh_authorized_keys_command:") {
				t.Fatalf("protected edit = %.600s", got)
			}

		})
	}
}
