// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// POSIX permissions emulate the managed gateway that cannot read the
// user's project.

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

// managedHermesHook judges one Hermes hook call as a managed gateway that
// cannot read the user's home (ProtectHome), with the evidence header the
// Hermes hook client computes as the user before the home is locked.
func managedHermesHook(t *testing.T, home, pack, body string) hermesHookOutcome {
	t.Helper()
	header := hookpaths.ResolveConnector("hermes", "", "pre_tool_call", []byte(body))
	root := filepath.Dir(home)
	if err := os.Chmod(root, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(root, 0o700)
	if _, err := os.ReadDir(home); err == nil {
		t.Skip("the test process can read a locked directory")
	}
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "hermes"
	cfg.Guardrail.RulePack = pack
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hermes/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hookpaths.Header, header)
	req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
	out := httptest.NewRecorder()
	api.handleAgentHook("hermes").ServeHTTP(out, req)
	return hermesOutcome(t, out.Body.String())
}

// GAP-0488: a Hermes V4A patch is a native file tool. Each file its
// Update, Add, Delete and Move headers name is judged by the file-write
// rules as write_file (or a delete) of that file, with the hook client's
// resolution of the path, in every profile: an ordinary project file is
// allowed in a managed gateway that cannot read the project, as write_file
// and replace-mode patch of the same file are, and a protected file named
// directly or through a link stays blocked.
func TestGAP0488ManagedHermesV4AIsAFileTool(t *testing.T) {
	home, project := hermesPatchHome(t)
	// The managed gateway's own state is outside the user's home.
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(project, "keys-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "old.txt"), []byte("# base\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	patch := func(body string) string {
		return hermesPatchBody(t, project, "patch", map[string]any{"mode": "patch", "patch": body})
	}
	add := func(path string) string {
		return "*** Begin Patch\n*** Add File: " + path + "\n+ordinary\n*** End Patch\n"
	}
	move := func(source, dest string) string {
		return "*** Begin Patch\n*** Move File: " + source + " -> " + dest + "\n*** End Patch\n"
	}
	del := func(path string) string { return "*** Begin Patch\n*** Delete File: " + path + "\n*** End Patch\n" }
	ordinary := []struct{ name, body string }{
		{"update-relative", hermesV4AUpdate("notes.txt")},
		{"update-absolute", hermesV4AUpdate(filepath.Join(project, "notes.txt"))},
		{"update-dot-relative", hermesV4AUpdate("./notes.txt")},
		{"update-two-files", hermesV4AUpdate("notes.txt", "old.txt")},
		{"add-relative", add("new.txt")},
		{"add-absolute", add(filepath.Join(project, "new.txt"))},
		{"add-nested", add("sub/new.txt")},
		{"add-with-space", add("new file.txt")},
		{"add-tilde-project", add("~/proj/new.txt")},
		{"delete-relative", del("old.txt")},
		{"move-relative", move("old.txt", "moved.txt")},
		{"move-absolute", move(filepath.Join(project, "old.txt"), filepath.Join(project, "moved.txt"))},
		{"update-spaced", "***Begin Patch\n***Update  File:notes.txt\n@@\n # base\n+ordinary\n***End Patch\n"},
		{"add-spaced", "*** Begin Patch\n***Add  File: fresh.txt\n+ordinary\n*** End Patch\n"},
		{"add-unicode-space", "*** Begin Patch\n*** Add File: fresh.txt\n+ordinary\n*** End Patch\n"},
		{"update-mentions-keys-text", "*** Begin Patch\n*** Update File: notes.txt\n@@\n # base\n+see ~/.ssh/authorized_keys\n*** End Patch\n"},
	}
	for _, pack := range []string{"", "strict"} {
		writeFile := managedHermesHook(t, home, pack, hermesPatchBody(t, project, "write_file",
			map[string]any{"path": "notes.txt", "content": "ordinary"}))
		replace := managedHermesHook(t, home, pack, hermesPatchBody(t, project, "patch",
			map[string]any{"mode": "replace", "path": "notes.txt", "old_string": "# base", "new_string": "ordinary"}))
		if writeFile.action != "allow" || replace.action != "allow" {
			t.Fatalf("pack %q: write_file = %s, replace = %s; both controls must allow", pack, writeFile, replace)
		}
		for _, form := range ordinary {
			if got := managedHermesHook(t, home, pack, patch(form.body)); got.action != "allow" {
				t.Errorf("pack %q: ordinary V4A %s = %s, want allow (write_file %s)", pack, form.name, got, writeFile)
			}
		}
		for _, form := range []struct{ name, body string }{
			{"update-keys-name", hermesV4AUpdate("~/.ssh/authorized_keys")},
			{"update-keys-absolute", hermesV4AUpdate(filepath.Join(home, ".ssh", "authorized_keys"))},
			{"add-keys-name", add("~/.ssh/authorized_keys")},
			{"update-keys-link", hermesV4AUpdate("keys-link")},
			{"update-ordinary-then-keys-link", hermesV4AUpdate("notes.txt", "keys-link")},
			{"move-onto-keys-link", move("old.txt", "keys-link")},
			{"move-onto-keys", move("old.txt", "~/.ssh/authorized_keys")},
			{"delete-keys", del("~/.ssh/authorized_keys")},
		} {
			if got := managedHermesHook(t, home, pack, patch(form.body)); got.action != "block" {
				t.Errorf("pack %q: protected V4A %s = %s, want block", pack, form.name, got)
			}
		}
	}
}

// GAP-0488: the managed gateway takes the hook's reading of a V4A target
// only for a target the hook found to be no link. Evidence that names the
// link as its own target keeps the hook's protected-target decision, so it
// cannot turn a write through a link to the keys file into an allow.
func TestGAP0488ManagedHermesV4ALinkReadingIsNotProof(t *testing.T) {
	home, project := hermesPatchHome(t)
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	link := filepath.Join(project, "keys-link")
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), link); err != nil {
		t.Fatal(err)
	}
	body := hermesPatchBody(t, project, "patch", map[string]any{"mode": "patch", "patch": hermesV4AUpdate("keys-link")})
	targets, ok := hookpaths.Decode(hookpaths.ResolveConnector("hermes", "", "pre_tool_call", []byte(body)))
	if !ok || targets[hookpaths.ActionDecisionKey] != hookpaths.ProtectedTargetDecision {
		t.Fatalf("client evidence = %v, want the protected-target decision", targets)
	}
	targets[link] = link
	root := filepath.Dir(home)
	if err := os.Chmod(root, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(root, 0o700)
	if _, err := os.ReadDir(home); err == nil {
		t.Skip("the test process can read a locked directory")
	}
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "hermes"
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hermes/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hookpaths.Header, encodeTargets(t, targets))
	req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
	out := httptest.NewRecorder()
	api.handleAgentHook("hermes").ServeHTTP(out, req)
	if got := hermesOutcome(t, out.Body.String()); got.action != "block" {
		t.Fatalf("keys link read as its own target = %s, want block", got)
	}
}
