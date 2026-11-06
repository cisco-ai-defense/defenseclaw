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

func TestGAP0488ManagedHermesV4AClientTargets(t *testing.T) {
	home, project := hermesPatchHome(t)
	root := filepath.Dir(home)
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(project, "keys-link")); err != nil {
		t.Fatal(err)
	}
	serveWithPack := func(pack, tool string, args map[string]any) hermesHookOutcome {
		t.Helper()
		body := hermesPatchBody(t, project, tool, args)
		header := hookpaths.ResolveConnector("hermes", "", "pre_tool_call", []byte(body))
		if err := os.Chmod(root, 0); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(root, 0o700)
		if _, err := os.ReadDir(project); err == nil {
			t.Skip("the test process can read the private project")
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
	serve := func(tool string, args map[string]any) hermesHookOutcome {
		return serveWithPack("", tool, args)
	}
	update := func(path string) string { return hermesV4AUpdate(path) }
	add := func(path string) string {
		return "*** Begin Patch\n*** Add File: " + path + "\n+ordinary\n*** End Patch\n"
	}
	move := func(source, dest string) string {
		return "*** Begin Patch\n*** Move File: " + source + " -> " + dest + "\n*** End Patch\n"
	}
	forms := []struct{ name, body string }{
		{"update-relative", update("notes.txt")},
		{"update-absolute", update(filepath.Join(project, "notes.txt"))},
		{"add-relative", add("new.txt")},
		{"add-absolute", add(filepath.Join(project, "new.txt"))},
		{"move-relative", move("notes.txt", "moved.txt")},
		{"update-dot-relative", update("./notes.txt")},
		{"add-nested", add("sub/new.txt")},
		{"move-absolute", move(filepath.Join(project, "notes.txt"), filepath.Join(project, "moved.txt"))},
		{"update-spaced", "***Begin Patch\n***Update  File:notes.txt\n@@\n # base\n+ordinary\n***End Patch\n"},
		{"add-spaced", "*** Begin Patch\n***Add  File: fresh.txt\n+ordinary\n*** End Patch\n"},
		{"move-spaced", "***Begin Patch\n***Move  File: notes.txt  ->  moved.txt\n***End Patch\n"},
		{"add-unicode-space", "*** Begin Patch\n***\u00a0Add File:\u00a0fresh.txt\n+ordinary\n*** End Patch\n"},
		{"move-dot-paths", move("./notes.txt", "./moved.txt")},
		{"add-with-space", add("new file.txt")},
	}
	for _, form := range forms {
		got := serve("patch", map[string]any{"mode": "patch", "patch": form.body})
		if got.action != "allow" {
			t.Errorf("ordinary %s = %s, want allow", form.name, got)
		}
		strict := serveWithPack("strict", "patch", map[string]any{"mode": "patch", "patch": form.body})
		if strict.action != "block" {
			t.Errorf("strict %s = %s, want block", form.name, strict)
		}
	}
	for _, test := range []struct {
		name, tool string
		args       map[string]any
		want       string
	}{
		{"write-file", "write_file", map[string]any{"path": "notes.txt", "content": "ordinary"}, "allow"},
		{"replace", "patch", map[string]any{"mode": "replace", "path": "notes.txt", "old_string": "base", "new_string": "ordinary"}, "allow"},
		{"keys-name", "patch", map[string]any{"mode": "patch", "patch": update("~/.ssh/authorized_keys")}, "block"},
		{"keys-link", "patch", map[string]any{"mode": "patch", "patch": update("keys-link")}, "block"},
		{"move-destination-link", "patch", map[string]any{"mode": "patch", "patch": move("notes.txt", "keys-link")}, "block"},
		{"unverified-body", "patch", map[string]any{"mode": "patch", "patch": "*** Begin Patch\n*** End Patch\n"}, "block"},
	} {
		got := serve(test.tool, test.args)
		if got.action != test.want {
			t.Errorf("%s = %s, want %s", test.name, got, test.want)
		}
	}
}

func TestGAP0488ForgedDirectReadingOfLinkedHermesTargetBlocks(t *testing.T) {
	home, project := hermesPatchHome(t)
	root := filepath.Dir(home)
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	link := filepath.Join(project, "keys-link")
	if err := os.Symlink(keys, link); err != nil {
		t.Fatal(err)
	}
	body := hermesPatchBody(t, project, "patch", map[string]any{
		"mode": "patch", "patch": hermesV4AUpdate("keys-link"),
	})
	targets, ok := hookpaths.Decode(hookpaths.ResolveConnector("hermes", "", "pre_tool_call", []byte(body)))
	if !ok {
		t.Fatal("client evidence did not decode")
	}
	targets[link] = link
	if err := os.Chmod(root, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(root, 0o700)
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
	if got := hermesOutcome(t, out.Body.String()).action; got != "block" {
		t.Fatalf("linked target with inconsistent client reading = %s, want block", got)
	}
}
