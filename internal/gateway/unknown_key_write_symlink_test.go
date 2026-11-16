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

// unknownKeyWriteSymlinkCalls are the native write tools with one key
// outside the reviewed schema (nativeWriteExtraKeyCalls) and a Claude Code
// Edit with one.
func unknownKeyWriteSymlinkCalls() []nativeWriteCall {
	return append(nativeWriteExtraKeyCalls(), nativeWriteCall{"claudecode", "Edit", func(p string) map[string]any {
		return map[string]any{"file_path": p, "old_string": "# base", "new_string": "# base\n# k", "description": "add a line"}
	}})
}

// TestUnknownKeyNativeWritesThroughASymlinkAreBlocked pins the write-target
// class of a native write call with a key outside its tool's reviewed
// schema (GAP-0655): the call stays partial, but the harness writes the
// file its target key names. Through a project symlink (named by an
// absolute or a relative path) or a hard link to
// ~/.ssh/authorized_keys it is blocked by the SSH persistence rule, on a
// gateway that resolves the link itself and on a managed gateway that
// cannot look into the home (ProtectHome; the mode-zero parent stands in
// for it) and reads the hook's write evidence. The symlink check judged
// only the partial call's path facts, which name no target, and the
// evidence listed none, so the write was allowed. The same call to an
// ordinary project file stays allowed.
func TestUnknownKeyNativeWritesThroughASymlinkAreBlocked(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway walk")
	}
	root := t.TempDir()
	homes := filepath.Join(root, "homes")
	home := filepath.Join(homes, "alice")
	project := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	notes := filepath.Join(project, "notes.txt")
	for _, file := range []string{keys, notes} {
		if err := os.WriteFile(file, []byte("# base\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link, hard := filepath.Join(project, "deploy.cfg"), filepath.Join(project, "hard.cfg")
	if err := os.Symlink(keys, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(keys, hard); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	for i, call := range unknownKeyWriteSymlinkCalls() {
		for _, row := range []struct {
			label, target string
			block         bool
		}{
			{"link", link, true}, {"relative-link", filepath.Base(link), true},
			{"hard-link", hard, true}, {"ordinary", notes, false},
		} {
			target, want := row.target, row.block
			for _, protectHome := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/protect-home=%t", call.name(i), row.label, protectHome), func(t *testing.T) {
					if err := os.Chmod(homes, 0o700); err != nil {
						t.Fatal(err)
					}
					body := call.body(t, project, target)
					var got string
					if protectHome {
						evidence := hookpaths.ResolveConnector(call.connector, "", "preToolUse", []byte(body))
						if err := os.Chmod(homes, 0); err != nil {
							t.Fatal(err)
						}
						got = overLimitHostHookWithEvidence(t, call.connector, home, body, evidence)
					} else {
						got = unknownKeyLocalHostHook(t, call.connector, body)
					}
					if blocked := nativeWriteBlocked(t, got); blocked != want {
						t.Fatalf("blocked = %t, want %t: %.600s", blocked, want, got)
					}
				})
			}
		}
	}
}

// unknownKeyLocalHostHook posts body to an unmanaged gateway that resolves
// write targets itself: no write evidence, no managed hook peer.
func unknownKeyLocalHostHook(t *testing.T, connector, body string) string {
	t.Helper()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+connector+"/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if connector == "copilot" {
		req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connector).ServeHTTP(recorder, req)
	return recorder.Body.String()
}
