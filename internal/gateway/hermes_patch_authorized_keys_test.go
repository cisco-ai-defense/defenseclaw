// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The sandbox ingress fixture is POSIX-only, and the host table uses POSIX
// homes; the Hermes write projection itself is platform-neutral and is
// pinned on every OS by connector.TestHermesTrustedWriteViews.

//go:build !windows

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

const hermesPatchAuthorizedKeysRule = "persistence.ssh_authorized_keys_command"

// hermesPatchCall is one Hermes native file-write tool call (patch in its
// replace and V4A modes, or write_file) for the file at path.
type hermesPatchCall struct {
	name, tool string
	args       func(path string) map[string]any
}

func hermesV4A(header string) string {
	return "*** Begin Patch\n" + header + "\n@@\n # base\n+# k\n*** End Patch\n"
}

// hermesPatchCalls are the write forms Hermes' file tools accept (the
// published patch and write_file schemas, and the handler's own reading of
// them: mode defaults to replace, cross_profile is accepted, other keys are
// ignored).
func hermesPatchCalls() []hermesPatchCall {
	replace := func(extra map[string]any) func(string) map[string]any {
		return func(p string) map[string]any {
			args := map[string]any{"path": p, "old_string": "# base", "new_string": "# base\n# k"}
			for key, value := range extra {
				args[key] = value
			}
			return args
		}
	}
	v4a := func(body func(string) string, extra map[string]any) func(string) map[string]any {
		return func(p string) map[string]any {
			args := map[string]any{"mode": "patch", "patch": body(p)}
			for key, value := range extra {
				args[key] = value
			}
			return args
		}
	}
	return []hermesPatchCall{
		{"replace-no-mode", "patch", replace(nil)},
		{"replace-mode", "patch", replace(map[string]any{"mode": "replace"})},
		{"replace-all", "patch", replace(map[string]any{"mode": "replace", "replace_all": true})},
		{"replace-cross-profile", "patch", replace(map[string]any{"cross_profile": true})},
		{"replace-ignored-key", "patch", replace(map[string]any{"task_note": "x"})},
		{"replace-with-patch-key", "patch", replace(map[string]any{"patch": hermesV4A("*** Update File: notes.md")})},
		{"v4a-update", "patch", v4a(func(p string) string { return hermesV4A("*** Update File: " + p) }, nil)},
		{"v4a-add", "patch", v4a(func(p string) string {
			return "*** Begin Patch\n*** Add File: " + p + "\n+# k\n*** End Patch\n"
		}, nil)},
		{"v4a-second-file", "patch", v4a(func(p string) string {
			return "*** Begin Patch\n*** Update File: other.md\n@@\n x\n+y\n*** Update File: " + p + "\n@@\n # base\n+# k\n*** End Patch\n"
		}, nil)},
		// Hermes' own markers take any whitespace, need no Begin line and
		// start at the last Begin line before the first End line.
		{"v4a-loose-header", "patch", v4a(func(p string) string {
			return "*** Begin Patch\n***Update  File:" + p + "\n@@\n # base\n+# k\n*** End Patch\n"
		}, nil)},
		{"v4a-no-begin", "patch", v4a(func(p string) string { return "*** Update File: " + p + "\n@@\n # base\n+# k\n" }, nil)},
		{"v4a-loose-begin", "patch", v4a(func(p string) string {
			return "*** Begin Patch\n*** Update File: other.md\n@@\n x\n+y\n***Begin Patch\n*** Update File: " + p + "\n@@\n # base\n+# k\n*** End Patch\n"
		}, map[string]any{"path": "other.md"})},
		{"v4a-move", "patch", v4a(func(p string) string {
			return "*** Begin Patch\n*** Move File: draft.md -> " + p + "\n*** End Patch\n"
		}, nil)},
		{"v4a-crlf", "patch", v4a(func(p string) string {
			return "*** Begin Patch\r\n*** Update File: " + p + "\r\n@@\r\n # base\r\n+# k\r\n*** End Patch\r\n"
		}, nil)},
		{"write-file", "write_file", func(p string) map[string]any { return map[string]any{"path": p, "content": "# k\n"} }},
		{"write-file-cross-profile", "write_file", func(p string) map[string]any {
			return map[string]any{"path": p, "content": "# k\n", "cross_profile": true}
		}},
	}
}

func hermesPatchBody(t *testing.T, cwd, tool string, args map[string]any) string {
	t.Helper()
	return string(mustJSON(t, map[string]any{"hook_event_name": "pre_tool_call", "tool_name": tool, "tool_input": args,
		"session_id": "20261015_1", "cwd": cwd, "extra": map[string]any{"tool_call_id": "call_1", "task_id": "t1"}}))
}

// hermesPatchVerdict reads a Hermes hook verdict: true for a block by the
// authorized-keys rule, false for an allow.
func hermesPatchVerdict(t *testing.T, got string) bool {
	t.Helper()
	var resp map[string]any
	if err := json.Unmarshal([]byte(got), &resp); err != nil {
		t.Fatalf("verdict %q: %v", got, err)
	}
	if resp["action"] == "block" {
		if !strings.Contains(got, hermesPatchAuthorizedKeysRule) {
			t.Fatalf("blocked by another rule: %.800s", got)
		}
		return true
	}
	if resp["action"] != "allow" {
		t.Fatalf("verdict = %.800s", got)
	}
	return false
}

func hermesPatchHostHook(t *testing.T, home, cwd, body string) string {
	t.Helper()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "hermes"
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hermes/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hookpaths.Header, hookpaths.Resolve([]byte(body)))
	req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
	recorder := httptest.NewRecorder()
	api.handleAgentHook("hermes").ServeHTTP(recorder, req)
	return recorder.Body.String()
}

func hermesPatchHome(t *testing.T) (home, project string) {
	t.Helper()
	root := t.TempDir()
	home, project = filepath.Join(root, "home"), filepath.Join(root, "home", "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(project, "notes.txt")} {
		if err := os.WriteFile(file, []byte("# base\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Chdir(project)
	return home, project
}

// TestHermesNativeWritesOfAuthorizedKeysAreBlocked pins that every Hermes
// native write form naming the active user's ~/.ssh/authorized_keys (by
// absolute path, by ~ and relative to the working directory) is blocked by
// the SSH persistence rule, and that the same form on a project file stays
// allowed. Each form is judged as the reviewed write contract it implements,
// so its target reaches the same file-write rules as write_file (GAP-0667).
func TestHermesNativeWritesOfAuthorizedKeysAreBlocked(t *testing.T) {
	home, project := hermesPatchHome(t)
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	targets := []struct {
		path  string
		block bool
	}{
		{keys, true},
		{"~/.ssh/authorized_keys", true},
		{filepath.Join(project, "notes.txt"), false},
		{"notes.txt", false},
	}
	for _, call := range hermesPatchCalls() {
		for _, target := range targets {
			t.Run(call.name+"/"+target.path, func(t *testing.T) {
				got := hermesPatchHostHook(t, home, project, hermesPatchBody(t, project, call.tool, call.args(target.path)))
				if blocked := hermesPatchVerdict(t, got); blocked != target.block {
					t.Fatalf("blocked = %t, want %t: %.800s", blocked, target.block, got)
				}
			})
		}
	}
}

// TestHermesUnverifiablePatchCallsAreBlocked pins the conservative result for
// a patch call whose write targets cannot be read: Hermes either refuses it
// or the targets are unknown, so the protected file may be one of them.
func TestHermesUnverifiablePatchCallsAreBlocked(t *testing.T) {
	home, project := hermesPatchHome(t)
	for name, args := range map[string]map[string]any{
		"unknown mode":      {"mode": "diff", "path": "notes.txt", "old_string": "a", "new_string": "b"},
		"path not a string": {"path": []any{"notes.txt"}, "old_string": "a", "new_string": "b"},
		"no old string":     {"path": "notes.txt", "new_string": "b"},
		"empty body":        {"mode": "patch", "patch": ""},
		"no operations":     {"mode": "patch", "patch": "*** Begin Patch\n*** End Patch\n"},
		"update no hunk":    {"mode": "patch", "patch": "*** Begin Patch\n*** Update File: notes.txt\n*** End Patch\n"},
		"body not a string": {"mode": "patch", "patch": []any{"*** Begin Patch"}},
		"traversal":         {"mode": "patch", "patch": hermesV4A("*** Update File: ../.ssh/authorized_keys")},
	} {
		t.Run(name, func(t *testing.T) {
			got := hermesPatchHostHook(t, home, project, hermesPatchBody(t, project, "patch", args))
			if !hermesPatchVerdict(t, got) {
				t.Fatalf("allowed: %.800s", got)
			}
		})
	}
}

// TestHermesNativeWritesOfAuthorizedKeysAreBlockedInASandbox is the same
// table through the authenticated sandbox ingress: the guest home is the
// sandbox HOME, and a file of the mounted project stays allowed.
func TestHermesNativeWritesOfAuthorizedKeysAreBlockedInASandbox(t *testing.T) {
	f := newSandboxIngressFixture(t)
	keys := sandboxauth.SandboxHome + "/.ssh/authorized_keys"
	for _, call := range hermesPatchCalls() {
		for _, target := range []struct {
			path  string
			block bool
		}{{keys, true}, {"/work/app/notes.txt", false}} {
			t.Run(call.name+"/"+target.path, func(t *testing.T) {
				_, token := f.mint(t, "dc-hermes-"+call.name+map[bool]string{true: "-k", false: "-b"}[target.block],
					"hermes", "0.19.0", "hermes-hooks-v1", f.project)
				resp := f.hook(t, "/api/v1/hermes/hook", token, hermesPatchBody(t, "/work/app", call.tool, call.args(target.path)))
				raw, _ := json.Marshal(resp)
				if blocked := hermesPatchVerdict(t, string(raw)); blocked != target.block {
					t.Fatalf("blocked = %t, want %t: %.800s", blocked, target.block, raw)
				}
			})
		}
	}
}

// TestHermesV4AAddIsJudgedOnItsContent pins that a V4A Add is judged on the
// text Hermes writes (the "+" line contents of its hunks), as a write_file
// call of that text is: a global LD_PRELOAD export added to a login profile
// is blocked by the same rule either way, and a benign project file added
// the same way stays allowed (GAP-0667).
func TestHermesV4AAddIsJudgedOnItsContent(t *testing.T) {
	const rule = "persistence.global_ld_preload_install"
	home, project := hermesPatchHome(t)
	profile := "/etc/profile.d/connect_logger.sh"
	add := func(path, lines string) map[string]any {
		return map[string]any{"mode": "patch", "patch": "*** Begin Patch\n*** Add File: " + path + "\n" + lines + "*** End Patch\n"}
	}
	for _, test := range []struct {
		name, tool string
		args       map[string]any
		block      bool
	}{
		{"write-file", "write_file", map[string]any{"path": profile, "content": "# loader\nexport LD_PRELOAD=/usr/local/lib/libconnect_logger.so"}, true},
		{"v4a-add", "patch", add(profile, "+# loader\n+export LD_PRELOAD=/usr/local/lib/libconnect_logger.so\n"), true},
		{"v4a-add-second-hunk", "patch", add(profile, "+# loader\n@@ x @@\n+export LD_PRELOAD=/usr/local/lib/libconnect_logger.so\n"), true},
		{"write-file-escaped-padding", "write_file", map[string]any{"path": profile, "content": "# " + strings.Repeat("<", 12000) + "\nexport LD_PRELOAD=/usr/local/lib/libconnect_logger.so"}, true},
		{"v4a-add-escaped-padding", "patch", add(profile, "+# "+strings.Repeat("<", 12000)+"\n+export LD_PRELOAD=/usr/local/lib/libconnect_logger.so\n"), true},
		{"v4a-add-ctl-padding", "patch", add(profile, "+# "+strings.Repeat("\x01", 12000)+"\n+export LD_PRELOAD=/usr/local/lib/libconnect_logger.so\n"), true},
		{"v4a-add-benign", "patch", add(filepath.Join(project, "run.sh"), "+#!/bin/sh\n+echo hello\n"), false},
		{"v4a-add-benign-relative", "patch", add("run.sh", "+#!/bin/sh\n+echo hello\n"), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := hermesPatchHostHook(t, home, project, hermesPatchBody(t, project, test.tool, test.args))
			var resp map[string]any
			if err := json.Unmarshal([]byte(got), &resp); err != nil {
				t.Fatalf("verdict %q: %v", got, err)
			}
			if blocked := resp["action"] == "block" && strings.Contains(got, rule); blocked != test.block ||
				(!test.block && resp["action"] != "allow") {
				t.Fatalf("action %v, want block by %s = %t: %.800s", resp["action"], rule, test.block, got)
			}
		})
	}
}
