// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The host table uses POSIX homes and /etc/profile.d; the Kiro write
// projection itself is platform-neutral and is pinned on every OS by
// connector.TestKiroTrustedWriteArgs.

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
)

// kiroNativeWriteCalls are the Kiro native write shapes: the kiro-cli
// fs_write commands, the IDE fs_write and fs_append {path, text}, and
// str_replace {path, oldStr, newStr}.
func kiroNativeWriteCalls() []struct {
	name, tool string
	args       func(path, text string) map[string]any
} {
	return []struct {
		name, tool string
		args       func(path, text string) map[string]any
	}{
		{"cli-create", "fs_write", func(p, s string) map[string]any {
			return map[string]any{"command": "create", "path": p, "file_text": s, "__tool_use_purpose": "write the file"}
		}},
		{"cli-append", "fs_write", func(p, s string) map[string]any {
			return map[string]any{"command": "append", "path": p, "new_str": s, "summary": "append"}
		}},
		{"cli-insert", "fs_write", func(p, s string) map[string]any {
			return map[string]any{"command": "insert", "path": p, "insert_line": 1, "new_str": s}
		}},
		{"cli-str-replace", "fs_write", func(p, s string) map[string]any {
			return map[string]any{"command": "str_replace", "path": p, "old_str": "# base", "new_str": s}
		}},
		{"ide-fs-write", "fs_write", func(p, s string) map[string]any { return map[string]any{"path": p, "text": s} }},
		{"ide-fs-append", "fs_append", func(p, s string) map[string]any { return map[string]any{"path": p, "text": s} }},
		{"str-replace", "str_replace", func(p, s string) map[string]any {
			return map[string]any{"path": p, "oldStr": "# base", "newStr": s}
		}},
	}
}

// kiroNativeWriteHook sends one Kiro preToolUse call through the agent hook
// in action mode and returns the raw verdict and the response body.
func kiroNativeWriteHook(t *testing.T, home, cwd, tool string, args map[string]any) (string, string) {
	t.Helper()
	body := string(mustJSON(t, map[string]any{"hook_event_name": "preToolUse", "session_id": "kiro-write",
		"cwd": cwd, "tool_name": tool, "tool_input": args}))
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "kiro"
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/kiro/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hookpaths.Header, hookpaths.Resolve([]byte(body)))
	req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
	recorder := httptest.NewRecorder()
	api.handleAgentHook("kiro").ServeHTTP(recorder, req)
	var resp map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("verdict %q: %v", recorder.Body.String(), err)
	}
	raw, _ := resp["raw_action"].(string)
	return raw, recorder.Body.String()
}

// TestKiroNativeWritesAreJudgedAsWrites pins that every Kiro native write
// shape naming ~/.ssh/authorized_keys is blocked by the SSH persistence rule,
// that the same shape on a project file is allowed, and that the text a
// write reaches the content rules (LD_PRELOAD into /etc/profile.d). Only
// fs_write {path, content} named a write target before; the other shapes
// were allowed with no rule (GAP-0688).
func TestKiroNativeWritesAreJudgedAsWrites(t *testing.T) {
	home, project := hermesPatchHome(t)
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK7 attacker\n"
	for _, call := range kiroNativeWriteCalls() {
		for _, target := range []struct {
			path, text, rule string
		}{
			{keys, key, hermesPatchAuthorizedKeysRule},
			{"~/.ssh/authorized_keys", key, hermesPatchAuthorizedKeysRule},
			{"/etc/profile.d/logger.sh", "# logger\nexport LD_PRELOAD=/usr/local/lib/liblogger.so\n", "persistence.global_ld_preload_install"},
			{filepath.Join(project, "notes.txt"), "# notes\n", ""},
			{"notes.txt", "# notes\n", ""},
		} {
			if strings.HasSuffix(call.name, "str-replace") && strings.HasPrefix(target.path, "/etc/") {
				// An edit is judged as Claude Code Edit: the LD_PRELOAD
				// install rule reads the content of a whole-file write.
				continue
			}
			t.Run(call.name+"/"+target.path, func(t *testing.T) {
				raw, got := kiroNativeWriteHook(t, home, project, call.tool, call.args(target.path, target.text))
				if target.rule == "" {
					if raw != "allow" {
						t.Fatalf("project write raw_action = %q, want allow: %.800s", raw, got)
					}
					return
				}
				if raw != "block" || !strings.Contains(got, target.rule) {
					t.Fatalf("raw_action = %q, want block by %s: %.800s", raw, target.rule, got)
				}
			})
		}
	}
}

// TestKiroUnreviewedWriteShapesAreBlocked pins the conservative result for a
// Kiro write-class call outside the reviewed shapes, even on a project file:
// its write target or text cannot be read, so it is never a silent allow.
func TestKiroUnreviewedWriteShapesAreBlocked(t *testing.T) {
	home, project := hermesPatchHome(t)
	for name, call := range map[string]struct {
		tool string
		args map[string]any
	}{
		"unknown command": {"fs_write", map[string]any{"command": "rewrite", "path": "notes.txt", "file_text": "x"}},
		"unknown key":     {"fs_write", map[string]any{"command": "create", "path": "notes.txt", "file_text": "x", "mode": "0600"}},
		"text not string": {"fs_append", map[string]any{"path": "notes.txt", "text": []any{"x"}}},
		"no new text":     {"str_replace", map[string]any{"path": "notes.txt", "oldStr": "# base"}},
	} {
		t.Run(name, func(t *testing.T) {
			if raw, got := kiroNativeWriteHook(t, home, project, call.tool, call.args); raw != "block" {
				t.Fatalf("raw_action = %q, want the conservative block: %.800s", raw, got)
			}
		})
	}
}

// TestKiroLiveWriteHook covers the write call sent by current Kiro CLI hooks
// and the same call with other write targets.
func TestKiroLiveWriteHook(t *testing.T) {
	home, project := hermesPatchHome(t)
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	hardLink := filepath.Join(project, "keys-hard.txt")
	symlink := filepath.Join(project, "keys-link.txt")
	if err := os.Link(keys, hardLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, symlink); err != nil {
		t.Fatal(err)
	}

	for _, target := range []struct {
		name, path, content, rule string
	}{
		{"authorized keys absolute", keys, "V688-HARDLINK2\n", hermesPatchAuthorizedKeysRule},
		{"authorized keys tilde", "~/.ssh/authorized_keys", "V688-HARDLINK2\n", hermesPatchAuthorizedKeysRule},
		{"authorized keys hard link", hardLink, "V688-HARDLINK2\n", hermesPatchAuthorizedKeysRule},
		{"authorized keys symlink", symlink, "V688-HARDLINK2\n", hermesPatchAuthorizedKeysRule},
		{"profile content", "/etc/profile.d/logger.sh", "# logger\nexport LD_PRELOAD=/usr/local/lib/liblogger.so\n", "persistence.global_ld_preload_install"},
		{"project absolute", filepath.Join(project, "lab-hard2.txt"), "V688-HARDLINK2\n", ""},
		{"project relative", "lab-hard2.txt", "V688-HARDLINK2\n", ""},
	} {
		t.Run(target.name, func(t *testing.T) {
			args := map[string]any{
				"__tool_use_purpose": "Creating the requested file with the specified content",
				"command":            "create",
				"path":               target.path,
				"content":            target.content,
			}
			raw, got := kiroNativeWriteHook(t, home, project, "write", args)
			want := "allow"
			if target.rule != "" {
				want = "block"
			}
			if raw != want || (target.rule != "" && !strings.Contains(got, target.rule)) {
				t.Fatalf("raw_action = %q, want %s by %s: %.800s", raw, want, target.rule, got)
			}
		})
	}
	for _, call := range []struct {
		name string
		args map[string]any
		rule string
	}{
		{"insert end hard link", map[string]any{"command": "insert", "path": hardLink, "content": "V688-HARDLINK2\n"}, hermesPatchAuthorizedKeysRule},
		{"insert end symlink", map[string]any{"command": "insert", "path": symlink, "content": "V688-HARDLINK2\n"}, hermesPatchAuthorizedKeysRule},
		{"insert real path", map[string]any{"command": "insert", "path": keys, "content": "V688-HARDLINK2\n", "insertLine": 3}, hermesPatchAuthorizedKeysRule},
		{"replace hard link", map[string]any{"command": "strReplace", "path": hardLink, "oldStr": "# base", "newStr": "# next", "replaceAll": true}, hermesPatchAuthorizedKeysRule},
		{"insert end profile content", map[string]any{"command": "insert", "path": "/etc/profile.d/logger.sh", "content": "# logger\nexport LD_PRELOAD=/usr/local/lib/liblogger.so\n"}, "persistence.global_ld_preload_install"},
		{"insert end project", map[string]any{"command": "insert", "path": filepath.Join(project, "notes.txt"), "content": "# notes\n"}, ""},
		{"insert line project", map[string]any{"command": "insert", "path": filepath.Join(project, "notes.txt"), "content": "# notes\n", "insertLine": 3}, ""},
		{"replace project", map[string]any{"command": "strReplace", "path": filepath.Join(project, "notes.txt"), "oldStr": "# base", "newStr": "# notes", "replaceAll": true}, ""},
	} {
		t.Run(call.name, func(t *testing.T) {
			call.args["__tool_use_purpose"] = "Update the requested file"
			raw, got := kiroNativeWriteHook(t, home, project, "write", call.args)
			want := "allow"
			if call.rule != "" {
				want = "block"
			}
			if raw != want || (call.rule != "" && !strings.Contains(got, call.rule)) {
				t.Fatalf("raw_action = %q, want %s by %s: %.800s", raw, want, call.rule, got)
			}
		})
	}
	t.Run("unreviewed command", func(t *testing.T) {
		args := map[string]any{
			"__tool_use_purpose": "Creating the requested file with the specified content",
			"command":            "undo_edit",
			"path":               filepath.Join(project, "lab-hard2.txt"),
			"content":            "V688-HARDLINK2\n",
		}
		if raw, got := kiroNativeWriteHook(t, home, project, "write", args); raw != "block" {
			t.Fatalf("raw_action = %q, want block: %.800s", raw, got)
		}
	})
	t.Run("bare write symlink", func(t *testing.T) {
		args := map[string]any{"path": symlink, "content": "V688-HARDLINK2\n"}
		if raw, got := kiroNativeWriteHook(t, home, project, "write", args); raw != "block" ||
			!strings.Contains(got, hermesPatchAuthorizedKeysRule) {
			t.Fatalf("raw_action = %q, want authorized keys block: %.800s", raw, got)
		}
	})
}
