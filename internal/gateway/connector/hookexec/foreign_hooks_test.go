// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type foreignHookFixture struct {
	profile   string
	workspace string
	dataHome  string
	rt        *stubRT
}

func newForeignHookFixture(t *testing.T) foreignHookFixture {
	t.Helper()
	root := t.TempDir()
	fixture := foreignHookFixture{
		profile:   filepath.Join(root, "profile"),
		workspace: filepath.Join(root, "workspace"),
		dataHome:  filepath.Join(root, "profile", ".defenseclaw"),
		rt:        ok(`{"action":"allow","hook_output":{"permission":"allow"}}`),
	}
	for _, dir := range []string{fixture.profile, fixture.workspace, filepath.Join(fixture.dataHome, "hooks")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

func writeForeignHookJSON(t *testing.T, path string, value interface{}) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f foreignHookFixture) payload(event string) []byte {
	body, _ := json.Marshal(map[string]interface{}{
		"hook_event_name": event,
		"cursor_version":  "3.9.0",
		"workspace_roots": []string{f.workspace},
		"tool_name":       "Shell",
		"tool_input":      map[string]interface{}{"command": "echo ORIGINAL"},
	})
	return body
}

func (f foreignHookFixture) run(t *testing.T, event string, mutate func(*Options)) runResult {
	t.Helper()
	var stdout, stderr bytes.Buffer
	token := "managed-token"
	opts := Options{
		Connector:                 "cursor",
		APIAddr:                   "127.0.0.1:8787",
		Home:                      f.dataHome,
		HookDir:                   filepath.Join(f.dataHome, "hooks"),
		ManagedEnterprise:         true,
		StrictAvailability:        true,
		FailMode:                  "closed",
		AuthenticatedManagedToken: &token,
		ForeignHookHomes:          []string{f.profile},
		Getenv:                    func(string) string { return "" },
		Stdin:                     bytes.NewReader(f.payload(event)),
		Stdout:                    &stdout,
		Stderr:                    &stderr,
		HTTPClient:                &http.Client{Transport: f.rt},
	}
	if mutate != nil {
		mutate(&opts)
	}
	code := Run(context.Background(), opts)
	return runResult{stdout: stdout.String(), stderr: stderr.String(), code: code, rt: f.rt}
}

func rewritingCursorHooks(command string) map[string]interface{} {
	return map[string]interface{}{
		"version": 1,
		"hooks": map[string]interface{}{
			"preToolUse": []interface{}{map[string]interface{}{"command": command}},
		},
	}
}

func rewritingClaudeHooks(command string) map[string]interface{} {
	return map[string]interface{}{
		"hooks": map[string]interface{}{
			"PreToolUse": []interface{}{map[string]interface{}{
				"matcher": "*",
				"hooks":   []interface{}{map[string]interface{}{"type": "command", "command": command}},
			}},
		},
	}
}

func assertForeignHookDenied(t *testing.T, result runResult, path string) {
	t.Helper()
	if result.rt.requests != 0 {
		t.Fatalf("gateway requests = %d, want the guard to deny before gateway contact", result.rt.requests)
	}
	var response map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(result.stdout)), &response); err != nil {
		t.Fatalf("stdout is not a Cursor response: %q", result.stdout)
	}
	if response["permission"] != "deny" {
		t.Fatalf("permission = %#v, want deny; stdout=%s", response["permission"], result.stdout)
	}
	message, _ := response["user_message"].(string)
	if !strings.Contains(message, path) {
		t.Fatalf("deny message %q does not name %s", message, path)
	}
	if agent, _ := response["agent_message"].(string); agent != message {
		t.Fatalf("agent_message = %q, want the same guidance as user_message", agent)
	}
}

// A user-level Cursor preToolUse hook can return updated_input after the
// managed hook allowed the original input; the managed gate must deny.
func TestCursorForeignHookGuardDeniesUserLevelRewriter(t *testing.T) {
	fixture := newForeignHookFixture(t)
	path := filepath.Join(fixture.profile, ".cursor", "hooks.json")
	writeForeignHookJSON(t, path, rewritingCursorHooks("node rewrite.js"))
	result := fixture.run(t, "preToolUse", nil)
	assertForeignHookDenied(t, result, path)
	digest, err := foreignHookHandlerDigest(map[string]interface{}{"command": "node rewrite.js"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.stdout, "sha256:"+digest) {
		t.Fatalf("deny message does not carry the approvable digest %s: %s", digest, result.stdout)
	}
	if !strings.Contains(result.stdout, "connector_hooks.cursor.approved_foreign_hooks") {
		t.Fatalf("deny message does not name the allowlist key: %s", result.stdout)
	}
}

func TestCursorForeignHookGuardCoversEverySource(t *testing.T) {
	for name, build := range map[string]func(f foreignHookFixture) (string, interface{}){
		"project cursor hooks": func(f foreignHookFixture) (string, interface{}) {
			return filepath.Join(f.workspace, ".cursor", "hooks.json"), rewritingCursorHooks("./rewrite.sh")
		},
		"user claude settings": func(f foreignHookFixture) (string, interface{}) {
			return filepath.Join(f.profile, ".claude", "settings.json"), rewritingClaudeHooks("./rewrite.sh")
		},
		"user claude local settings": func(f foreignHookFixture) (string, interface{}) {
			return filepath.Join(f.profile, ".claude", "settings.local.json"), rewritingClaudeHooks("./rewrite.sh")
		},
		"project claude settings": func(f foreignHookFixture) (string, interface{}) {
			return filepath.Join(f.workspace, ".claude", "settings.json"), rewritingClaudeHooks("./rewrite.sh")
		},
		"project claude local settings": func(f foreignHookFixture) (string, interface{}) {
			return filepath.Join(f.workspace, ".claude", "settings.local.json"), rewritingClaudeHooks("./rewrite.sh")
		},
		"case-folded event name": func(f foreignHookFixture) (string, interface{}) {
			return filepath.Join(f.workspace, ".cursor", "hooks.json"), map[string]interface{}{
				"hooks": map[string]interface{}{"PreToolUse": []interface{}{map[string]interface{}{"command": "x"}}},
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newForeignHookFixture(t)
			path, value := build(fixture)
			writeForeignHookJSON(t, path, value)
			assertForeignHookDenied(t, fixture.run(t, "preToolUse", nil), path)
		})
	}
}

func TestCursorForeignHookGuardAllowsApprovedDigestAndNonRewritingHooks(t *testing.T) {
	fixture := newForeignHookFixture(t)
	path := filepath.Join(fixture.profile, ".cursor", "hooks.json")
	writeForeignHookJSON(t, path, map[string]interface{}{
		"version": 1,
		"hooks": map[string]interface{}{
			"preToolUse":           []interface{}{map[string]interface{}{"command": "approved-formatter"}},
			"beforeShellExecution": []interface{}{map[string]interface{}{"command": "audit-only"}},
			"afterFileEdit":        []interface{}{map[string]interface{}{"command": "lint"}},
		},
	})
	digest, err := foreignHookHandlerDigest(map[string]interface{}{"command": "approved-formatter"})
	if err != nil {
		t.Fatal(err)
	}
	result := fixture.run(t, "preToolUse", func(opts *Options) {
		opts.ApprovedForeignHooks = []string{"SHA256:" + strings.ToUpper(digest)}
	})
	if result.rt.requests != 1 {
		t.Fatalf("approved hook: gateway requests = %d, want 1; stdout=%s stderr=%s", result.rt.requests, result.stdout, result.stderr)
	}
	if strings.Contains(result.stdout, "deny") {
		t.Fatalf("approved hook was denied: %s", result.stdout)
	}
}

func TestCursorForeignHookGuardOnlyGatesManagedPreToolUse(t *testing.T) {
	fixture := newForeignHookFixture(t)
	writeForeignHookJSON(t, filepath.Join(fixture.profile, ".cursor", "hooks.json"), rewritingCursorHooks("rewrite"))
	// Other events keep their normal gateway path.
	if result := fixture.run(t, "beforeSubmitPrompt", nil); result.rt.requests != 1 {
		t.Fatalf("beforeSubmitPrompt requests = %d, want 1", result.rt.requests)
	}
	// Per-user (unmanaged) Cursor hooks are unchanged.
	fixture.rt = ok(`{"action":"allow"}`)
	result := fixture.run(t, "preToolUse", func(opts *Options) {
		opts.ManagedEnterprise = false
		opts.AuthenticatedManagedToken = nil
		opts.Token = "tkn"
	})
	if result.rt.requests != 1 {
		t.Fatalf("unmanaged preToolUse requests = %d, want 1; stderr=%s", result.rt.requests, result.stderr)
	}
}

func TestCursorForeignHookGuardFailsClosedOnUnverifiableFiles(t *testing.T) {
	for name, prepare := range map[string]func(t *testing.T, path string){
		"invalid json": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte(`{"hooks": {"preToolUse": [ // comment`), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"oversized": func(t *testing.T, path string) {
			if err := os.WriteFile(path, bytes.Repeat([]byte(" "), int(foreignHookFileLimit)+1), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, path string) {
			target := filepath.Join(filepath.Dir(path), "elsewhere.json")
			writeForeignHookJSON(t, target, rewritingCursorHooks("rewrite"))
			if err := os.Symlink(target, path); err != nil {
				if runtime.GOOS == "windows" {
					t.Skipf("symlink creation needs privileges on Windows: %v", err)
				}
				t.Fatal(err)
			}
		},
		"hooks not an object": func(t *testing.T, path string) {
			writeForeignHookJSON(t, path, map[string]interface{}{"hooks": []interface{}{"x"}})
		},
		"trailing data": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte(`{"hooks":{}} {"hooks":{"preToolUse":[{"command":"x"}]}}`), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newForeignHookFixture(t)
			path := filepath.Join(fixture.workspace, ".cursor", "hooks.json")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			prepare(t, path)
			result := fixture.run(t, "preToolUse", nil)
			assertForeignHookDenied(t, result, path)
			if !strings.Contains(result.stdout, "cannot be verified") {
				t.Fatalf("unverifiable file message = %s", result.stdout)
			}
		})
	}
}

func TestCursorForeignHookGuardIgnoresEmptyAndHandlerlessEntries(t *testing.T) {
	fixture := newForeignHookFixture(t)
	writeForeignHookJSON(t, filepath.Join(fixture.profile, ".claude", "settings.json"), map[string]interface{}{
		"hooks": map[string]interface{}{
			"PreToolUse": []interface{}{map[string]interface{}{"matcher": "Bash", "hooks": []interface{}{}}},
			"PostToolUse": []interface{}{map[string]interface{}{
				"hooks": []interface{}{map[string]interface{}{"type": "command", "command": "log"}},
			}},
		},
		"permissions": map[string]interface{}{"allow": []interface{}{"Bash(ls)"}},
	})
	if err := os.WriteFile(filepath.Join(fixture.workspace, "empty.json"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	writeForeignHookJSON(t, filepath.Join(fixture.workspace, ".claude", "settings.local.json"), map[string]interface{}{
		"hooks": map[string]interface{}{"PreToolUse": []interface{}{map[string]interface{}{"matcher": "Bash"}}},
	})
	if result := fixture.run(t, "preToolUse", nil); result.rt.requests != 1 {
		t.Fatalf("gateway requests = %d, want 1; stdout=%s", result.rt.requests, result.stdout)
	}
}

// The exact managed DefenseClaw registration of the administrator-owned hook
// binary is not foreign; a per-user script, a lookalike command, or the same
// binary without --enterprise-managed (which follows per-user gateway
// configuration and could echo rewritten input) is.
func TestCursorForeignHookGuardRecognizesOnlyTrustedExecutableRegistrations(t *testing.T) {
	trusted := filepath.Join(t.TempDir(), "Program Files", "DefenseClaw", "defenseclaw-hook.exe")
	owned := []map[string]interface{}{
		{"type": "command", "command": trusted, "args": []interface{}{"hook", "--connector", "claudecode", "--enterprise-managed"}},
		{"command": `"` + trusted + `" hook --connector cursor --enterprise-managed`},
	}
	for _, handler := range owned {
		if !foreignHookHandlerOwned(handler, trusted) {
			t.Fatalf("trusted registration treated as foreign: %#v", handler)
		}
	}
	foreign := []map[string]interface{}{
		{"type": "command", "command": trusted, "args": []interface{}{"hook", "--connector", "claudecode"}},
		{"command": `"` + trusted + `" hook --connector cursor`},
		{"command": `"` + trusted + `" hook --connector cursor --enterprise-managed & rewrite.cmd`},
		{"command": `"` + trusted + "\" hook --connector cursor --enterprise-managed\nrewrite.cmd"},
		{"type": "command", "command": trusted, "args": []interface{}{"hook", "--connector", "claudecode", "--event", "x"}},
		{"type": "command", "command": trusted},
		{"command": `"` + trusted + `" hook --connector cursor & rewrite.cmd`},
		{"command": trusted + " hook --connector cursor"}, // unquoted path with spaces
		{"command": filepath.Join(filepath.Dir(trusted), "..", "..", "user", "cursor-hook.ps1")},
		{"type": "http", "url": "http://127.0.0.1:1/rewrite"},
		{"type": "command", "command": "defenseclaw-hook.exe", "args": []interface{}{"hook", "--connector", "cursor"}},
	}
	for _, handler := range foreign {
		if foreignHookHandlerOwned(handler, trusted) {
			t.Fatalf("foreign registration treated as owned: %#v", handler)
		}
	}
	if foreignHookHandlerOwned(owned[0], "") {
		t.Fatal("registration accepted without a trusted executable")
	}

	fixture := newForeignHookFixture(t)
	writeForeignHookJSON(t, filepath.Join(fixture.profile, ".claude", "settings.json"), map[string]interface{}{
		"hooks": map[string]interface{}{"PreToolUse": []interface{}{map[string]interface{}{
			"matcher": "*",
			"hooks":   []interface{}{owned[0]},
		}}},
	})
	result := fixture.run(t, "preToolUse", func(opts *Options) { opts.ForeignHookTrustedExecutable = trusted })
	if result.rt.requests != 1 {
		t.Fatalf("trusted registration blocked the tool call: %s", result.stdout)
	}
}

func TestCursorPayloadWorkspaceRootsNormalization(t *testing.T) {
	absolute := filepath.Join(t.TempDir(), "repo")
	payload, _ := json.Marshal(map[string]interface{}{
		"workspace_roots": []interface{}{absolute, "relative/path", "", 7, "file://" + filepath.ToSlash(absolute)},
		"cwd":             absolute,
	})
	roots := cursorPayloadWorkspaceRoots(payload)
	for _, root := range roots {
		if !filepath.IsAbs(root) {
			t.Fatalf("non-absolute root kept: %q", root)
		}
	}
	if len(roots) == 0 || roots[0] != absolute {
		t.Fatalf("roots = %v, want %s first", roots, absolute)
	}
	if runtime.GOOS == "windows" {
		if root, ok := normalizeCursorWorkspaceRoot("/c:/Users/dev/repo"); !ok || root != `c:\Users\dev\repo` {
			t.Fatalf("URI-style Windows root = (%q, %v)", root, ok)
		}
	}
	many := make([]string, foreignHookMaxRoots+5)
	for index := range many {
		many[index] = filepath.Join(absolute, "r", string(rune('a'+index%26)), strings.Repeat("x", index))
	}
	payload, _ = json.Marshal(map[string]interface{}{"workspace_roots": many})
	if got := len(cursorPayloadWorkspaceRoots(payload)); got != foreignHookMaxRoots {
		t.Fatalf("workspace roots = %d, want bounded %d", got, foreignHookMaxRoots)
	}
}

func TestForeignHookParseCacheIsKeyedByContent(t *testing.T) {
	fixture := newForeignHookFixture(t)
	path := filepath.Join(fixture.workspace, ".cursor", "hooks.json")
	writeForeignHookJSON(t, path, map[string]interface{}{"hooks": map[string]interface{}{}})
	if result := fixture.run(t, "preToolUse", nil); result.rt.requests != 1 {
		t.Fatalf("clean file blocked: %s", result.stdout)
	}
	// Rewriting the same path must be re-read and re-parsed, never served
	// from a cached "clean" verdict.
	writeForeignHookJSON(t, path, rewritingCursorHooks("rewrite"))
	fixture.rt = ok(`{"action":"allow"}`)
	assertForeignHookDenied(t, fixture.run(t, "preToolUse", nil), path)
}

// A changed profile environment variable must not hide the user's own hook
// files: the protected profile directory resolved for the process token is
// scanned in addition to the environment-derived home.
func TestCursorForeignHookGuardScansProtectedProfileHome(t *testing.T) {
	fixture := newForeignHookFixture(t)
	path := filepath.Join(fixture.profile, ".cursor", "hooks.json")
	writeForeignHookJSON(t, path, rewritingCursorHooks("node rewrite.js"))
	decoy := t.TempDir()
	result := fixture.run(t, "preToolUse", func(opts *Options) {
		opts.ForeignHookHomes = []string{decoy}
		opts.ForeignHookProfileHome = fixture.profile
	})
	assertForeignHookDenied(t, result, path)
}
