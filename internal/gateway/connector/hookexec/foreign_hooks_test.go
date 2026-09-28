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
	"strconv"
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

// withGateway returns the fixture with a fresh gateway stub, so a run that
// reaches the gateway cannot change the request count another run sees.
func (f foreignHookFixture) withGateway() foreignHookFixture {
	f.rt = ok(`{"action":"allow"}`)
	return f
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
	agent, _ := response["agent_message"].(string)
	if !strings.Contains(agent, path) || !strings.HasPrefix(agent, "DefenseClaw blocked this tool call") {
		t.Fatalf("agent_message = %q, want the same guidance as user_message", agent)
	}
	if strings.Contains(agent, " that runs ") {
		t.Fatalf("agent_message %q repeats the handler command line", agent)
	}
}

func cursorDenyMessages(t *testing.T, stdout string) (string, string) {
	t.Helper()
	var response map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &response); err != nil {
		t.Fatalf("stdout is not a Cursor response: %q", stdout)
	}
	user, _ := response["user_message"].(string)
	agent, _ := response["agent_message"].(string)
	return user, agent
}

// A user-level Cursor preToolUse hook can return updated_input after the
// managed hook allowed the original input; the managed gate must deny.
func TestCursorForeignHookGuardDeniesUserLevelRewriter(t *testing.T) {
	fixture := newForeignHookFixture(t)
	path := filepath.Join(fixture.profile, ".cursor", "hooks.json")
	writeForeignHookJSON(t, path, rewritingCursorHooks("node rewrite.js"))
	result := fixture.run(t, "preToolUse", nil)
	assertForeignHookDenied(t, result, path)
	digest, err := foreignHookApprovalDigest(foreignHookScopeUser, "preToolUse", map[string]interface{}{"command": "node rewrite.js"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.stdout, "sha256:"+digest) {
		t.Fatalf("deny message does not carry the approvable digest %s: %s", digest, result.stdout)
	}
	if !strings.Contains(result.stdout, "connector_hooks.cursor.approved_foreign_hooks") {
		t.Fatalf("deny message does not name the allowlist key: %s", result.stdout)
	}
	// The user sees what the handler runs before asking for approval; the
	// model does not receive the command line.
	user, agent := cursorDenyMessages(t, result.stdout)
	if !strings.Contains(user, `that runs command "node rewrite.js"`) {
		t.Fatalf("user_message does not show the handler command: %s", user)
	}
	if strings.Contains(agent, "node rewrite.js") {
		t.Fatalf("agent_message carries the handler command: %s", agent)
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
	digest, err := foreignHookApprovalDigest(foreignHookScopeUser, "preToolUse", map[string]interface{}{"command": "approved-formatter"})
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

// An approval covers one registration in one scope: the same handler text in
// a project file, under a broader Claude-format matcher, or under another
// event is a different registration and still denies.
func TestCursorForeignHookApprovalIsBoundToScopeEventAndMatcher(t *testing.T) {
	handler := map[string]interface{}{"type": "command", "command": ".cursor/hooks/format.sh"}
	claudeGroup := func(matcher string) map[string]interface{} {
		return map[string]interface{}{"matcher": matcher, "hooks": []interface{}{handler}}
	}
	userDigest, err := foreignHookApprovalDigest(foreignHookScopeUser, "preToolUse", handler)
	if err != nil {
		t.Fatal(err)
	}
	projectReadDigest, err := foreignHookApprovalDigest(foreignHookScopeProject, "preToolUse", claudeGroup("Read"))
	if err != nil {
		t.Fatal(err)
	}
	approve := func(opts *Options) { opts.ApprovedForeignHooks = []string{userDigest, projectReadDigest} }

	fixture := newForeignHookFixture(t)
	writeForeignHookJSON(t, filepath.Join(fixture.profile, ".cursor", "hooks.json"), map[string]interface{}{
		"hooks": map[string]interface{}{"preToolUse": []interface{}{handler}},
	})
	claudeSettings := filepath.Join(fixture.workspace, ".claude", "settings.json")
	writeForeignHookJSON(t, claudeSettings, map[string]interface{}{
		"hooks": map[string]interface{}{"PreToolUse": []interface{}{claudeGroup("Read")}},
	})
	if result := fixture.run(t, "preToolUse", approve); result.rt.requests != 1 {
		t.Fatalf("approved registrations denied: %s", result.stdout)
	}

	// The user-scope approval does not cover the same text in a project file.
	projectHooks := filepath.Join(fixture.workspace, ".cursor", "hooks.json")
	writeForeignHookJSON(t, projectHooks, map[string]interface{}{
		"hooks": map[string]interface{}{"preToolUse": []interface{}{handler}},
	})
	fixture.rt = ok(`{"action":"allow"}`)
	assertForeignHookDenied(t, fixture.run(t, "preToolUse", approve), projectHooks)
	if err := os.Remove(projectHooks); err != nil {
		t.Fatal(err)
	}

	// The matcher is part of the Claude-format registration.
	writeForeignHookJSON(t, claudeSettings, map[string]interface{}{
		"hooks": map[string]interface{}{"PreToolUse": []interface{}{claudeGroup("*")}},
	})
	fixture.rt = ok(`{"action":"allow"}`)
	assertForeignHookDenied(t, fixture.run(t, "preToolUse", approve), claudeSettings)

	// Event names are canonical, so the Claude-format spelling of the same
	// event keeps the approval.
	writeForeignHookJSON(t, claudeSettings, map[string]interface{}{
		"hooks": map[string]interface{}{"preToolUse": []interface{}{claudeGroup("Read")}},
	})
	fixture.rt = ok(`{"action":"allow"}`)
	if result := fixture.run(t, "preToolUse", approve); result.rt.requests != 1 {
		t.Fatalf("approved registration under the canonical event name denied: %s", result.stdout)
	}

	// The event is part of the registration: the preToolUse approval does not
	// cover the same handler registered for workspaceOpen.
	userHooks := filepath.Join(fixture.profile, ".cursor", "hooks.json")
	writeForeignHookJSON(t, userHooks, map[string]interface{}{
		"hooks": map[string]interface{}{"workspaceOpen": []interface{}{handler}},
	})
	fixture.rt = ok(`{"action":"allow"}`)
	result := fixture.run(t, "preToolUse", approve)
	assertForeignHookDenied(t, result, userHooks)
	if !strings.Contains(result.stdout, "registers a workspaceOpen hook") {
		t.Fatalf("denial does not name the workspaceOpen registration: %s", result.stdout)
	}
	openDigest, err := foreignHookApprovalDigest(foreignHookScopeUser, "workspaceOpen", handler)
	if err != nil {
		t.Fatal(err)
	}
	if openDigest == userDigest {
		t.Fatal("the approval digest does not depend on the event")
	}
}

func writeCursorPluginManifest(t *testing.T, plugin string, manifest map[string]interface{}) {
	t.Helper()
	writeForeignHookJSON(t, filepath.Join(plugin, ".cursor-plugin", "plugin.json"), manifest)
}

// Cursor plugins bundle hooks that run beside the managed hook; a plugin's
// preToolUse handler can return updated_input just like a user hook, and a
// workspaceOpen handler can load further plugins.
func TestCursorForeignHookGuardScansPluginHooks(t *testing.T) {
	for name, build := range map[string]func(t *testing.T, plugins string) string{
		"local plugin default hooks": func(t *testing.T, plugins string) string {
			plugin := filepath.Join(plugins, "local", "p")
			writeCursorPluginManifest(t, plugin, map[string]interface{}{"name": "p"})
			path := filepath.Join(plugin, "hooks", "hooks.json")
			writeForeignHookJSON(t, path, rewritingCursorHooks("./scripts/rewrite.sh"))
			return path
		},
		"manifest hooks path": func(t *testing.T, plugins string) string {
			plugin := filepath.Join(plugins, "local", "p")
			writeCursorPluginManifest(t, plugin, map[string]interface{}{"name": "p", "hooks": "./config/custom-hooks.json"})
			path := filepath.Join(plugin, "config", "custom-hooks.json")
			writeForeignHookJSON(t, path, rewritingCursorHooks("./scripts/rewrite.sh"))
			return path
		},
		"manifest hooks path list": func(t *testing.T, plugins string) string {
			plugin := filepath.Join(plugins, "local", "p")
			writeCursorPluginManifest(t, plugin, map[string]interface{}{"name": "p", "hooks": []interface{}{"./missing.json", "./b.json"}})
			path := filepath.Join(plugin, "b.json")
			writeForeignHookJSON(t, path, rewritingCursorHooks("./scripts/rewrite.sh"))
			return path
		},
		"manifest inline event map": func(t *testing.T, plugins string) string {
			plugin := filepath.Join(plugins, "local", "p")
			writeCursorPluginManifest(t, plugin, map[string]interface{}{
				"name":  "p",
				"hooks": map[string]interface{}{"preToolUse": []interface{}{map[string]interface{}{"command": "./rewrite.sh"}}},
			})
			return filepath.Join(plugin, ".cursor-plugin", "plugin.json")
		},
		"manifest inline document": func(t *testing.T, plugins string) string {
			plugin := filepath.Join(plugins, "local", "p")
			writeCursorPluginManifest(t, plugin, map[string]interface{}{"name": "p", "hooks": rewritingCursorHooks("./rewrite.sh")})
			return filepath.Join(plugin, ".cursor-plugin", "plugin.json")
		},
		"marketplace cache layout": func(t *testing.T, plugins string) string {
			plugin := filepath.Join(plugins, "cache", "acme", "p", "1.2.0")
			writeCursorPluginManifest(t, plugin, map[string]interface{}{"name": "p"})
			path := filepath.Join(plugin, "hooks", "hooks.json")
			writeForeignHookJSON(t, path, rewritingCursorHooks("./rewrite.sh"))
			return path
		},
		"hooks folder without a manifest": func(t *testing.T, plugins string) string {
			path := filepath.Join(plugins, "local", "p", "hooks", "hooks.json")
			writeForeignHookJSON(t, path, rewritingCursorHooks("./rewrite.sh"))
			return path
		},
		"claude-format plugin hooks": func(t *testing.T, plugins string) string {
			plugin := filepath.Join(plugins, "local", "p")
			writeCursorPluginManifest(t, plugin, map[string]interface{}{"name": "p"})
			path := filepath.Join(plugin, "hooks", "hooks.json")
			writeForeignHookJSON(t, path, rewritingClaudeHooks("${CLAUDE_PLUGIN_ROOT}/rewrite.sh"))
			return path
		},
		"bare event map": func(t *testing.T, plugins string) string {
			plugin := filepath.Join(plugins, "local", "p")
			writeCursorPluginManifest(t, plugin, map[string]interface{}{"name": "p"})
			path := filepath.Join(plugin, "hooks", "hooks.json")
			writeForeignHookJSON(t, path, map[string]interface{}{
				"preToolUse": []interface{}{map[string]interface{}{"command": "./rewrite.sh"}},
			})
			return path
		},
		"plugin workspaceOpen loader": func(t *testing.T, plugins string) string {
			plugin := filepath.Join(plugins, "local", "p")
			writeCursorPluginManifest(t, plugin, map[string]interface{}{"name": "p"})
			path := filepath.Join(plugin, "hooks", "hooks.json")
			writeForeignHookJSON(t, path, map[string]interface{}{"hooks": map[string]interface{}{
				"workspaceOpen": []interface{}{map[string]interface{}{"command": "./load-plugins.sh"}},
			}})
			return path
		},
		"entry with a command and an empty hooks array": func(t *testing.T, plugins string) string {
			plugin := filepath.Join(plugins, "local", "p")
			writeCursorPluginManifest(t, plugin, map[string]interface{}{"name": "p"})
			path := filepath.Join(plugin, "hooks", "hooks.json")
			writeForeignHookJSON(t, path, map[string]interface{}{"hooks": map[string]interface{}{
				"preToolUse": []interface{}{map[string]interface{}{"command": "./rewrite.sh", "hooks": []interface{}{}}},
			}})
			return path
		},
		"plugin nested in a marketplace checkout that is a plugin": func(t *testing.T, plugins string) string {
			marketplace := filepath.Join(plugins, "marketplaces", "acme")
			writeCursorPluginManifest(t, marketplace, map[string]interface{}{"name": "acme"})
			writeForeignHookJSON(t, filepath.Join(marketplace, ".cursor-plugin", "marketplace.json"), map[string]interface{}{
				"name":    "acme",
				"plugins": []interface{}{map[string]interface{}{"name": "foo", "source": "plugins/foo"}},
			})
			nested := filepath.Join(marketplace, "plugins", "foo")
			writeCursorPluginManifest(t, nested, map[string]interface{}{"name": "foo"})
			path := filepath.Join(nested, "hooks", "hooks.json")
			writeForeignHookJSON(t, path, rewritingCursorHooks("./rewrite.sh"))
			return path
		},
		"hooks folder nested in a plugin": func(t *testing.T, plugins string) string {
			plugin := filepath.Join(plugins, "local", "p")
			writeCursorPluginManifest(t, plugin, map[string]interface{}{"name": "p"})
			path := filepath.Join(plugin, "plugins", "bar", "hooks", "hooks.json")
			writeForeignHookJSON(t, path, rewritingCursorHooks("./rewrite.sh"))
			return path
		},
		"marketplace entry hooks path": func(t *testing.T, plugins string) string {
			marketplace := filepath.Join(plugins, "marketplaces", "acme")
			writeForeignHookJSON(t, filepath.Join(marketplace, ".cursor-plugin", "marketplace.json"), map[string]interface{}{
				"name": "acme",
				"plugins": []interface{}{map[string]interface{}{
					"name": "foo", "source": "plugins/foo", "hooks": "./config/hooks.json",
				}},
			})
			path := filepath.Join(marketplace, "plugins", "foo", "config", "hooks.json")
			writeForeignHookJSON(t, path, rewritingCursorHooks("./rewrite.sh"))
			return path
		},
		"marketplace entry hooks path under pluginRoot": func(t *testing.T, plugins string) string {
			marketplace := filepath.Join(plugins, "marketplaces", "acme")
			writeForeignHookJSON(t, filepath.Join(marketplace, ".cursor-plugin", "marketplace.json"), map[string]interface{}{
				"name":     "acme",
				"metadata": map[string]interface{}{"pluginRoot": "./plugins"},
				"plugins": []interface{}{map[string]interface{}{
					"name": "foo", "source": map[string]interface{}{"path": "foo"}, "hooks": "cfg/h.json",
				}},
			})
			path := filepath.Join(marketplace, "plugins", "foo", "cfg", "h.json")
			writeForeignHookJSON(t, path, rewritingClaudeHooks("./rewrite.sh"))
			return path
		},
		"marketplace entry inline hooks": func(t *testing.T, plugins string) string {
			marketplace := filepath.Join(plugins, "marketplaces", "acme")
			path := filepath.Join(marketplace, ".cursor-plugin", "marketplace.json")
			writeForeignHookJSON(t, path, map[string]interface{}{
				"name": "acme",
				"plugins": []interface{}{
					map[string]interface{}{"name": "quiet", "source": "quiet"},
					map[string]interface{}{"name": "foo", "source": "foo", "hooks": rewritingCursorHooks("./rewrite.sh")},
				},
			})
			return path
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newForeignHookFixture(t)
			path := build(t, filepath.Join(fixture.profile, ".cursor", "plugins"))
			result := fixture.run(t, "preToolUse", nil)
			assertForeignHookDenied(t, result, path)
			if !strings.Contains(result.stdout, "plugin-level hook file") {
				t.Fatalf("plugin denial does not name the plugin scope: %s", result.stdout)
			}
		})
	}
}

// An entry that carries its own command next to a hooks array runs that
// command when it is read in the Cursor layout, so grouping only the trusted
// DefenseClaw registration under it does not hide the command.
func TestCursorForeignHookGuardGatesTheCommandOfAGroupedEntry(t *testing.T) {
	trusted := filepath.Join(t.TempDir(), "DefenseClaw", "defenseclaw-hook")
	owned := map[string]interface{}{
		"type": "command", "command": trusted, "args": []interface{}{"hook", "--connector", "cursor", "--enterprise-managed"},
	}
	mixed := map[string]interface{}{"matcher": "*", "command": "./rewrite.sh", "hooks": []interface{}{owned}}
	events := map[string]interface{}{"preToolUse": []interface{}{mixed}}
	withTrusted := func(approved ...string) func(*Options) {
		return func(opts *Options) {
			opts.ForeignHookTrustedExecutable = trusted
			opts.ApprovedForeignHooks = approved
		}
	}
	for name, build := range map[string]func(t *testing.T, f foreignHookFixture) (string, string){
		"plugin hooks file": func(t *testing.T, f foreignHookFixture) (string, string) {
			plugin := filepath.Join(f.profile, ".cursor", "plugins", "local", "p")
			writeCursorPluginManifest(t, plugin, map[string]interface{}{"name": "p"})
			path := filepath.Join(plugin, "hooks", "hooks.json")
			writeForeignHookJSON(t, path, map[string]interface{}{"hooks": events})
			return path, foreignHookScopePlugin
		},
		"plugin manifest inline hooks": func(t *testing.T, f foreignHookFixture) (string, string) {
			plugin := filepath.Join(f.profile, ".cursor", "plugins", "local", "p")
			writeCursorPluginManifest(t, plugin, map[string]interface{}{"name": "p", "hooks": events})
			return filepath.Join(plugin, ".cursor-plugin", "plugin.json"), foreignHookScopePlugin
		},
		"claude-format settings": func(t *testing.T, f foreignHookFixture) (string, string) {
			path := filepath.Join(f.workspace, ".claude", "settings.json")
			writeForeignHookJSON(t, path, map[string]interface{}{"hooks": events})
			return path, foreignHookScopeProject
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newForeignHookFixture(t)
			path, scope := build(t, fixture)
			result := fixture.run(t, "preToolUse", withTrusted())
			assertForeignHookDenied(t, result, path)
			user, _ := cursorDenyMessages(t, result.stdout)
			if !strings.Contains(user, `that runs command "./rewrite.sh"`) {
				t.Fatalf("denial does not name the entry's own command: %s", user)
			}
			// The entry's approval covers the whole registration.
			digest, err := foreignHookApprovalDigest(scope, "preToolUse", mixed)
			if err != nil {
				t.Fatal(err)
			}
			fixture.rt = ok(`{"action":"allow"}`)
			if result := fixture.run(t, "preToolUse", withTrusted(digest)); result.rt.requests != 1 {
				t.Fatalf("approved entry denied: %s", result.stdout)
			}
		})
	}

	// A matcher group that holds only the trusted registration is not foreign.
	fixture := newForeignHookFixture(t)
	writeForeignHookJSON(t, filepath.Join(fixture.profile, ".cursor", "plugins", "local", "p", "hooks", "hooks.json"),
		map[string]interface{}{"hooks": map[string]interface{}{"preToolUse": []interface{}{
			map[string]interface{}{"matcher": "*", "hooks": []interface{}{owned}},
		}}})
	if result := fixture.run(t, "preToolUse", withTrusted()); result.rt.requests != 1 {
		t.Fatalf("trusted matcher group denied: %s", result.stdout)
	}
}

func TestCursorForeignHookGuardAllowsPluginsWithoutGatedHooks(t *testing.T) {
	fixture := newForeignHookFixture(t)
	plugins := filepath.Join(fixture.profile, ".cursor", "plugins")
	formatter := filepath.Join(plugins, "local", "formatter")
	writeCursorPluginManifest(t, formatter, map[string]interface{}{"name": "formatter"})
	writeForeignHookJSON(t, filepath.Join(formatter, "hooks", "hooks.json"), map[string]interface{}{
		"hooks": map[string]interface{}{"afterFileEdit": []interface{}{map[string]interface{}{"command": "./format.sh"}}},
	})
	writeCursorPluginManifest(t, filepath.Join(plugins, "local", "skills-only"), map[string]interface{}{"name": "skills-only"})
	// A marketplace checkout: its root metadata is not a plugin manifest, and
	// version-control folders are not plugin sources.
	marketplace := filepath.Join(plugins, "marketplaces", "acme")
	writeForeignHookJSON(t, filepath.Join(marketplace, ".cursor-plugin", "marketplace.json"), map[string]interface{}{
		"name": "acme",
		"plugins": []interface{}{
			"not an entry",
			map[string]interface{}{"name": "approved", "source": "approved"},
			map[string]interface{}{"name": "remote", "source": map[string]interface{}{"source": "github", "repo": "acme/remote"}},
			map[string]interface{}{"name": "formatting", "source": "formatting", "hooks": "hooks/format.json"},
		},
	})
	writeForeignHookJSON(t, filepath.Join(marketplace, "formatting", "hooks", "format.json"), map[string]interface{}{
		"hooks": map[string]interface{}{"afterFileEdit": []interface{}{map[string]interface{}{"command": "./format.sh"}}},
	})
	writeForeignHookJSON(t, filepath.Join(marketplace, ".git", "hooks", "hooks.json"), rewritingCursorHooks("ignored"))
	writeForeignHookJSON(t, filepath.Join(marketplace, "node_modules", "x", "hooks", "hooks.json"), rewritingCursorHooks("ignored"))
	approvedPlugin := filepath.Join(marketplace, "approved")
	writeCursorPluginManifest(t, approvedPlugin, map[string]interface{}{"name": "approved"})
	// Version-control and package folders inside a plugin are skipped too.
	writeForeignHookJSON(t, filepath.Join(approvedPlugin, ".git", "hooks", "hooks.json"), rewritingCursorHooks("ignored"))
	writeForeignHookJSON(t, filepath.Join(approvedPlugin, "node_modules", "y", "hooks", "hooks.json"), rewritingCursorHooks("ignored"))
	handler := map[string]interface{}{"command": "./approved.sh"}
	writeForeignHookJSON(t, filepath.Join(approvedPlugin, "hooks", "hooks.json"), map[string]interface{}{
		"hooks": map[string]interface{}{"preToolUse": []interface{}{handler}},
	})
	digest, err := foreignHookApprovalDigest(foreignHookScopePlugin, "preToolUse", handler)
	if err != nil {
		t.Fatal(err)
	}
	result := fixture.run(t, "preToolUse", func(opts *Options) { opts.ApprovedForeignHooks = []string{digest} })
	if result.rt.requests != 1 {
		t.Fatalf("plugins without unapproved gated hooks were denied: %s", result.stdout)
	}

	// A folder named like a skipped one is still read when it is a plugin.
	hidden := filepath.Join(plugins, "local", "node_modules")
	writeCursorPluginManifest(t, hidden, map[string]interface{}{"name": "node_modules"})
	hiddenHooks := filepath.Join(hidden, "hooks", "hooks.json")
	writeForeignHookJSON(t, hiddenHooks, rewritingCursorHooks("./rewrite.sh"))
	fixture.rt = ok(`{"action":"allow"}`)
	assertForeignHookDenied(t, fixture.run(t, "preToolUse", func(opts *Options) {
		opts.ApprovedForeignHooks = []string{digest}
	}), hiddenHooks)
}

func TestCursorForeignHookGuardFailsClosedOnUnverifiablePluginTrees(t *testing.T) {
	for name, prepare := range map[string]func(t *testing.T, plugins string) (string, string){
		"invalid manifest": func(t *testing.T, plugins string) (string, string) {
			path := filepath.Join(plugins, "local", "p", ".cursor-plugin", "plugin.json")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(`{"name": "p", "hooks": `), 0o600); err != nil {
				t.Fatal(err)
			}
			return path, "not valid JSON"
		},
		"manifest hooks of another type": func(t *testing.T, plugins string) (string, string) {
			plugin := filepath.Join(plugins, "local", "p")
			writeCursorPluginManifest(t, plugin, map[string]interface{}{"name": "p", "hooks": 7})
			return filepath.Join(plugin, ".cursor-plugin", "plugin.json"), "not a path or an object"
		},
		"invalid marketplace manifest": func(t *testing.T, plugins string) (string, string) {
			path := filepath.Join(plugins, "marketplaces", "acme", ".cursor-plugin", "marketplace.json")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(`{"name": "acme", "plugins": [`), 0o600); err != nil {
				t.Fatal(err)
			}
			return path, "not valid JSON"
		},
		"marketplace plugins of another type": func(t *testing.T, plugins string) (string, string) {
			path := filepath.Join(plugins, "marketplaces", "acme", ".cursor-plugin", "marketplace.json")
			writeForeignHookJSON(t, path, map[string]interface{}{
				"name":    "acme",
				"plugins": map[string]interface{}{"foo": map[string]interface{}{"hooks": "hooks.json"}},
			})
			return path, "plugins value is not an array"
		},
		"marketplace entry hooks of another type": func(t *testing.T, plugins string) (string, string) {
			path := filepath.Join(plugins, "marketplaces", "acme", ".cursor-plugin", "marketplace.json")
			writeForeignHookJSON(t, path, map[string]interface{}{
				"name":    "acme",
				"plugins": []interface{}{map[string]interface{}{"name": "foo", "source": "foo", "hooks": true}},
			})
			return path, `plugin entry \"foo\" hooks value is not a path or an object`
		},
		"marketplace hooks path for a remote source": func(t *testing.T, plugins string) (string, string) {
			path := filepath.Join(plugins, "marketplaces", "acme", ".cursor-plugin", "marketplace.json")
			writeForeignHookJSON(t, path, map[string]interface{}{
				"name": "acme",
				"plugins": []interface{}{map[string]interface{}{
					"name": "foo", "source": map[string]interface{}{"source": "github", "repo": "acme/foo"}, "hooks": "hooks.json",
				}},
			})
			return path, "source is not a local folder"
		},
		"marketplace inline hooks that cannot be read": func(t *testing.T, plugins string) (string, string) {
			path := filepath.Join(plugins, "marketplaces", "acme", ".cursor-plugin", "marketplace.json")
			writeForeignHookJSON(t, path, map[string]interface{}{
				"name": "acme",
				"plugins": []interface{}{map[string]interface{}{
					"name": "foo", "source": "foo", "hooks": map[string]interface{}{"preToolUse": "not a list"},
				}},
			})
			return path, "inline hooks"
		},
		"too many folders": func(t *testing.T, plugins string) (string, string) {
			for index := 0; index <= foreignHookPluginMaxDirs; index++ {
				if err := os.MkdirAll(filepath.Join(plugins, "cache", strconv.Itoa(index)), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			return plugins, "more than"
		},
		"linked plugin folder": func(t *testing.T, plugins string) (string, string) {
			target := filepath.Join(filepath.Dir(plugins), "elsewhere")
			writeCursorPluginManifest(t, target, map[string]interface{}{"name": "p"})
			writeForeignHookJSON(t, filepath.Join(target, "hooks", "hooks.json"), rewritingCursorHooks("./rewrite.sh"))
			link := filepath.Join(plugins, "local", "p")
			if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, link); err != nil {
				if runtime.GOOS == "windows" {
					t.Skipf("symlink creation needs privileges on Windows: %v", err)
				}
				t.Fatal(err)
			}
			return link, "link"
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newForeignHookFixture(t)
			path, detail := prepare(t, filepath.Join(fixture.profile, ".cursor", "plugins"))
			result := fixture.run(t, "preToolUse", nil)
			assertForeignHookDenied(t, result, path)
			if !strings.Contains(result.stdout, "cannot be verified") || !strings.Contains(result.stdout, detail) {
				t.Fatalf("unverifiable plugin source message = %s", result.stdout)
			}
		})
	}
}

// Depth alone does not make a plugin tree unverifiable: an installed plugin
// (cache/<marketplace>/<plugin>/<version>) with a deep source or skill folder
// is walked to the bottom within the folder bound, and a hooks file at any
// depth is still found.
func TestCursorForeignHookGuardWalksDeepPluginFolders(t *testing.T) {
	deepFolder := func(plugins string) string {
		parts := []string{plugins, "cache", "acme", "p", "1.2.0", "skills", "s"}
		for level := 0; level < 8; level++ {
			parts = append(parts, "d"+strconv.Itoa(level))
		}
		return filepath.Join(parts...)
	}

	fixture := newForeignHookFixture(t)
	deep := deepFolder(filepath.Join(fixture.profile, ".cursor", "plugins"))
	writeCursorPluginManifest(t, filepath.Join(fixture.profile, ".cursor", "plugins", "cache", "acme", "p", "1.2.0"),
		map[string]interface{}{"name": "p"})
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "notes.md"), []byte("notes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if result := fixture.run(t, "preToolUse", nil); result.rt.requests != 1 {
		t.Fatalf("a deep plugin folder without hooks was denied: %s", result.stdout)
	}

	hooks := filepath.Join(deep, "hooks", "hooks.json")
	writeForeignHookJSON(t, hooks, rewritingCursorHooks("./rewrite.sh"))
	result := fixture.withGateway().run(t, "preToolUse", nil)
	assertForeignHookDenied(t, result, hooks)
	if !strings.Contains(result.stdout, "plugin-level hook file") || !strings.Contains(result.stdout, "registers a preToolUse hook") {
		t.Fatalf("a deep plugin hooks file was not reported as a handler: %s", result.stdout)
	}
}

func symlinkForTest(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink creation needs privileges on Windows: %v", err)
		}
		t.Fatal(err)
	}
}

// A link inside a plugin that resolves to a file under a name Cursor never
// loads hooks from (CLAUDE.md linked to AGENTS.md, a script alias) holds no
// hooks and does not deny. A link that resolves to a folder, cannot be
// resolved, or stands in for a hooks folder, a hooks/hooks.json file or a
// .cursor-plugin folder still cannot be verified.
func TestCursorForeignHookGuardIgnoresPluginLinksToFiles(t *testing.T) {
	fixture := newForeignHookFixture(t)
	plugin := filepath.Join(fixture.profile, ".cursor", "plugins", "local", "p")
	writeCursorPluginManifest(t, plugin, map[string]interface{}{"name": "p"})
	if err := os.WriteFile(filepath.Join(plugin, "AGENTS.md"), []byte("# Agents"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkForTest(t, "AGENTS.md", filepath.Join(plugin, "CLAUDE.md"))
	symlinkForTest(t, filepath.Join("..", "AGENTS.md"), filepath.Join(plugin, "scripts", "README.md"))
	if result := fixture.run(t, "preToolUse", nil); result.rt.requests != 1 {
		t.Fatalf("links to files inside a plugin were denied: %s", result.stdout)
	}

	for name, prepare := range map[string]func(t *testing.T, plugin string) string{
		"link to a folder": func(t *testing.T, plugin string) string {
			target := filepath.Join(filepath.Dir(plugin), "..", "..", "..", "elsewhere")
			writeForeignHookJSON(t, filepath.Join(target, "hooks", "hooks.json"), rewritingCursorHooks("./rewrite.sh"))
			link := filepath.Join(plugin, "vendor")
			symlinkForTest(t, target, link)
			return link
		},
		// Created before its target exists, so on Windows this is a file
		// symbolic link; Windows still opens paths through it.
		"file link that now points at a folder": func(t *testing.T, plugin string) string {
			target := filepath.Join(filepath.Dir(plugin), "..", "..", "..", "later")
			link := filepath.Join(plugin, "later")
			symlinkForTest(t, target, link)
			writeForeignHookJSON(t, filepath.Join(target, "hooks", "hooks.json"), rewritingCursorHooks("./rewrite.sh"))
			return link
		},
		"link that cannot be resolved": func(t *testing.T, plugin string) string {
			link := filepath.Join(plugin, "missing")
			symlinkForTest(t, filepath.Join(plugin, "does-not-exist"), link)
			return link
		},
		"hooks.json link": func(t *testing.T, plugin string) string {
			target := filepath.Join(plugin, "real-hooks.json")
			writeForeignHookJSON(t, target, rewritingCursorHooks("./rewrite.sh"))
			link := filepath.Join(plugin, "hooks", "hooks.json")
			symlinkForTest(t, target, link)
			return link
		},
		"hooks folder link to a file": func(t *testing.T, plugin string) string {
			target := filepath.Join(plugin, "notes.txt")
			if err := os.WriteFile(target, []byte("notes"), 0o600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(plugin, "hooks")
			symlinkForTest(t, target, link)
			return link
		},
		"plugin metadata link to a file": func(t *testing.T, plugin string) string {
			target := filepath.Join(plugin, "plugin.json")
			writeForeignHookJSON(t, target, map[string]interface{}{"name": "p", "hooks": rewritingCursorHooks("./rewrite.sh")})
			link := filepath.Join(plugin, ".cursor-plugin")
			symlinkForTest(t, target, link)
			return link
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newForeignHookFixture(t)
			plugin := filepath.Join(fixture.profile, ".cursor", "plugins", "local", "p")
			if err := os.MkdirAll(plugin, 0o700); err != nil {
				t.Fatal(err)
			}
			link := prepare(t, plugin)
			result := fixture.run(t, "preToolUse", nil)
			assertForeignHookDenied(t, result, link)
			if !strings.Contains(result.stdout, "cannot be verified") || !strings.Contains(result.stdout, "link or reparse point") {
				t.Fatalf("unverifiable link message = %s", result.stdout)
			}
		})
	}
}

// A file loaded from two scopes needs an approval in each: a plugin manifest
// that points at the user's hooks file registers the handler as a plugin hook
// too.
func TestCursorForeignHookGuardScansSharedFilesOncePerScope(t *testing.T) {
	fixture := newForeignHookFixture(t)
	handler := map[string]interface{}{"command": "./rewrite.sh"}
	userHooks := filepath.Join(fixture.profile, ".cursor", "hooks.json")
	writeForeignHookJSON(t, userHooks, map[string]interface{}{
		"hooks": map[string]interface{}{"preToolUse": []interface{}{handler}},
	})
	writeCursorPluginManifest(t, filepath.Join(fixture.profile, ".cursor", "plugins", "local", "p"), map[string]interface{}{
		"name":  "p",
		"hooks": userHooks,
	})
	userDigest, err := foreignHookApprovalDigest(foreignHookScopeUser, "preToolUse", handler)
	if err != nil {
		t.Fatal(err)
	}
	result := fixture.run(t, "preToolUse", func(opts *Options) { opts.ApprovedForeignHooks = []string{userDigest} })
	assertForeignHookDenied(t, result, userHooks)
	if !strings.Contains(result.stdout, "plugin-level hook file") {
		t.Fatalf("shared file was not scanned in the plugin scope: %s", result.stdout)
	}
	pluginDigest, err := foreignHookApprovalDigest(foreignHookScopePlugin, "preToolUse", handler)
	if err != nil {
		t.Fatal(err)
	}
	fixture.rt = ok(`{"action":"allow"}`)
	result = fixture.run(t, "preToolUse", func(opts *Options) {
		opts.ApprovedForeignHooks = []string{userDigest, pluginDigest}
	})
	if result.rt.requests != 1 {
		t.Fatalf("file approved in both scopes was denied: %s", result.stdout)
	}
}

// A workspaceOpen handler can return pluginPaths that load plugins, and so
// their hooks, from any folder; it is gated like a preToolUse handler.
func TestCursorForeignHookGuardGatesWorkspaceOpenHandlers(t *testing.T) {
	fixture := newForeignHookFixture(t)
	loader := map[string]interface{}{"command": "./load-plugins.sh"}
	userHooks := filepath.Join(fixture.profile, ".cursor", "hooks.json")
	writeForeignHookJSON(t, userHooks, map[string]interface{}{
		"version": 1,
		"hooks":   map[string]interface{}{"workspaceOpen": []interface{}{loader}},
	})
	result := fixture.run(t, "preToolUse", nil)
	assertForeignHookDenied(t, result, userHooks)
	if !strings.Contains(result.stdout, "registers a workspaceOpen hook") {
		t.Fatalf("denial does not name the workspaceOpen event: %s", result.stdout)
	}
	digest, err := foreignHookApprovalDigest(foreignHookScopeUser, "workspaceOpen", loader)
	if err != nil {
		t.Fatal(err)
	}
	approve := func(opts *Options) { opts.ApprovedForeignHooks = []string{digest} }
	fixture.rt = ok(`{"action":"allow"}`)
	if result := fixture.run(t, "preToolUse", approve); result.rt.requests != 1 {
		t.Fatalf("approved workspaceOpen handler denied: %s", result.stdout)
	}
	projectHooks := filepath.Join(fixture.workspace, ".cursor", "hooks.json")
	writeForeignHookJSON(t, projectHooks, map[string]interface{}{
		"hooks": map[string]interface{}{"WorkspaceOpen": []interface{}{loader}},
	})
	fixture.rt = ok(`{"action":"allow"}`)
	assertForeignHookDenied(t, fixture.run(t, "preToolUse", approve), projectHooks)
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

func fileURIForTest(path string) string {
	slashed := filepath.ToSlash(path)
	if !strings.HasPrefix(slashed, "/") {
		slashed = "/" + slashed
	}
	return "file://" + slashed
}

func cursorPayloadForTest(body map[string]interface{}) []byte {
	payload := map[string]interface{}{
		"hook_event_name": "preToolUse",
		"cursor_version":  "3.9.0",
		"tool_name":       "Shell",
		"tool_input":      map[string]interface{}{"command": "echo ORIGINAL"},
	}
	for key, value := range body {
		payload[key] = value
	}
	encoded, _ := json.Marshal(payload)
	return encoded
}

func TestCursorPayloadWorkspaceRootsNormalization(t *testing.T) {
	absolute := filepath.Join(t.TempDir(), "repo")
	other := filepath.Join(filepath.Dir(absolute), "other")
	payload, _ := json.Marshal(map[string]interface{}{
		"workspace_roots": []interface{}{absolute, "", fileURIForTest(absolute), nil, other},
		"cwd":             other,
	})
	roots, problem := cursorPayloadWorkspaceRoots(payload)
	if problem != "" {
		t.Fatalf("valid roots reported a problem: %s", problem)
	}
	if len(roots) != 2 || roots[0] != absolute || roots[1] != other {
		t.Fatalf("roots = %v, want the de-duplicated [%s %s]", roots, absolute, other)
	}
	// No folder open: Cursor reports an empty list.
	if roots, problem := cursorPayloadWorkspaceRoots([]byte(`{"workspace_roots":[],"cwd":null}`)); problem != "" || len(roots) != 0 {
		t.Fatalf("empty roots = (%v, %q), want none and no problem", roots, problem)
	}
	// workspace_roots is a base field of every Cursor hook call; without it
	// the project hooks that apply are unknown.
	for _, payload := range []string{`{"workspace_roots":null,"cwd":null}`, `{}`, `null`, `{"cwd":"/repo"}`} {
		if roots, problem := cursorPayloadWorkspaceRoots([]byte(payload)); !strings.Contains(problem, "workspace_roots") || roots != nil {
			t.Fatalf("payload %s = (%v, %q), want a workspace_roots problem", payload, roots, problem)
		}
	}
	for _, payload := range []string{`[1]`, `"x"`, `{"workspace_roots":`} {
		if _, problem := cursorPayloadWorkspaceRoots([]byte(payload)); problem == "" {
			t.Fatalf("payload %s is not an object but reported no problem", payload)
		}
	}
	if runtime.GOOS == "windows" {
		if root, ok := normalizeCursorWorkspaceRoot("/c:/Users/dev/repo"); !ok || root != `c:\Users\dev\repo` {
			t.Fatalf("URI-style Windows root = (%q, %v)", root, ok)
		}
		if root, ok := normalizeCursorWorkspaceRoot("file://build01/share/repo"); !ok || root != `\\build01\share\repo` {
			t.Fatalf("UNC file URI root = (%q, %v)", root, ok)
		}
		if _, ok := normalizeCursorWorkspaceRoot("/share/repo"); ok {
			t.Fatal("drive-less rooted Windows path accepted as a local absolute root")
		}
	} else if _, ok := normalizeCursorWorkspaceRoot("file://build01/share/repo"); ok {
		t.Fatal("file URI with a remote host accepted")
	}

	// Duplicates count once toward the bound.
	duplicates := make([]string, 3*foreignHookMaxRoots)
	for index := range duplicates {
		duplicates[index] = absolute
	}
	payload, _ = json.Marshal(map[string]interface{}{"workspace_roots": duplicates, "cwd": absolute})
	if roots, problem := cursorPayloadWorkspaceRoots(payload); problem != "" || len(roots) != 1 {
		t.Fatalf("duplicate roots = (%v, %q), want one root", roots, problem)
	}
	distinct := make([]string, foreignHookMaxRoots)
	for index := range distinct {
		distinct[index] = filepath.Join(absolute, "r", strconv.Itoa(index))
	}
	payload, _ = json.Marshal(map[string]interface{}{"workspace_roots": distinct})
	if roots, problem := cursorPayloadWorkspaceRoots(payload); problem != "" || len(roots) != foreignHookMaxRoots {
		t.Fatalf("%d distinct roots = (%d roots, %q), want all of them", foreignHookMaxRoots, len(roots), problem)
	}
	payload, _ = json.Marshal(map[string]interface{}{"workspace_roots": distinct, "cwd": other})
	if roots, problem := cursorPayloadWorkspaceRoots(payload); problem == "" || roots != nil {
		t.Fatalf("roots past the bound = (%d roots, %q), want a problem instead of a truncated list", len(roots), problem)
	}
}

// Roots the guard cannot scan must deny instead of narrowing the scan: a
// 33rd folder (or cwd past the bound) may hold the rewriting hook.
func TestCursorForeignHookGuardDeniesUnverifiableWorkspaceRoots(t *testing.T) {
	fixture := newForeignHookFixture(t)
	roots := make([]string, 0, foreignHookMaxRoots)
	for index := 0; index < foreignHookMaxRoots; index++ {
		dir := filepath.Join(fixture.workspace, "empty", strconv.Itoa(index))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		roots = append(roots, dir)
	}
	rewriter := filepath.Join(fixture.workspace, "rewriter")
	writeForeignHookJSON(t, filepath.Join(rewriter, ".cursor", "hooks.json"), rewritingCursorHooks("rewrite"))
	withRewriter := append(append([]string(nil), roots...), rewriter)
	for name, body := range map[string]map[string]interface{}{
		"more roots than the bound":     {"workspace_roots": withRewriter},
		"cwd past the bound":            {"workspace_roots": roots, "cwd": rewriter},
		"relative root":                 {"workspace_roots": []interface{}{"relative/repo"}},
		"remote root":                   {"workspace_roots": []interface{}{"vscode-remote://ssh-remote+build01/home/dev/repo"}},
		"non-string root":               {"workspace_roots": []interface{}{fixture.workspace, 7}},
		"roots not an array":            {"workspace_roots": fixture.workspace},
		"relative cwd":                  {"workspace_roots": []interface{}{fixture.workspace}, "cwd": "repo"},
		"remote host file URI on POSIX": {"workspace_roots": []interface{}{"file://build01/share/repo"}},
		// Cursor sends workspace_roots with every hook call.
		"missing workspace_roots":             {"cwd": rewriter},
		"null workspace_roots":                {"workspace_roots": nil, "cwd": rewriter},
		"neither workspace_roots nor cwd set": {},
	} {
		if name == "remote host file URI on POSIX" && runtime.GOOS == "windows" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			result := fixture.withGateway().run(t, "preToolUse", func(opts *Options) {
				opts.Stdin = bytes.NewReader(cursorPayloadForTest(body))
			})
			assertForeignHookDenied(t, result, "")
			if !strings.Contains(result.stdout, "workspace folders Cursor reported cannot be verified") {
				t.Fatalf("root problem message = %s", result.stdout)
			}
		})
	}
	// The rewriter is found when it is inside the bound.
	result := fixture.withGateway().run(t, "preToolUse", func(opts *Options) {
		opts.Stdin = bytes.NewReader(cursorPayloadForTest(map[string]interface{}{
			"workspace_roots": withRewriter[1:],
		}))
	})
	assertForeignHookDenied(t, result, filepath.Join(rewriter, ".cursor", "hooks.json"))
	// Repeated roots are one folder.
	duplicates := make([]string, 3*foreignHookMaxRoots)
	for index := range duplicates {
		duplicates[index] = roots[0]
	}
	result = fixture.withGateway().run(t, "preToolUse", func(opts *Options) {
		opts.Stdin = bytes.NewReader(cursorPayloadForTest(map[string]interface{}{
			"workspace_roots": duplicates,
			"cwd":             roots[0],
		}))
	})
	if result.rt.requests != 1 {
		t.Fatalf("duplicate roots: gateway requests = %d, want 1; stdout=%s", result.rt.requests, result.stdout)
	}
	// With no folder open Cursor reports an empty list, and only the user and
	// plugin hooks apply.
	result = fixture.withGateway().run(t, "preToolUse", func(opts *Options) {
		opts.Stdin = bytes.NewReader(cursorPayloadForTest(map[string]interface{}{"workspace_roots": []interface{}{}}))
	})
	if result.rt.requests != 1 {
		t.Fatalf("empty workspace: gateway requests = %d, want 1; stdout=%s", result.rt.requests, result.stdout)
	}
}

func TestCursorForeignHookGuardRereadsChangedHookFiles(t *testing.T) {
	fixture := newForeignHookFixture(t)
	path := filepath.Join(fixture.workspace, ".cursor", "hooks.json")
	writeForeignHookJSON(t, path, map[string]interface{}{"hooks": map[string]interface{}{}})
	if result := fixture.run(t, "preToolUse", nil); result.rt.requests != 1 {
		t.Fatalf("clean file blocked: %s", result.stdout)
	}
	// Rewriting the same path must be re-read and re-parsed, never served
	// from an earlier "clean" result.
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
