// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The sandbox ingress fixture and the Hermes helpers are POSIX-only; the
// reduction itself is platform-neutral and is pinned on every OS by the
// actionfacts over-limit tests.

//go:build !windows

package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// overLimitWriteText is written text over the 64 KiB string limit, and
// overArgsLimitText over the 256 KiB argument limit: either leaves the call
// limit-exceeded. Most rows use the smaller one; a hook call of this size
// takes seconds under the race detector.
var (
	overLimitWriteText = strings.Repeat("# k\n", 17000)
	overArgsLimitText  = strings.Repeat("# k\n", 70000)
)

// overLimitNativeWriteCalls are native file-write tool calls whose
// arguments are over the argument limit, in each harness's shape.
func overLimitNativeWriteCalls() []nativeWriteCall {
	return []nativeWriteCall{
		{"claudecode", "Write", func(p string) map[string]any { return map[string]any{"file_path": p, "content": overLimitWriteText} }},
		{"claudecode", "Write", func(p string) map[string]any {
			return map[string]any{"file_path": p, "content": overArgsLimitText}
		}},
		{"claudecode", "Edit", func(p string) map[string]any {
			return map[string]any{"file_path": p, "old_string": "# base", "new_string": overLimitWriteText}
		}},
		{"claudecode", "MultiEdit", func(p string) map[string]any {
			return map[string]any{"file_path": p, "edits": []any{map[string]any{"old_string": "# base", "new_string": overLimitWriteText}}}
		}},
		{"opencode", "write", func(p string) map[string]any { return map[string]any{"filePath": p, "content": overLimitWriteText} }},
		{"opencode", "edit", func(p string) map[string]any {
			return map[string]any{"filePath": p, "oldString": "# base", "newString": overLimitWriteText}
		}},
		{"codex", "apply_patch", func(p string) map[string]any {
			return map[string]any{"command": "*** Begin Patch\n*** Update File: " + p + "\n@@\n # base\n" +
				strings.Repeat("+# k\n", 54000) + "*** End Patch\n"}
		}},
		{"copilot", "create", func(p string) map[string]any { return map[string]any{"path": p, "file_text": overLimitWriteText} }},
	}
}

// overLimitHermesCalls are Hermes write_file and patch (replace) calls over
// the argument limit.
func overLimitHermesCalls() []hermesPatchCall {
	return []hermesPatchCall{
		{"write-file", "write_file", func(p string) map[string]any { return map[string]any{"path": p, "content": overLimitWriteText} }},
		{"replace", "patch", func(p string) map[string]any {
			return map[string]any{"path": p, "old_string": "# base", "new_string": overLimitWriteText}
		}},
	}
}

// A hook call of this size takes about a second, and twenty under the race
// detector, so the tables judge every tool on the protected file and only
// some on a project file (they share one reduction per argument shape), and
// the sandbox table judges Claude Code Write, OpenCode write, Codex
// apply_patch and both Hermes tools.
var (
	overLimitHostBenign    = map[string]bool{"claudecode-Write-0": true, "opencode-write-4": true, "codex-apply_patch-6": true, "hermes-write-file": true}
	overLimitSandboxRows   = map[string]bool{"claudecode-Write-0": true, "opencode-write-4": true, "codex-apply_patch-6": true, "hermes-write-file": true, "hermes-replace": true}
	overLimitSandboxBenign = map[string]bool{"claudecode-Write-0": true, "hermes-write-file": true}
)

// overLimitRow reports whether the table has the row of call name for
// a protected target (want) or a project file.
func overLimitRow(benign map[string]bool, name string, want bool) bool { return want || benign[name] }

// overLimitNotUnverified fails a row whose verdict is the conservative block
// of a call whose targets cannot be read: a row whose targets the reduction
// reads is judged by the rules themselves, and that block would hide a
// broken reduction.
func overLimitNotUnverified(t *testing.T, got string) {
	t.Helper()
	if strings.Contains(got, overLimitUnverifiedWriteTitle) {
		t.Fatalf("conservative block of an unread target, not the rule verdict: %.600s", got)
	}
}

func overLimitHostHook(t *testing.T, connector, home, body string) string {
	t.Helper()
	return overLimitHostHookWithEvidence(t, connector, home, body,
		hookpaths.ResolveConnector(connector, "", "preToolUse", []byte(body)))
}

// overLimitHostHookWithEvidence is overLimitHostHook with the hook client's
// write evidence computed by the caller.
func overLimitHostHookWithEvidence(t *testing.T, connector, home, body, evidence string) string {
	t.Helper()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+connector+"/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hookpaths.Header, evidence)
	switch connector {
	case "codex":
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	case "copilot":
		req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
	}
	req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connector).ServeHTTP(recorder, req)
	return recorder.Body.String()
}

// TestOverLimitNativeWritesOfAuthorizedKeysAreBlockedOnTheHost pins that a
// native file-write tool call naming ~/.ssh/authorized_keys is blocked by
// the SSH persistence rule when its arguments are over the argument limit,
// and that the same call writing a project file stays allowed. The
// limit-exceeded arguments named no write target, so the call was allowed
// with no rule (GAP-0674).
func TestOverLimitNativeWritesOfAuthorizedKeysAreBlockedOnTheHost(t *testing.T) {
	home, project := hermesPatchHome(t)
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	targets := map[string]bool{keys: true, filepath.Join(project, "big.json"): false}
	for i, call := range overLimitNativeWriteCalls() {
		for target, want := range targets {
			if !overLimitRow(overLimitHostBenign, call.name(i), want) {
				continue
			}
			t.Run(fmt.Sprintf("%s/block=%t", call.name(i), want), func(t *testing.T) {
				got := overLimitHostHook(t, call.connector, home, call.body(t, project, target))
				if blocked := nativeWriteBlocked(t, got); blocked != want {
					t.Fatalf("blocked = %t, want %t: %.600s", blocked, want, got)
				}
				overLimitNotUnverified(t, got)
			})
		}
	}
	for _, call := range overLimitHermesCalls() {
		for target, want := range targets {
			if !overLimitRow(overLimitHostBenign, "hermes-"+call.name, want) {
				continue
			}
			t.Run(fmt.Sprintf("hermes-%s/block=%t", call.name, want), func(t *testing.T) {
				got := hermesPatchHostHook(t, home, project, hermesPatchBody(t, project, call.tool, call.args(target)))
				if blocked := hermesPatchVerdict(t, got); blocked != want {
					t.Fatalf("blocked = %t, want %t: %.600s", blocked, want, got)
				}
				overLimitNotUnverified(t, got)
			})
		}
	}
}

// overLimitProtectHomeRows are the rows of the ProtectHome table: the write
// tools of each connector on the link, and two of them on a project file.
var overLimitProtectHomeRows = map[string]bool{
	"claudecode-Write-0": true, "claudecode-Edit-2": true, "opencode-write-4": true,
	"codex-apply_patch-6": true, "copilot-create-7": true,
}

// TestOverLimitNativeWritesThroughAHomeSymlinkUnderProtectHome pins the
// reduced call's write evidence on a managed gateway that cannot look into
// the user's home (ProtectHome; the mode-zero parent stands in for it): a
// native write tool call over the argument limit to a project symlink to
// ~/.ssh/authorized_keys is blocked by the SSH persistence rule, and the
// same call to an ordinary project file stays allowed. The hook client
// listed no target of the reduced call and the gateway dropped the
// truncation marker that said so, so the write through the link was
// allowed with no rule.
func TestOverLimitNativeWritesThroughAHomeSymlinkUnderProtectHome(t *testing.T) {
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
	notes := filepath.Join(project, "big.json")
	for _, file := range []string{keys, notes} {
		if err := os.WriteFile(file, []byte("# base\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(project, "deploy.cfg")
	if err := os.Symlink(keys, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	for i, call := range overLimitNativeWriteCalls() {
		if !overLimitProtectHomeRows[call.name(i)] {
			continue
		}
		for target, want := range map[string]bool{link: true, notes: false} {
			if !overLimitRow(overLimitHostBenign, call.name(i), want) {
				continue
			}
			t.Run(fmt.Sprintf("%s/block=%t", call.name(i), want), func(t *testing.T) {
				if err := os.Chmod(homes, 0o700); err != nil {
					t.Fatal(err)
				}
				body := call.body(t, project, target)
				evidence := hookpaths.ResolveConnector(call.connector, "", "preToolUse", []byte(body))
				if err := os.Chmod(homes, 0); err != nil {
					t.Fatal(err)
				}
				got := overLimitHostHookWithEvidence(t, call.connector, home, body, evidence)
				if blocked := nativeWriteBlocked(t, got); blocked != want {
					t.Fatalf("blocked = %t, want %t: %.600s", blocked, want, got)
				}
				overLimitNotUnverified(t, got)
			})
		}
	}
}

// TestOverLimitNativeWritesOfAuthorizedKeysAreBlockedInASandbox is the same
// table through the authenticated sandbox ingress, with the guest home.
func TestOverLimitNativeWritesOfAuthorizedKeysAreBlockedInASandbox(t *testing.T) {
	f := newSandboxIngressFixture(t)
	versions := map[string][3]string{
		"opencode":   {"1.18.10", "opencode-hooks-v1", "/api/v1/opencode/hook"},
		"claudecode": {"2.1.156", "claudecode-hooks-v1", "/api/v1/claude-code/hook"},
		"codex":      {"0.128.0", "codex-hooks-v1", "/api/v1/codex/hook"},
		"copilot":    {"1.0.40", "copilot-hooks-v1", "/api/v1/copilot/hook"},
	}
	keys := sandboxauth.SandboxHome + "/.ssh/authorized_keys"
	targets := map[string]bool{keys: true, "/work/app/big.json": false}
	for i, call := range overLimitNativeWriteCalls() {
		if !overLimitSandboxRows[call.name(i)] {
			continue
		}
		v := versions[call.connector]
		var headers []string
		switch call.connector {
		case "codex":
			headers = []string{"X-DefenseClaw-Hook-Event", "PreToolUse", "X-DefenseClaw-Hook-Contract", v[1]}
		case "copilot":
			headers = []string{"X-DefenseClaw-Copilot-Event", "preToolUse"}
		}
		for target, want := range targets {
			if !overLimitRow(overLimitSandboxBenign, call.name(i), want) {
				continue
			}
			t.Run(fmt.Sprintf("%s/block=%t", call.name(i), want), func(t *testing.T) {
				_, token := f.mint(t, fmt.Sprintf("dc-ol-%s-%t", call.name(i), want), call.connector, v[0], v[1], f.project)
				resp := f.hook(t, v[2], token, call.body(t, "/work/app", target), headers...)
				raw, _ := json.Marshal(resp)
				if got := nativeWriteBlocked(t, string(raw)); got != want {
					t.Fatalf("blocked = %t, want %t: %.600s", got, want, raw)
				}
				overLimitNotUnverified(t, string(raw))
			})
		}
	}
	for _, call := range overLimitHermesCalls() {
		for target, want := range targets {
			if !overLimitSandboxRows["hermes-"+call.name] || !overLimitRow(overLimitSandboxBenign, "hermes-"+call.name, want) {
				continue
			}
			t.Run(fmt.Sprintf("hermes-%s/block=%t", call.name, want), func(t *testing.T) {
				_, token := f.mint(t, fmt.Sprintf("dc-ol-hermes-%s-%t", call.name, want), "hermes", "0.19.0", "hermes-hooks-v1", f.project)
				resp := f.hook(t, "/api/v1/hermes/hook", token, hermesPatchBody(t, "/work/app", call.tool, call.args(target)))
				raw, _ := json.Marshal(resp)
				if got := hermesPatchVerdict(t, string(raw)); got != want {
					t.Fatalf("blocked = %t, want %t: %.600s", got, want, raw)
				}
				overLimitNotUnverified(t, string(raw))
			})
		}
	}
}

// TestOverLimitWriteToolCallsWithUnreadableTargets pins the conservative
// block of an over-limit write tool call whose targets cannot be read, with
// its reason, and that an over-limit call of a tool that writes no file
// keeps the limit-exceeded result (allowed).
func TestOverLimitWriteToolCallsWithUnreadableTargets(t *testing.T) {
	home, project := hermesPatchHome(t)
	body := func(tool string, args map[string]any) string {
		return string(mustJSON(t, map[string]any{"hook_event_name": "PreToolUse", "session_id": "s-ol-" + tool, "turn_id": "t1",
			"cwd": project, "tool_name": tool, "tool_input": args, "tool_use_id": "u1"}))
	}
	big := filepath.Join(project, "big.json")
	for name, args := range map[string]map[string]any{
		"unknown key":       {"file_path": big, "content": overLimitWriteText, "mode": "x"},
		"large unknown key": {"file_path": big, "notes": overLimitWriteText},
		"content not text":  {"file_path": big, "content": []any{overLimitWriteText}},
	} {
		t.Run(name, func(t *testing.T) {
			got := overLimitHostHook(t, "claudecode", home, body("Write", args))
			if !nativeWriteBlocked(t, got) || !strings.Contains(got, overLimitUnverifiedWriteTitle) {
				t.Fatalf("verdict = %.600s", got)
			}
		})
	}
	for name, call := range map[string][2]any{
		"grep": {"Grep", map[string]any{"pattern": overLimitWriteText, "path": project}},
		"read": {"Read", map[string]any{"file_path": big, "pages": overLimitWriteText}},
	} {
		t.Run(name, func(t *testing.T) {
			got := overLimitHostHook(t, "claudecode", home, body(call[0].(string), call[1].(map[string]any)))
			if nativeWriteBlocked(t, got) {
				t.Fatalf("blocked: %.600s", got)
			}
		})
	}
}

// overLimitPathRuleRows are the protected targets of
// TestOverLimitNativeWritesKeepTheirPathRules, with the rule and the action
// of the same call under the limit.
func overLimitPathRuleRows(home string) []struct{ target, rule, action string } {
	return []struct{ target, rule, action string }{
		{"/etc/shadow", "PATH-ETC-SHADOW", "block"},
		{filepath.Join(home, ".ssh", "id_ed25519"), "PATH-SSH-DIR", "alert"},
	}
}

func overLimitHookAction(t *testing.T, got string) string {
	t.Helper()
	var resp map[string]any
	if err := json.Unmarshal([]byte(got), &resp); err != nil {
		t.Fatalf("verdict %q: %v", got, err)
	}
	action, _ := resp["action"].(string)
	return action
}

// TestOverLimitNativeWritesKeepTheirPathRules pins that the path rules judge
// the target of a write tool call over the argument limit as they judge the
// same call under it: Claude Code Write, OpenCode write and Hermes
// write_file of /etc/shadow are blocked by PATH-ETC-SHADOW and of an SSH
// private key alert with PATH-SSH-DIR, and a project file whose large text
// names those paths stays allowed with neither rule. Over the limit, the
// recovery lanes and the context checks read facts that name no target, so
// those calls were allowed with no rule (GAP-0674).
func TestOverLimitNativeWritesKeepTheirPathRules(t *testing.T) {
	home, project := hermesPatchHome(t)
	shapes := map[string]func(target string) string{}
	for i, call := range overLimitNativeWriteCalls() {
		if name := call.name(i); name == "claudecode-Write-0" || name == "opencode-write-4" {
			shapes[name] = func(target string) string {
				return overLimitHostHook(t, call.connector, home, call.body(t, project, target))
			}
		}
	}
	writeFile := overLimitHermesCalls()[0]
	shapes["hermes-"+writeFile.name] = func(target string) string {
		return hermesPatchHostHook(t, home, project, hermesPatchBody(t, project, writeFile.tool, writeFile.args(target)))
	}
	if len(shapes) != 3 {
		t.Fatalf("shapes = %d, want 3", len(shapes))
	}
	for name, hook := range shapes {
		for _, row := range overLimitPathRuleRows(home) {
			t.Run(name+"/"+filepath.Base(row.target), func(t *testing.T) {
				got := hook(row.target)
				if action := overLimitHookAction(t, got); action != row.action || !strings.Contains(got, row.rule) {
					t.Fatalf("action = %q, want %q with %s: %.600s", action, row.action, row.rule, got)
				}
				overLimitNotUnverified(t, got)
			})
		}
	}
	t.Run("project doc naming protected paths", func(t *testing.T) {
		doc := "see /etc/shadow, ~/.ssh/authorized_keys and ~/.ssh/id_ed25519\n" + overLimitWriteText
		call := nativeWriteCall{"claudecode", "Write", func(p string) map[string]any { return map[string]any{"file_path": p, "content": doc} }}
		got := overLimitHostHook(t, call.connector, home, call.body(t, project, filepath.Join(project, "docs", "notes.md")))
		if action := overLimitHookAction(t, got); action != "allow" ||
			strings.Contains(got, "PATH-ETC-SHADOW") || strings.Contains(got, "PATH-SSH-DIR") {
			t.Fatalf("action = %q: %.600s", action, got)
		}
	})
}

// TestOverLimitWriteTargetsInTheTrustedFallback pins the same judgement in
// dispatchTrustedFallback, which judges an over-limit write tool call whose
// view cannot be projected or whose rule generation has no semantic rules.
func TestOverLimitWriteTargetsInTheTrustedFallback(t *testing.T) {
	home, project := hermesPatchHome(t)
	generation := snapshotRulePackGenerationFor(t.Context(), "claudecode")
	options := ruleScanOptions{includeToolCallOnly: true, excludeTrustExploit: true}
	doc := "see /etc/shadow\n" + overLimitWriteText
	for name, row := range map[string]struct {
		target, content string
		want            bool
	}{
		"shadow":      {"/etc/shadow", overLimitWriteText, true},
		"project doc": {filepath.Join(project, "docs", "notes.md"), doc, false},
	} {
		t.Run(name, func(t *testing.T) {
			args := mustJSON(t, map[string]any{"file_path": row.target, "content": row.content})
			input := actionfacts.Input{Tool: "Write", Args: args, CWD: project, ActiveHome: home}
			facts := actionfacts.Analyze(input)
			if facts.Authoritative() || !actionfacts.LimitExceededWriteTool(input, facts) {
				t.Fatalf("facts are not limit-exceeded: %+v", facts.Parse)
			}
			findings, _ := dispatchTrustedFallback(generation, trustedActionRequest{
				Input: input, LegacyText: string(args), Connector: "claudecode", EnforcementCapable: true,
			}, facts, options)
			finding := findingWithID(findings, "PATH-ETC-SHADOW")
			if got := finding != nil && finding.contributesToEnforcement(); got != row.want {
				t.Fatalf("PATH-ETC-SHADOW enforces = %t, want %t: %v", got, row.want, FindingStrings(findings))
			}
			for _, finding := range findings {
				if finding.Title == overLimitUnverifiedWriteTitle {
					t.Fatalf("conservative block of an unread target: %v", FindingStrings(findings))
				}
			}
		})
	}
}
