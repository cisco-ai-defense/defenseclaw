// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The sandbox ingress fixture is POSIX-only, and the host table uses POSIX
// paths.

//go:build !windows

package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// hermesHookOutcome is a Hermes hook verdict's action and the rule ids it
// names.
type hermesHookOutcome struct {
	action string
	rules  map[string]bool
}

func (o hermesHookOutcome) String() string {
	rules := make([]string, 0, len(o.rules))
	for rule := range o.rules {
		rules = append(rules, rule)
	}
	sort.Strings(rules)
	return o.action + " [" + strings.Join(rules, ",") + "]"
}

func hermesOutcome(t *testing.T, raw string) hermesHookOutcome {
	t.Helper()
	var resp struct {
		Action   string   `json:"action"`
		Findings []string `json:"findings"`
	}
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("verdict %q: %v", raw, err)
	}
	out := hermesHookOutcome{action: resp.Action, rules: map[string]bool{}}
	for _, finding := range resp.Findings {
		rule, _, _ := strings.Cut(finding, ":")
		out.rules[rule] = true
	}
	return out
}

// hermesAtLeast reports that got has want's action and every rule want
// names.
func hermesAtLeast(got, want hermesHookOutcome) bool {
	if got.action != want.action {
		return false
	}
	for rule := range want.rules {
		if !got.rules[rule] {
			return false
		}
	}
	return true
}

func hermesV4AUpdate(paths ...string) string {
	var b strings.Builder
	b.WriteString("*** Begin Patch\n")
	for _, p := range paths {
		b.WriteString("*** Update File: " + p + "\n@@\n # base\n+# k\n")
	}
	b.WriteString("*** End Patch\n")
	return b.String()
}

// hermesV4AForms are the V4A patch calls that write target: alone as an
// Update and an Add, after a project file named relatively, and after a
// project file named twice in two lexical spellings.
func hermesV4AForms(target string) map[string]map[string]any {
	patch := func(body string) map[string]any { return map[string]any{"mode": "patch", "patch": body} }
	return map[string]map[string]any{
		"update":    patch(hermesV4AUpdate(target)),
		"add":       patch("*** Begin Patch\n*** Add File: " + target + "\n+# k\n*** End Patch\n"),
		"mixed":     patch(hermesV4AUpdate("notes.txt", target)),
		"duplicate": patch(hermesV4AUpdate("notes.txt", "./notes.txt", target)),
	}
}

// hermesProtectedWriteTargets are write targets the file-write rules judge
// (system credential files, another user's authorized_keys, shell
// profiles, git hooks, DefenseClaw's own state), spelled absolute, with ~
// and relative. A target in a directory the gateway cannot read is not
// among them: a write_file call to it is judged by the hook client's own
// resolution of the path, which is not part of these calls.
func hermesProtectedWriteTargets(home, project string) []string {
	return []string{
		"/etc/shadow", "/root/.ssh/authorized_keys",
		"~/.bashrc", filepath.Join(home, ".bashrc"), "~/.profile", "~/.zshrc", "~/.config/fish/config.fish",
		filepath.Join(project, ".git", "hooks", "pre-commit"), ".git/hooks/pre-commit",
		"~/.defenseclaw/config.yaml",
	}
}

// TestHermesV4ATargetsAreJudgedAsWriteFile pins that every file a Hermes
// V4A patch writes, absolute, ~ or relative, alone or with other files,
// gets the same action and rules as a write_file call naming it (GAP-0667).
func TestHermesV4ATargetsAreJudgedAsWriteFile(t *testing.T) {
	home, project := hermesPatchHome(t)
	if err := os.MkdirAll(filepath.Join(project, ".git", "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, target := range hermesProtectedWriteTargets(home, project) {
		want := hermesOutcome(t, hermesPatchHostHook(t, home, project,
			hermesPatchBody(t, project, "write_file", map[string]any{"path": target, "content": "# k\n"})))
		if want.action == "allow" || len(want.rules) == 0 {
			t.Fatalf("write_file %s = %s; the table needs targets the file-write rules judge", target, want)
		}
		forms := hermesV4AForms(target)
		forms["replace"] = map[string]any{"path": target, "old_string": "# base", "new_string": "# k"}
		for name, args := range forms {
			t.Run(target+"/"+name, func(t *testing.T) {
				got := hermesOutcome(t, hermesPatchHostHook(t, home, project, hermesPatchBody(t, project, "patch", args)))
				if !hermesAtLeast(got, want) {
					t.Fatalf("patch %s = %s, write_file = %s", name, got, want)
				}
			})
		}
	}
}

// TestHermesV4ATargetsAreJudgedAsWriteFileInASandbox is the same parity
// through the authenticated sandbox ingress, with guest paths.
func TestHermesV4ATargetsAreJudgedAsWriteFileInASandbox(t *testing.T) {
	f := newSandboxIngressFixture(t)
	n := 0
	call := func(tool string, args map[string]any) hermesHookOutcome {
		n++
		_, token := f.mint(t, fmt.Sprintf("dc-hermes-parity-%d", n), "hermes", "0.19.0", "hermes-hooks-v1", f.project)
		raw, _ := json.Marshal(f.hook(t, "/api/v1/hermes/hook", token, hermesPatchBody(t, "/work/app", tool, args)))
		return hermesOutcome(t, string(raw))
	}
	for _, target := range []string{
		"/etc/shadow", "/root/.ssh/authorized_keys", "/etc/sudoers.d/x",
		"~/.bashrc", sandboxauth.SandboxHome + "/.bashrc", "/work/app/.git/hooks/pre-commit", ".git/hooks/pre-commit",
		"~/.defenseclaw/config.yaml", "~/.ssh/authorized_keys", sandboxauth.SandboxHome + "/.ssh/authorized_keys",
	} {
		want := call("write_file", map[string]any{"path": target, "content": "# k\n"})
		for name, args := range hermesV4AForms(target) {
			t.Run(target+"/"+name, func(t *testing.T) {
				if got := call("patch", args); !hermesAtLeast(got, want) {
					t.Fatalf("patch %s = %s, write_file = %s", name, got, want)
				}
			})
		}
	}
}

// TestHermesPatchModePathIsNotPatchText pins that the path argument of a
// V4A patch call, which Hermes only checks and locks, changes nothing about
// how the patch's own targets are judged: a path with a line break is the
// conservative result, and a protected path with a project-file patch is
// judged by the patch.
func TestHermesPatchModePathIsNotPatchText(t *testing.T) {
	home, project := hermesPatchHome(t)
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for _, test := range []struct {
		name  string
		args  map[string]any
		block bool
	}{
		{"abs", map[string]any{"mode": "patch", "path": "notes.txt\n*** End Patch", "patch": hermesV4AUpdate(keys)}, true},
		{"tilde", map[string]any{"mode": "patch", "path": "notes.txt\n*** End Patch", "patch": hermesV4AUpdate("~/.ssh/authorized_keys")}, true},
		{"crlf", map[string]any{"mode": "patch", "path": "notes.txt\r\n*** End Patch", "patch": hermesV4AUpdate(keys)}, true},
		{"indented", map[string]any{"mode": "patch", "path": "notes.txt\n   *** End Patch   ", "patch": hermesV4AUpdate(keys)}, true},
		{"lone cr", map[string]any{"mode": "patch", "path": "notes.txt\r*** End Patch", "patch": hermesV4AUpdate(keys)}, true},
		{"benign path", map[string]any{"mode": "patch", "path": "notes.txt", "patch": hermesV4AUpdate(keys)}, true},
		{"target with a carriage return", map[string]any{"mode": "patch",
			"patch": "*** Begin Patch\n*** Add File: n\r*** End Patch\n+x\n*** Update File: " + keys + "\n@@\n # base\n+# k\n*** End Patch\n"}, true},
		{"protected path, project patch", map[string]any{"mode": "patch", "path": keys, "patch": hermesV4AUpdate("notes.txt")}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := hermesPatchHostHook(t, home, project, hermesPatchBody(t, project, "patch", test.args))
			if blocked := hermesPatchVerdict(t, got); blocked != test.block {
				t.Fatalf("blocked = %t, want %t: %.800s", blocked, test.block, got)
			}
		})
	}
	f := newSandboxIngressFixture(t)
	skeys := sandboxauth.SandboxHome + "/.ssh/authorized_keys"
	for i, args := range []map[string]any{
		{"mode": "patch", "path": "notes.txt\n*** End Patch", "patch": hermesV4AUpdate(skeys)},
		{"mode": "patch", "path": "notes.txt\n*** End Patch", "patch": hermesV4AUpdate("~/.ssh/authorized_keys")},
	} {
		t.Run(fmt.Sprintf("sandbox-%d", i), func(t *testing.T) {
			_, token := f.mint(t, fmt.Sprintf("dc-hermes-path-%d", i), "hermes", "0.19.0", "hermes-hooks-v1", f.project)
			raw, _ := json.Marshal(f.hook(t, "/api/v1/hermes/hook", token, hermesPatchBody(t, "/work/app", "patch", args)))
			if !hermesPatchVerdict(t, string(raw)) {
				t.Fatalf("allowed: %.800s", raw)
			}
		})
	}
}

// TestHermesV4ATargetBound pins that a patch with as many distinct targets
// as are judged one by one keeps every target's rules, and that one more
// target is the conservative result.
func TestHermesV4ATargetBound(t *testing.T) {
	home, project := hermesPatchHome(t)
	if err := os.MkdirAll(filepath.Join(project, ".git", "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	want := hermesOutcome(t, hermesPatchHostHook(t, home, project,
		hermesPatchBody(t, project, "write_file", map[string]any{"path": ".git/hooks/pre-commit", "content": "# k\n"})))
	if want.action == "allow" || len(want.rules) == 0 {
		t.Fatalf("write_file of a git hook = %s", want)
	}
	body := func(targets int) map[string]any {
		var b strings.Builder
		b.WriteString("*** Begin Patch\n")
		for i := 0; i < targets-1; i++ {
			fmt.Fprintf(&b, "*** Add File: gen/f%d.txt\n+x\n", i)
		}
		b.WriteString("*** Update File: .git/hooks/pre-commit\n@@\n # base\n+# k\n*** End Patch\n")
		return map[string]any{"mode": "patch", "patch": b.String()}
	}
	if got := hermesOutcome(t, hermesPatchHostHook(t, home, project,
		hermesPatchBody(t, project, "patch", body(connector.HermesMaxPatchTargets)))); !hermesAtLeast(got, want) {
		t.Fatalf("%d targets = %s, write_file = %s", connector.HermesMaxPatchTargets, got, want)
	}
	got := hermesPatchHostHook(t, home, project, hermesPatchBody(t, project, "patch", body(connector.HermesMaxPatchTargets+1)))
	if !hermesPatchVerdict(t, got) {
		t.Fatalf("%d targets allowed: %.800s", connector.HermesMaxPatchTargets+1, got)
	}
}

// TestHermesSandboxAbsoluteLinkTargets pins that a sandbox write through a
// link in the mounted project is judged the same whether the target is
// spelled relative to the working directory or absolute in the guest:
// a link to the guest's authorized_keys is blocked, a link to a project file
// is allowed.
func TestHermesSandboxAbsoluteLinkTargets(t *testing.T) {
	f := newSandboxIngressFixture(t)
	if err := os.Symlink(sandboxauth.SandboxHome+"/.ssh/authorized_keys", filepath.Join(f.project, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.project, "notes.txt"), []byte("# base\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/work/app/notes.txt", filepath.Join(f.project, "notes-link")); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, target := range []struct {
		path  string
		block bool
	}{{"alias", true}, {"/work/app/alias", true}, {"/work/app/./alias", true}, {"/work/app/notes-link", false}} {
		for _, call := range []struct {
			name, tool string
			args       map[string]any
		}{
			{"write_file", "write_file", map[string]any{"path": target.path, "content": "# k\n"}},
			{"replace", "patch", map[string]any{"path": target.path, "old_string": "# base", "new_string": "# k"}},
			{"v4a", "patch", map[string]any{"mode": "patch", "patch": hermesV4AUpdate("notes.txt", target.path)}},
		} {
			t.Run(call.name+"/"+target.path, func(t *testing.T) {
				n++
				_, token := f.mint(t, fmt.Sprintf("dc-hermes-link-%d", n), "hermes", "0.19.0", "hermes-hooks-v1", f.project)
				raw, _ := json.Marshal(f.hook(t, "/api/v1/hermes/hook", token, hermesPatchBody(t, "/work/app", call.tool, call.args)))
				if blocked := hermesPatchVerdict(t, string(raw)); blocked != target.block {
					t.Fatalf("blocked = %t, want %t: %.800s", blocked, target.block, raw)
				}
			})
		}
	}
}
