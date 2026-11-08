// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The rows name POSIX system paths (/etc) and a POSIX managed peer.

//go:build !windows

package gateway

import (
	"strings"
	"testing"
)

// fileToolContentRule is one code-owned rule that proves its text from the
// content a file tool writes: the file it protects, the text that trips it,
// the ordinary text of the same file, and whether an edit that only inserts
// the text can trip it (a rule that needs the complete final document cannot
// be proven by a fragment).
type fileToolContentRule struct {
	name, rule, target string
	attack, benign     string
	// context is the line an edit replaces; the edit keeps it and adds text.
	context string
	edits   bool
}

var fileToolContentRules = []fileToolContentRule{
	{
		name: "ld.so.preload", rule: "persistence.global_ld_preload_install", target: "/etc/ld.so.preload",
		attack: "/usr/local/lib/libr109ib17.so\n", benign: "# no libraries are preloaded\n",
		context: "# managed\n", edits: true,
	},
	{
		name: "profile.d LD_PRELOAD", rule: "persistence.global_ld_preload_install", target: "/etc/profile.d/r109ib17.sh",
		attack: "export LD_PRELOAD=/usr/local/lib/libr109ib17.so\n", benign: "export CLICOLOR=1\n",
		context: "# managed\n", edits: true,
	},
	{
		name: "pam.d", rule: "tamper.pam_permit_authentication_bypass", target: "/etc/pam.d/sshd",
		attack: "auth sufficient pam_permit.so\n", benign: "auth required pam_unix.so\n",
		context: "auth required pam_unix.so\n", edits: true,
	},
	{
		name: "pam.conf", rule: "tamper.pam_permit_authentication_bypass", target: "/etc/pam.conf",
		attack: "login auth sufficient pam_permit.so\n", benign: "login auth required pam_unix.so\n",
		context: "login auth required pam_unix.so\n", edits: true,
	},
	{
		name: "docker daemon", rule: "tamper.docker_insecure_http_registry", target: "/etc/docker/daemon.json",
		attack: "{\"insecure-registries\":[\"http://registry.example.test:5000\"]}\n",
		benign: "{\"log-level\":\"warn\"}\n",
	},
}

// fileToolRows are the native file-tool calls of each connector that write
// text as the whole file (whole is true) or insert it beside context.
func fileToolRows(rule fileToolContentRule, text string, whole bool) []sudoersHookRow {
	target := rule.target
	plus := func(body string) string {
		var out strings.Builder
		for _, line := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
			out.WriteString("+" + line + "\n")
		}
		return out.String()
	}
	patch := func(directive, body string) string {
		return "*** Begin Patch\n*** " + directive + " File: " + target + "\n" + body + "*** End Patch\n"
	}
	if whole {
		return []sudoersHookRow{
			{"claudecode", "Write", sudoersClaudeCall("Write", sudoersFixed(map[string]any{"file_path": target, "content": text}))},
			{"codex", "apply_patch add", sudoersClaudeCall("apply_patch", sudoersFixed(map[string]any{"command": patch("Add", plus(text))}))},
			{"hermes", "write_file", sudoersHermesCall("write_file", sudoersFixed(map[string]any{"path": target, "content": text}))},
			{"copilot", "create", sudoersCopilotCall("create", sudoersFixed(map[string]any{"path": target, "file_text": text}))},
		}
	}
	old, added := rule.context, rule.context+text
	return []sudoersHookRow{
		{"claudecode", "Edit", sudoersClaudeCall("Edit", sudoersFixed(map[string]any{"file_path": target, "old_string": old, "new_string": added}))},
		{"claudecode", "Edit replace_all false", sudoersClaudeCall("Edit", sudoersFixed(map[string]any{"file_path": target, "old_string": old, "new_string": added, "replace_all": false}))},
		{"claudecode", "Edit replace_all true", sudoersClaudeCall("Edit", sudoersFixed(map[string]any{"file_path": target, "old_string": old, "new_string": added, "replace_all": true}))},
		{"claudecode", "MultiEdit", sudoersClaudeCall("MultiEdit", sudoersFixed(map[string]any{"file_path": target,
			"edits": []any{map[string]any{"old_string": old, "new_string": added}}}))},
		{"codex", "apply_patch update", sudoersClaudeCall("apply_patch", sudoersFixed(map[string]any{
			"command": patch("Update", "@@\n "+strings.TrimSuffix(old, "\n")+"\n"+plus(text))}))},
		{"hermes", "patch replace", sudoersHermesCall("patch", sudoersFixed(map[string]any{"path": target, "old_string": old, "new_string": added}))},
		{"copilot", "edit", sudoersCopilotCall("edit", sudoersFixed(map[string]any{"path": target, "old_str": old, "new_str": added}))},
	}
}

// TestFileToolWritesOfProtectedContentAreBlockedLikeTheWholeFileWrite: each
// code-owned content rule judges the text of a native file-tool call whatever
// the tool: the whole-file write of Claude Code, Codex, Hermes and Copilot,
// and, for a rule whose text proves itself in a fragment, an edit, multi-edit
// or patch that inserts the text, with or without replace_all. Each is
// refused on the balanced and the strict profile (the permissive profile
// alerts on these rules and does not refuse).
func TestFileToolWritesOfProtectedContentAreBlockedLikeTheWholeFileWrite(t *testing.T) {
	hostLinksEtc(t, true)
	for _, rule := range fileToolContentRules {
		rows := fileToolRows(rule, rule.attack, true)
		if rule.edits {
			rows = append(rows, fileToolRows(rule, rule.attack, false)...)
		}
		for _, profile := range []string{"default", "strict"} {
			for _, row := range rows {
				t.Run(rule.name+"/"+profile+"/"+row.connector+" "+row.name, func(t *testing.T) {
					blocked, _, body := postSudoersHook(t, row, profile, false)
					if !blocked || !strings.Contains(body, rule.rule) {
						t.Fatalf("blocked = %t, want a block naming %s: %.600s", blocked, rule.rule, body)
					}
				})
			}
		}
	}
}

// TestFileToolWritesOfOrdinaryContentAreNotBlockedByTheContentRules: the
// ordinary text of the same files never names the rule, and the balanced
// profiles allow it.
func TestFileToolWritesOfOrdinaryContentAreNotBlockedByTheContentRules(t *testing.T) {
	hostLinksEtc(t, true)
	for _, rule := range fileToolContentRules {
		rows := fileToolRows(rule, rule.benign, true)
		if rule.edits {
			rows = append(rows, fileToolRows(rule, rule.benign, false)...)
		}
		for _, profile := range []string{"default", "permissive"} {
			for _, row := range rows {
				t.Run(rule.name+"/"+profile+"/"+row.connector+" "+row.name, func(t *testing.T) {
					blocked, _, body := postSudoersHook(t, row, profile, false)
					if strings.Contains(body, rule.rule) {
						t.Fatalf("names %s for ordinary text: %.600s", rule.rule, body)
					}
					if blocked {
						t.Logf("blocked by another rule (not this fix): %.300s", body)
					}
				})
			}
		}
	}
}

// TestOverLimitPatchOfAContentRuleTargetKeepsItsVerdict: a Codex patch that
// adds protected text to a file a content rule judges gets the verdict of the
// same patch padded past the argument limit, and a padded patch of an
// ordinary project file stays allowed.
func TestOverLimitPatchOfAContentRuleTargetKeepsItsVerdict(t *testing.T) {
	home, project := hermesPatchHome(t)
	pad := strings.Repeat(" ", 70000)
	for _, rule := range fileToolContentRules {
		for _, c := range []struct {
			name, text string
			blocked    bool
		}{{"protected", rule.attack, true}, {"ordinary", rule.benign, false}} {
			for _, padded := range []bool{false, true} {
				t.Run(rule.name+"/"+c.name+"/padded="+map[bool]string{false: "no", true: "yes"}[padded], func(t *testing.T) {
					text := strings.TrimSuffix(c.text, "\n")
					if padded {
						text += pad
					}
					call := nativeWriteCall{"codex", "apply_patch", func(string) map[string]any {
						return map[string]any{"command": "*** Begin Patch\n*** Add File: " + rule.target + "\n+" + text + "\n*** End Patch\n"}
					}}
					got := overLimitHostHook(t, "codex", home, call.body(t, project, rule.target))
					action := overLimitHookAction(t, got)
					if c.blocked && (action != "block" || !strings.Contains(got, rule.rule)) {
						t.Fatalf("action = %q, want a block naming %s: %.600s", action, rule.rule, got)
					}
					if !c.blocked && strings.Contains(got, rule.rule) {
						t.Fatalf("ordinary text names %s: %.600s", rule.rule, got)
					}
				})
			}
		}
	}
}
