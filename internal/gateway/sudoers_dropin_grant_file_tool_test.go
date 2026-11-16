// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The rows name POSIX paths (/etc/sudoers.d) and a POSIX managed peer.

//go:build !windows

package gateway

import (
	"strings"
	"testing"
)

const sudoersGrantRuleID = "privilege.sudoers_unrestricted_nopasswd"

// sudoersDropInRows are the native file-tool calls of each connector that put
// the text into a drop-in of /etc/sudoers.d (or the main file) under both
// macOS spellings of /etc.
func sudoersDropInRows(t *testing.T, text string) []sudoersHookRow {
	patch := func(directive, path string) string {
		return "*** Begin Patch\n*** " + directive + " File: " + path + "\n" + "@@\n+" + strings.TrimSuffix(text, "\n") + "\n*** End Patch\n"
	}
	var rows []sudoersHookRow
	for _, target := range []string{"/etc/sudoers.d/r109ib17", "/private/etc/sudoers.d/r109ib17", "/etc/sudoers", "/Etc/Sudoers.d/R109"} {
		rows = append(rows,
			sudoersHookRow{"claudecode", "Write " + target, sudoersClaudeCall("Write", sudoersFixed(map[string]any{"file_path": target, "content": text}))},
			sudoersHookRow{"claudecode", "Edit " + target, sudoersClaudeCall("Edit", sudoersFixed(map[string]any{"file_path": target, "old_string": "# managed\n", "new_string": "# managed\n" + text}))},
			sudoersHookRow{"claudecode", "MultiEdit " + target, sudoersClaudeCall("MultiEdit", sudoersFixed(map[string]any{"file_path": target,
				"edits": []any{map[string]any{"old_string": "# managed\n", "new_string": "# managed\n" + text}}}))},
			sudoersHookRow{"codex", "apply_patch " + target, sudoersClaudeCall("apply_patch", sudoersFixed(map[string]any{"command": patch("Update", target)}))},
			sudoersHookRow{"hermes", "write_file " + target, sudoersHermesCall("write_file", sudoersFixed(map[string]any{"path": target, "content": text}))},
			sudoersHookRow{"hermes", "patch replace " + target, sudoersHermesCall("patch", sudoersFixed(map[string]any{"path": target, "old_string": "# managed\n", "new_string": "# managed\n" + text}))},
			sudoersHookRow{"copilot", "create " + target, sudoersCopilotCall("create", sudoersFixed(map[string]any{"path": target, "file_text": text}))},
			sudoersHookRow{"copilot", "edit " + target, sudoersCopilotCall("edit", sudoersFixed(map[string]any{"path": target, "old_str": "# managed\n", "new_str": text}))},
		)
	}
	return rows
}

// TestFileToolWriteOfAnUnrestrictedSudoersGrantIsBlockedInEveryProfile: a
// native file-tool write, edit or patch that puts an unrestricted passwordless
// grant into the main sudoers file or a drop-in of /etc/sudoers.d is refused by
// the grant rule on every profile and for the per-user and the managed gateway,
// whatever the tool calls its path argument and under both spellings of /etc.
func TestFileToolWriteOfAnUnrestrictedSudoersGrantIsBlockedInEveryProfile(t *testing.T) {
	hostLinksEtc(t, true)
	for _, profile := range []string{"default", "permissive", "strict"} {
		for _, managed := range []bool{false, true} {
			for _, row := range sudoersDropInRows(t, "r109yem5 ALL=(ALL) NOPASSWD: ALL\n") {
				name := profile + "/" + map[bool]string{false: "per-user", true: "managed"}[managed] + "/" + row.connector + " " + row.name
				t.Run(name, func(t *testing.T) {
					blocked, _, body := postSudoersHook(t, row, profile, managed)
					if !blocked || !strings.Contains(body, sudoersGrantRuleID) {
						t.Fatalf("blocked = %t, want a block naming %s: %.600s", blocked, sudoersGrantRuleID, body)
					}
				})
			}
		}
	}
}

// TestFileToolWriteOfOrdinarySudoersTextIsNotBlockedByTheGrantRule: the twins
// of the rows above that carry no unrestricted grant never name the grant rule,
// and the balanced profiles keep allowing an ordinary drop-in. The per-user
// gateway is the cell: a managed gateway on a host where /etc/sudoers.d is
// unreadable refuses every write there as an unreadable target
// (rel-1-0-6:GAP-0190), whatever the text.
func TestFileToolWriteOfOrdinarySudoersTextIsNotBlockedByTheGrantRule(t *testing.T) {
	hostLinksEtc(t, true)
	for _, text := range []string{
		"# managed by ops\n",
		"Defaults env_reset\n",
		"r109yem5 ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart api\n",
		"# r109yem5 ALL=(ALL) NOPASSWD: ALL\n",
		"root ALL=(ALL) NOPASSWD: ALL\n",
		"root\tALL=(ALL)\tNOPASSWD: ALL\n",
	} {
		for _, profile := range []string{"default", "permissive"} {
			for _, row := range sudoersDropInRows(t, text) {
				if strings.HasSuffix(row.name, "/etc/sudoers") || strings.HasSuffix(row.name, "/Etc/Sudoers.d/R109") {
					continue
				}
				t.Run(profile+"/"+row.connector+" "+row.name+" "+strings.TrimSpace(text), func(t *testing.T) {
					blocked, _, body := postSudoersHook(t, row, profile, false)
					if blocked || strings.Contains(body, sudoersGrantRuleID) {
						t.Fatalf("blocked = %t, names the grant rule = %t, want neither: %.600s", blocked, strings.Contains(body, sudoersGrantRuleID), body)
					}
				})
			}
		}
	}
}

// sudoersRelativeRows are file-tool calls made from a working directory that is
// the drop-in directory, naming the file by a short relative name.
func sudoersRelativeRows(text string) []sudoersHookRow {
	patch := func(name string) string {
		return "*** Begin Patch\n*** Add File: " + name + "\n+" + strings.TrimSuffix(text, "\n") + "\n*** End Patch\n"
	}
	inDir := func(dir string, call func(string) map[string]any) func(string) map[string]any {
		return func(p string) map[string]any {
			payload := call(p)
			payload["cwd"] = dir
			return payload
		}
	}
	var rows []sudoersHookRow
	// The gateway only keeps a working directory that exists on the host, so
	// the cell is /etc/sudoers.d; the macOS physical directory is covered by
	// the action-fact rows, whose working directory is not checked.
	for _, dir := range []string{"/etc/sudoers.d"} {
		for _, name := range []string{"r109c860", "./r109c860"} {
			label := " from " + dir + " as " + name
			rows = append(rows,
				sudoersHookRow{"claudecode", "Write" + label, inDir(dir, sudoersClaudeCall("Write", sudoersFixed(map[string]any{"file_path": name, "content": text})))},
				sudoersHookRow{"claudecode", "Edit" + label, inDir(dir, sudoersClaudeCall("Edit", sudoersFixed(map[string]any{"file_path": name, "old_string": "# managed\n", "new_string": text})))},
				sudoersHookRow{"codex", "apply_patch" + label, inDir(dir, sudoersClaudeCall("apply_patch", sudoersFixed(map[string]any{"command": patch(name)})))},
				sudoersHookRow{"hermes", "write_file" + label, inDir(dir, sudoersHermesCall("write_file", sudoersFixed(map[string]any{"path": name, "content": text})))},
				sudoersHookRow{"copilot", "create" + label, inDir(dir, sudoersCopilotCall("create", sudoersFixed(map[string]any{"path": name, "file_text": text})))},
			)
		}
	}
	return rows
}

// TestFileToolWriteOfAGrantByRelativeNameFromTheDropInDirectoryIsBlocked: a
// short name resolved against a working directory of /etc/sudoers.d is the
// drop-in file, so the arguments need not spell the word sudoers.
func TestFileToolWriteOfAGrantByRelativeNameFromTheDropInDirectoryIsBlocked(t *testing.T) {
	hostLinksEtc(t, true)
	for _, profile := range []string{"default", "permissive", "strict"} {
		for _, managed := range []bool{false, true} {
			for _, row := range sudoersRelativeRows("r109yem5 ALL=(ALL) NOPASSWD: ALL\n") {
				name := profile + "/" + map[bool]string{false: "per-user", true: "managed"}[managed] + "/" + row.connector + " " + row.name
				t.Run(name, func(t *testing.T) {
					blocked, _, body := postSudoersHook(t, row, profile, managed)
					if !blocked || !strings.Contains(body, sudoersGrantRuleID) {
						t.Fatalf("blocked = %t, want a block naming %s: %.600s", blocked, sudoersGrantRuleID, body)
					}
				})
			}
		}
	}
}

// TestFileToolWriteOfOrdinaryTextByRelativeNameFromTheDropInDirectoryIsAllowed
// is the benign twin: the same relative names with no unrestricted grant never
// name the grant rule and the balanced profiles allow them.
func TestFileToolWriteOfOrdinaryTextByRelativeNameFromTheDropInDirectoryIsAllowed(t *testing.T) {
	hostLinksEtc(t, true)
	for _, text := range []string{"# managed by ops\n", "root\tALL=(ALL)\tNOPASSWD: ALL\n"} {
		for _, profile := range []string{"default", "permissive"} {
			for _, row := range sudoersRelativeRows(text) {
				t.Run(profile+"/"+row.connector+" "+row.name+" "+strings.TrimSpace(text), func(t *testing.T) {
					blocked, _, body := postSudoersHook(t, row, profile, false)
					if blocked || strings.Contains(body, sudoersGrantRuleID) {
						t.Fatalf("blocked = %t, names the grant rule = %t, want neither: %.600s", blocked, strings.Contains(body, sudoersGrantRuleID), body)
					}
				})
			}
		}
	}
}

// TestFileToolWriteOfAGrantToADifferentlyCasedPathIsNotAGrantTargetOffMacOS: a
// host that keeps letter case has no /ETC/SUDOERS.D, so a write there is an
// ordinary file and balanced profiles allow it.
func TestFileToolWriteOfAGrantToADifferentlyCasedPathIsNotAGrantTargetOffMacOS(t *testing.T) {
	hostLinksEtc(t, false)
	const text = "r109yem5 ALL=(ALL) NOPASSWD: ALL\n"
	for _, profile := range []string{"default", "permissive"} {
		for _, target := range []string{"/ETC/SUDOERS.D/child", "/Etc/Sudoers"} {
			row := sudoersHookRow{"claudecode", "Write " + target, sudoersClaudeCall("Write", sudoersFixed(map[string]any{"file_path": target, "content": text}))}
			t.Run(profile+"/"+target, func(t *testing.T) {
				blocked, _, body := postSudoersHook(t, row, profile, false)
				if blocked || strings.Contains(body, sudoersGrantRuleID) {
					t.Fatalf("blocked = %t, names the grant rule = %t, want neither: %.600s", blocked, strings.Contains(body, sudoersGrantRuleID), body)
				}
			})
		}
	}
}
