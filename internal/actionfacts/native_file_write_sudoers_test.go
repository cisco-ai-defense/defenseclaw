// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
	"testing"
)

const nativeSudoersGrant = "r109yem5 ALL=(ALL) NOPASSWD: ALL\n"

func nativeSudoersArgs(t *testing.T, fields map[string]any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func nativeSudoersPatch(directive, target, body string) map[string]any {
	return map[string]any{"command": "*** Begin Patch\n*** " + directive + " File: " + target + "\n" + body + "*** End Patch\n"}
}

// TestNativeFileWriteOfAnUnrestrictedGrantIsProvenForEveryToolShape: the proof
// does not depend on how a connector spells the target and text arguments, on
// the letter case or the dot segments of the target, or on its macOS physical
// spelling.
func TestNativeFileWriteOfAnUnrestrictedGrantIsProvenForEveryToolShape(t *testing.T) {
	linksEtcForTest(t, true)
	edit := map[string]any{"old_string": "# drop-in\n", "new_string": "# drop-in\n" + nativeSudoersGrant}
	for _, row := range []struct {
		name, tool, cwd string
		args            map[string]any
	}{
		{"Write file_path", "Write", "", map[string]any{"file_path": "/etc/sudoers.d/r109", "content": nativeSudoersGrant}},
		{"Write macOS physical spelling", "Write", "", map[string]any{"file_path": "/private/etc/sudoers.d/r109", "content": nativeSudoersGrant}},
		{"Write main file", "Write", "", map[string]any{"file_path": "/etc/sudoers", "content": nativeSudoersGrant}},
		{"Write upper case", "Write", "", map[string]any{"file_path": "/ETC/Sudoers.d/R109", "content": nativeSudoersGrant}},
		{"Write dot segments", "Write", "", map[string]any{"file_path": "/etc/./sudoers.d//r109", "content": nativeSudoersGrant}},
		{"Write dotdot segment", "Write", "", map[string]any{"file_path": "/etc/ssh/../sudoers.d/r109", "content": nativeSudoersGrant}},
		{"Write relative to the working directory", "Write", "/etc", map[string]any{"file_path": "sudoers.d/r109", "content": nativeSudoersGrant}},
		{"write_file path", "write_file", "", map[string]any{"path": "/etc/sudoers.d/r109", "content": nativeSudoersGrant}},
		{"create file_text", "create", "", map[string]any{"path": "/etc/sudoers.d/r109", "file_text": nativeSudoersGrant}},
		{"Write camelCase path", "Write", "", map[string]any{"filePath": "/etc/sudoers.d/r109", "content": nativeSudoersGrant}},
		{"grant among comments", "Write", "", map[string]any{"file_path": "/etc/sudoers.d/r109", "content": "# managed\n\n  \t" + nativeSudoersGrant}},
		{"template characters elsewhere in the file", "Write", "", map[string]any{"file_path": "/etc/sudoers.d/r109", "content": "# ${HOME} {{x}} `id` $(id)\n" + nativeSudoersGrant}},
		{"CRLF line ends", "Write", "", map[string]any{"file_path": "/etc/sudoers.d/r109", "content": "# a\r\n" + strings.TrimSuffix(nativeSudoersGrant, "\n") + "\r\n"}},
		{"group grant", "Write", "", map[string]any{"file_path": "/etc/sudoers.d/r109", "content": "%wheel ALL=(ALL:ALL) NOPASSWD:ALL\n"}},
		{"Edit adds the grant", "Edit", "", map[string]any{"file_path": "/etc/sudoers.d/r109", "old_string": edit["old_string"], "new_string": edit["new_string"], "replace_all": false}},
		{"Edit without replace_all", "Edit", "", map[string]any{"file_path": "/etc/sudoers.d/r109", "old_string": edit["old_string"], "new_string": edit["new_string"]}},
		{"Copilot edit", "edit", "", map[string]any{"path": "/etc/sudoers.d/r109", "old_str": "# drop-in\n", "new_str": nativeSudoersGrant}},
		{"Edit replaces a scoped grant", "Edit", "", map[string]any{"file_path": "/etc/sudoers.d/r109", "old_string": "r109yem5 ALL=(ALL) NOPASSWD: /usr/bin/id", "new_string": "r109yem5 ALL=(ALL) NOPASSWD: ALL"}},
		{"Edit moves the grant to another principal", "Edit", "", map[string]any{"file_path": "/etc/sudoers.d/r109", "old_string": "alice ALL=(ALL) NOPASSWD: ALL", "new_string": "bob ALL=(ALL) NOPASSWD: ALL"}},
		{"MultiEdit", "MultiEdit", "", map[string]any{"file_path": "/etc/sudoers.d/r109", "edits": []any{
			map[string]any{"old_string": "a", "new_string": "b"},
			map[string]any{"old_string": "# drop-in\n", "new_string": nativeSudoersGrant},
		}}},
		{"apply_patch add", "apply_patch", "", nativeSudoersPatch("Add", "/etc/sudoers.d/r109", "+"+strings.TrimSuffix(nativeSudoersGrant, "\n")+"\n")},
		{"apply_patch update", "apply_patch", "", nativeSudoersPatch("Update", "/etc/sudoers.d/r109", "@@\n # drop-in\n+"+strings.TrimSuffix(nativeSudoersGrant, "\n")+"\n")},
		{"Write short name from the drop-in directory", "Write", "/etc/sudoers.d", map[string]any{"file_path": "r109", "content": nativeSudoersGrant}},
		{"Write dot-slash name from the drop-in directory", "Write", "/etc/sudoers.d", map[string]any{"file_path": "./r109", "content": nativeSudoersGrant}},
		{"Write short name from the macOS physical directory", "Write", "/private/etc/sudoers.d", map[string]any{"file_path": "r109", "content": nativeSudoersGrant}},
		{"write_file short name from the drop-in directory", "write_file", "/etc/sudoers.d", map[string]any{"path": "r109", "content": nativeSudoersGrant}},
		{"Edit short name from the drop-in directory", "Edit", "/etc/sudoers.d", map[string]any{"file_path": "r109", "old_string": "a", "new_string": nativeSudoersGrant}},
		{"apply_patch short name from the drop-in directory", "apply_patch", "/etc/sudoers.d", nativeSudoersPatch("Add", "r109", "+"+strings.TrimSuffix(nativeSudoersGrant, "\n")+"\n")},
		{"Write sudoers from /etc", "Write", "/etc", map[string]any{"file_path": "./sudoers", "content": nativeSudoersGrant}},
		{"tab separated grant", "Write", "", map[string]any{"file_path": "/etc/sudoers.d/r109", "content": "r109yem5\tALL=(ALL)\tNOPASSWD: ALL\n"}},
		{"apply_patch relative", "apply_patch", "/etc", nativeSudoersPatch("Add", "sudoers.d/r109", "+"+strings.TrimSuffix(nativeSudoersGrant, "\n")+"\n")},
	} {
		t.Run(row.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: row.tool, Args: nativeSudoersArgs(t, row.args), CWD: row.cwd})
			if !ExactPOSIXUnrestrictedSudoersGrantWrite(facts) ||
				!ExactPOSIXUnrestrictedSudoersGrantWrite(facts.EnforcementProjection()) {
				t.Fatalf("missing exact sudoers grant proof: %#v", facts.Parse)
			}
		})
	}
}

// TestNativeFileWriteBesideTheSudoersGrantStaysUnproven: the benign twins
// stay without a proof: a grant that is scoped, commented or the root user's,
// a target that is not sudoers, an edit that keeps or removes a grant, and a
// call that is not a reviewed file-write shape.
func TestNativeFileWriteBesideTheSudoersGrantStaysUnproven(t *testing.T) {
	linksEtcForTest(t, false)
	for _, row := range []struct {
		name, tool, cwd string
		args            map[string]any
	}{
		{"comment only drop-in", "Write", "", map[string]any{"file_path": "/etc/sudoers.d/r109", "content": "# managed by ops\n"}},
		{"Defaults line", "Write", "", map[string]any{"file_path": "/etc/sudoers.d/r109", "content": "Defaults env_reset\n"}},
		{"scoped grant", "Write", "", map[string]any{"file_path": "/etc/sudoers.d/r109", "content": "r109yem5 ALL=(ALL) NOPASSWD: /usr/bin/id\n"}},
		{"commented grant", "Write", "", map[string]any{"file_path": "/etc/sudoers.d/r109", "content": "# " + nativeSudoersGrant}},
		{"password required grant", "Write", "", map[string]any{"file_path": "/etc/sudoers.d/r109", "content": "r109yem5 ALL=(ALL) ALL\n"}},
		{"root grant", "Write", "", map[string]any{"file_path": "/etc/sudoers.d/r109", "content": "root ALL=(ALL) NOPASSWD: ALL\n"}},
		{"tab separated root grant", "Write", "", map[string]any{"file_path": "/etc/sudoers.d/r109", "content": "root\tALL=(ALL)\tNOPASSWD: ALL\n"}},
		{"short name from a project directory", "Write", "/work/proj", map[string]any{"file_path": "r109", "content": nativeSudoersGrant}},
		{"short name with a comment from the drop-in directory", "Write", "/etc/sudoers.d", map[string]any{"file_path": "r109", "content": "# managed\n"}},
		{"upper case path on a host that keeps case", "Write", "", map[string]any{"file_path": "/ETC/SUDOERS.D/r109", "content": nativeSudoersGrant}},
		{"project file named sudoers", "Write", "/work/proj", map[string]any{"file_path": "sudoers", "content": nativeSudoersGrant}},
		{"project etc/sudoers.d", "Write", "/work/proj", map[string]any{"file_path": "etc/sudoers.d/r109", "content": nativeSudoersGrant}},
		{"absolute project path", "Write", "", map[string]any{"file_path": "/work/proj/etc/sudoers.d/r109", "content": nativeSudoersGrant}},
		{"relative target without a working directory", "Write", "", map[string]any{"file_path": "sudoers.d/r109", "content": nativeSudoersGrant}},
		{"nested below the drop-in directory", "Write", "", map[string]any{"file_path": "/etc/sudoers.d/a/r109", "content": nativeSudoersGrant}},
		{"the drop-in directory itself", "Write", "", map[string]any{"file_path": "/etc/sudoers.d", "content": nativeSudoersGrant}},
		{"look-alike names", "Write", "", map[string]any{"file_path": "/etc/sudoersx", "content": nativeSudoersGrant}},
		{"macOS spelling off macOS", "Write", "", map[string]any{"file_path": "/private/etc/sudoers.d/r109", "content": nativeSudoersGrant}},
		{"Edit keeps a grant the file has", "Edit", "", map[string]any{"file_path": "/etc/sudoers.d/r109", "old_string": "alice ALL=(ALL) NOPASSWD: ALL\n", "new_string": "# ops\nalice ALL=(ALL) NOPASSWD: ALL\n"}},
		{"Edit removes a grant", "Edit", "", map[string]any{"file_path": "/etc/sudoers.d/r109", "old_string": "alice ALL=(ALL) NOPASSWD: ALL\n", "new_string": "# removed\n"}},
		{"Edit adds a scoped grant", "Edit", "", map[string]any{"file_path": "/etc/sudoers.d/r109", "old_string": "a", "new_string": "alice ALL=(ALL) NOPASSWD: /usr/bin/id\n"}},
		{"Edit of a project file", "Edit", "/work/proj", map[string]any{"file_path": "notes.md", "old_string": "a", "new_string": nativeSudoersGrant}},
		{"apply_patch removes a grant", "apply_patch", "", nativeSudoersPatch("Update", "/etc/sudoers.d/r109", "@@\n-"+strings.TrimSuffix(nativeSudoersGrant, "\n")+"\n+# removed\n")},
		{"apply_patch of a project file", "apply_patch", "/work/proj", nativeSudoersPatch("Add", "doc/sudoers.md", "+"+strings.TrimSuffix(nativeSudoersGrant, "\n")+"\n")},
		{"Read", "Read", "", map[string]any{"file_path": "/etc/sudoers.d/r109"}},
		{"text is not a reviewed content key", "write_file", "", map[string]any{"path": "/etc/sudoers.d/r109", "text": nativeSudoersGrant}},
		{"unknown extra key", "Write", "", map[string]any{"file_path": "/etc/sudoers.d/r109", "content": nativeSudoersGrant, "mode": "0440"}},
		{"two target keys", "Write", "", map[string]any{"file_path": "/etc/sudoers.d/r109", "path": "/work/x", "content": nativeSudoersGrant}},
		{"Bash is not a file tool", "Bash", "", map[string]any{"file_path": "/etc/sudoers.d/r109", "content": nativeSudoersGrant}},
	} {
		t.Run(row.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: row.tool, Args: nativeSudoersArgs(t, row.args), CWD: row.cwd})
			if ExactPOSIXUnrestrictedSudoersGrantWrite(facts) {
				t.Fatalf("a benign call produced a sudoers grant proof: %s", row.args)
			}
		})
	}
}

// TestNativeFileWriteSudoersTargetSpelledWithJSONEscapes: a target written with
// JSON escapes is the same file once decoded, so the cheap pre-filter must not
// hide it.
func TestNativeFileWriteSudoersTargetSpelledWithJSONEscapes(t *testing.T) {
	linksEtcForTest(t, true)
	for _, args := range []string{
		`{"file_path":"/etc/sudoers.d/r109","content":"r109yem5 ALL=(ALL) NOPASSWD: ALL\n"}`,
		`{"file_path":"\/etc\/SUDOERS.d\/r109","content":"r109yem5 ALL=(ALL) NOPASSWD: ALL\n"}`,
		`{"file_path":"/etc/\u0073udoers.d/r109","content":"r109yem5 ALL=(ALL) NOPASSWD: ALL\n"}`,
	} {
		facts := Analyze(Input{Tool: "Write", Args: json.RawMessage(args)})
		if !ExactPOSIXUnrestrictedSudoersGrantWrite(facts) {
			t.Errorf("no grant proof for %s: %#v", args, facts.Parse)
		}
	}
	facts := Analyze(Input{Tool: "Write", Args: json.RawMessage(
		`{"file_path":"/home/u/sudo/notes","content":"r109yem5 ALL=(ALL) NOPASSWD: ALL\n"}`)})
	if ExactPOSIXUnrestrictedSudoersGrantWrite(facts) {
		t.Error("a project file produced a grant proof")
	}
}
