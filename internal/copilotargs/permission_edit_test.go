// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package copilotargs

import (
	"strings"
	"testing"
)

// A native PermissionRequest shell call carries its command in toolInput as
// PreToolUse's toolArgs does (Copilot CLI 1.0.103:
// "toolName":"powershell","toolInput":{"command":"echo dc-ok"}); T7 read only
// an edit's diff there, so every shell call had no command and was blocked.
func TestPermissionToolArgsReadsTheShellCommand(t *testing.T) {
	for _, tool := range []string{"bash", "powershell"} {
		got := PermissionToolArgs(tool, map[string]any{"command": "echo ok"})
		if string(got) != `{"command":"echo ok"}` {
			t.Fatalf("%s: projected=%s", tool, got)
		}
	}
	if got := PermissionToolArgs("bash", nil); len(got) != 0 {
		t.Fatalf("null toolInput projected=%s", got)
	}
	if got := PermissionToolArgs("edit", map[string]any{"path": "/tmp/x", "old_str": "a", "new_str": "b"}); len(got) != 0 {
		t.Fatalf("edit outside the diff shape projected=%s", got)
	}
}

func TestPermissionEditArgsRequiresOneCompleteDeclaredDiff(t *testing.T) {
	const path = "/home/alice/project/notes.txt"
	base := "\ndiff --git a" + path + " b" + path + "\nindex 1234567..abcdef0 100644\n--- a" + path +
		"\n+++ b" + path + "\n@@ -1 +1 @@\n-old\n+new\n"
	for _, tc := range []struct {
		name, diff string
		valid      bool
	}{
		{"single file", base, true},
		{"two complete hunks", base + "@@ -3 +3 @@\n-before\n+after\n", true},
		{"second file", base + "diff --git a" + path + " b" + path + "\n", false},
		{"mismatched target", strings.Replace(base, "+++ b"+path, "+++ b/home/alice/project/other.txt", 1), false},
		{"missing line", strings.Replace(base, "+new\n", "", 1), false},
		{"extra line", base + "+hidden\n", false},
		{"rename metadata", strings.Replace(base, "index 1234567..abcdef0 100644", "rename from other.txt", 1), false},
		{"bare carriage return", base + "\r", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := PermissionEditArgs("edit", map[string]any{"file_path": path, "diff": tc.diff})
			if (len(got) > 0) != tc.valid {
				t.Fatalf("projected=%s, valid=%t", got, tc.valid)
			}
		})
	}
	if got := PermissionEditArgs("edit", map[string]any{"file_path": path, "diff": base, "another_path": "/tmp/hidden"}); len(got) != 0 {
		t.Fatalf("extra target became trusted: %s", got)
	}
}

func TestPermissionEditArgsNativeCreatedFileDiff(t *testing.T) {
	for _, path := range []string{"/home/alice/project/README.md", `C:\Users\alice\project\README.md`} {
		gitPath := strings.TrimPrefix(strings.ReplaceAll(path, `\`, "/"), "/")
		diff := "\ndiff --git a/" + gitPath + " b/" + gitPath +
			"\ncreate file mode 100644\nindex 0000000..0000000\n--- a/dev/null\n+++ b/" + gitPath +
			"\n@@ -1,0 +1,2 @@\n+first\n+second\n"
		got := PermissionEditArgs("edit", map[string]any{"file_path": path, "diff": diff})
		if len(got) == 0 || !strings.Contains(string(got), `"new_str":"first\nsecond"`) {
			t.Fatalf("native create diff %q projected=%s", path, got)
		}
		if bad := PermissionEditArgs("edit", map[string]any{"file_path": path,
			"diff": strings.Replace(diff, "+++ b/"+gitPath, "+++ b/other.txt", 1)}); len(bad) != 0 {
			t.Fatalf("mismatched created file projected=%s", bad)
		}
	}
}

// Copilot CLI 1.0.105 asks an apply_patch of context lines only as an edit
// whose diff has one empty hunk (managed AD RHEL, GAP-1832: the callback was
// HOOK-TOOL-CALL-UNPARSED and blocked in action mode). It projects onto an
// edit of the declared file with no text; any body line, a second hunk, a
// non-empty count or a created file stays unproven.
func TestPermissionEditArgsNoChangeDiffNamesItsFile(t *testing.T) {
	const path = "/home/dcad-r103-eng1@dclab.test/pah-proj/b.txt"
	head := "\ndiff --git a" + path + " b" + path + "\nindex 0000000..0000000 100644\n--- a" + path + "\n+++ b" + path + "\n"
	live := head + "@@ -0,0 +0,0 @@\n\n"
	got := PermissionEditArgs("edit", map[string]any{"file_path": path, "diff": live})
	if string(got) != `{"new_str":"","old_str":"","path":"`+path+`"}` {
		t.Fatalf("no-change diff projected=%s", got)
	}
	for name, diff := range map[string]string{
		"body line":       head + "@@ -0,0 +0,0 @@\n hidden\n",
		"second hunk":     head + "@@ -0,0 +0,0 @@\n@@ -0,0 +0,0 @@\n",
		"non-empty count": head + "@@ -1 +1 @@\n",
		"created file": "\ndiff --git a" + path + " b" + path + "\nnew file mode 100644\nindex 0000000..0000000\n--- a/dev/null\n+++ b" + path +
			"\n@@ -0,0 +0,0 @@\n",
		"other file": strings.Replace(live, "+++ b"+path, "+++ b/home/dcad-r103-eng1@dclab.test/.ssh/authorized_keys", 1),
	} {
		if got := PermissionEditArgs("edit", map[string]any{"file_path": path, "diff": diff}); len(got) != 0 {
			t.Fatalf("%s: projected=%s", name, got)
		}
	}
}
