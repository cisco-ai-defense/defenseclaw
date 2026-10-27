// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// TestR105ProtectHomeAWKOutputUsesClientTargets pins that a managed gateway
// that cannot read the user's home (ProtectHome) still blocks an awk call
// whose program writes through a link to ~/.ssh/authorized_keys: the literal
// print target of an inline program next to a dynamic input operand
// (GAP-2172, GAP-0498), the print target of a program file read with -f
// (GAP-2178, GAP-0508) and a target named by a variable the same command
// assigns (GAP-2197, GAP-0509). The user's hook reads the program as the
// user and lists the resolved output; the gateway judges that list. awk
// calls that only print, read or write a project file stay allowed.
func TestR105ProtectHomeAWKOutputUsesClientTargets(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway walk")
	}
	root := t.TempDir()
	homes := filepath.Join(root, "homes")
	home := filepath.Join(homes, "eng1")
	project := filepath.Join(home, "pcls9")
	keyDir := filepath.Join(home, ".ssh")
	for _, dir := range []string{keyDir, project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(keyDir, "authorized_keys")
	for file, data := range map[string]string{
		keys:                                 "",
		filepath.Join(project, "writer.awk"): "BEGIN { print \"marker\" >> \"alias\" }\n",
		filepath.Join(project, "report.awk"): "BEGIN { print \"marker\" >> \"report.txt\" }\n",
		filepath.Join(project, "read.awk"):   "{print}\n",
		filepath.Join(project, "data.txt"):   "d\n",
		filepath.Join(project, "input.txt"):  "d\n",
	} {
		if err := os.WriteFile(file, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(keys, filepath.Join(project, "alias")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	for _, tc := range []struct {
		text string
		want bool
	}{
		{`awk 'BEGIN {print "marker" >> "alias"}' "$input"`, true},
		{`awk 'BEGIN {print "marker" >> "alias"}' $input`, true},
		{`awk '/x/ {print "marker" > "alias"}' "$input"`, true},
		{`awk 'BEGIN {print "marker" >> "alias"}' input.txt`, true},
		{`awk -f writer.awk`, true},
		{`awk -f writer.awk data.txt`, true},
		{`awk -fwriter.awk input.txt`, true},
		{`gawk --file=writer.awk input.txt`, true},
		{`out=alias; awk "BEGIN {print \"# reviewed 2026-10-23\" >> \"$out\"}"`, true},
		{`awk "BEGIN {print $1 >> \"alias\"}" input.txt`, true},
		{`awk 'BEGIN {print "marker" >> "report.txt"}' "$input"`, false},
		{`awk -f read.awk input.txt`, false},
		{`awk -f report.awk input.txt`, false},
		{`awk '/print > "alias"/ {print}' "$input"`, false},
		{`out=report.txt; awk "BEGIN {print \"x\" >> \"$out\"}"`, false},
		{`awk '{print $1}' input.txt`, false},
	} {
		t.Run(tc.text, func(t *testing.T) {
			if err := os.Chmod(homes, 0o700); err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(map[string]any{"session_id": "gap2172", "hook_event_name": "PreToolUse",
				"tool_name": "Bash", "cwd": project, "tool_input": map[string]any{"command": tc.text}})
			if err != nil {
				t.Fatal(err)
			}
			evidence := hookpaths.Resolve(body)
			if err := os.Chmod(homes, 0); err != nil {
				t.Fatal(err)
			}
			got := overLimitHostHookWithEvidence(t, "claudecode", home, string(body), evidence)
			if blocked := nativeWriteBlocked(t, got); blocked != tc.want {
				decoded, _ := hookpaths.Decode(evidence)
				t.Fatalf("blocked = %t, want %t: %.600s evidence=%q", blocked, tc.want, got, decoded)
			}
		})
	}
}
