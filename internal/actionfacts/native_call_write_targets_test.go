// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"slices"
	"testing"
)

// NativeCallWriteTargets names the files a call writes through a patch or file
// tool it runs itself: a typed file tool, and the literal apply_patch envelope
// of a shell here-document. Any other shell text names none.
func TestNativeCallWriteTargets(t *testing.T) {
	const envelope = "*** Begin Patch\n*** Add File: notes.txt\n+x\n*** End Patch\n"
	call := func(tool string, args map[string]any) Input {
		raw, _ := json.Marshal(args)
		return Input{Tool: tool, Args: raw, CWD: "/home/u/proj", ActiveHome: "/home/u"}
	}
	rows := []struct {
		name  string
		input Input
		want  []string
	}{
		{"typed write", call("Write", map[string]any{"file_path": "notes.txt", "content": "x"}), []string{"notes.txt"}},
		{"shell here-document", call("Bash", map[string]any{"command": "apply_patch <<'EOF'\n" + envelope + "EOF\n"}), []string{"notes.txt"}},
		{"patch in a called function", call("Bash", map[string]any{"command": "f() {\napply_patch <<'EOF'\n" + envelope + "EOF\n}\nf\n"}), nil},
		{"shell redirect", call("Bash", map[string]any{"command": "echo x > notes.txt"}), nil},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			got := NativeCallWriteTargets(row.input, Analyze(row.input))
			if !slices.Equal(got, row.want) && (len(got) != 0 || len(row.want) != 0) {
				t.Fatalf("targets = %v, want %v", got, row.want)
			}
		})
	}
}
