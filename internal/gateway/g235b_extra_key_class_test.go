// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"strings"
	"testing"
)

// rel-1-0-6:GAP-0729 review 7: a native file-write call that carries
// DefenseClaw state in a key outside the tool's schema is a write of the
// state however many ordinary keys come first, whatever the key is called,
// and whether the path is rooted or relative to the working directory. A
// key that describes the call or holds the text it writes (description,
// note, content) is not a file the harness writes: a mention of the state
// there stays an ordinary write in every profile.
func TestG235bExtraKeyClass(t *testing.T) {
	type system struct{ name, home, cwd, project, state, relative string }
	posixHome, posixProject := dynamicWordParityProject(t)
	systems := []system{
		{"windows", `C:\Users\vn`, `C:\Users\vn\proj`, `C:\Users\vn\proj`, `C:\Users\vn\.defenseclaw\config.yaml`, `..\.defenseclaw\config.yaml`},
		{"posix", posixHome, posixProject, posixProject, posixHome + "/.defenseclaw/config.yaml", "../.defenseclaw/config.yaml"},
	}
	for _, sys := range systems {
		for _, managed := range []bool{false, true} {
			for _, pack := range []string{"", "strict", "permissive"} {
				for count := 0; count <= 12; count += 4 {
					input := map[string]any{"file_path": sys.project + "/notes.txt", "content": "x", "z_protected": sys.state}
					for i := 0; i < count; i++ {
						input[fmt.Sprintf("a%02d", i)] = sys.project + "/ordinary.txt"
					}
					if block, got := postFileToolCell(t, sys.home, sys.cwd, "Write", input, managed, pack); !block {
						t.Errorf("%s managed=%t pack=%q %d ordinary keys before the state: %.200s", sys.name, managed, pack, count, got)
					}
				}
				input := map[string]any{"file_path": sys.project + "/notes.txt", "content": "x", "f": sys.relative}
				// A Windows working directory is not readable by a gateway of
				// another operating system: that cell can name no file.
				if block, got := postFileToolCell(t, sys.home, sys.cwd, "Write", input, managed, pack); !block && sys.name == "posix" {
					t.Errorf("%s managed=%t pack=%q relative extra key: %.200s", sys.name, managed, pack, got)
				}
				for _, key := range []string{"description", "note", "comment", "content", "new_string", "title"} {
					input := map[string]any{"file_path": sys.project + "/notes.txt", "content": "x", key: sys.state}
					if _, got := postFileToolCell(t, sys.home, sys.cwd, "Write", input, managed, pack); strings.HasPrefix(got, `{"action":"block"`) {
						t.Errorf("%s managed=%t pack=%q %s mentions the state: %.200s, want allow", sys.name, managed, pack, key, got)
					}
				}
			}
		}
	}
}
