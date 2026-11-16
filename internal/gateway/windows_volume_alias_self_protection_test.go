// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// windowsVolumeSpellings lists the spellings of a file under the C: drive:
// the drive path, the \\?\ and \\.\ prefixes, the \\?\UNC\ form, and the
// \\localhost\C$ and \\127.0.0.1\C$ administrative shares.
func windowsVolumeSpellings(file string) []string {
	rest := strings.TrimPrefix(file, `C:\`)
	return []string{file, `\\?\` + file, `\\.\` + file, `\\?\UNC\localhost\C$\` + rest,
		`\\localhost\C$\` + rest, `\\127.0.0.1\C$\` + rest, `//localhost/C$/` + strings.ReplaceAll(rest, `\`, "/")}
}

// rel-1-0-6:GAP-0729: a file-tool write to DefenseClaw state is the write
// of the state file whichever spelling of the volume names it. A file of
// the project in the same spellings stays allowed. 8.3 short names and
// junctions need the Windows file system and are proved elsewhere.
func TestG235bWindowsVolumeAliasesOfStateAreSelfProtection(t *testing.T) {
	const home = `C:\Users\vn`
	state := home + `\.defenseclaw\config.yaml`
	project := home + `\proj\notes.txt`
	for _, tool := range []string{"Write", "Edit"} {
		for _, managed := range []bool{false, true} {
			for _, pack := range []string{"", "strict", "permissive"} {
				for _, protected := range []bool{true, false} {
					target := project
					if protected {
						target = state
					}
					for _, file := range windowsVolumeSpellings(target) {
						input := map[string]any{"file_path": file, "content": "x"}
						if tool == "Edit" {
							input = map[string]any{"file_path": file, "old_string": "a", "new_string": "b"}
						}
						block, got := postFileToolCell(t, home, home+`\proj`, tool, input, managed, pack)
						if protected && !block {
							t.Errorf("%s managed=%t pack=%s %s = %.160s, want protected block", tool, managed, pack, file, got)
						}
						if !protected && strings.HasPrefix(got, `{"action":"block"`) {
							t.Errorf("%s managed=%t pack=%s %s = %.160s, want allow", tool, managed, pack, file, got)
						}
					}
				}
			}
		}
	}
}

// rel-1-0-6:GAP-0729 review 6: a native file-write call that carries the
// file in a key outside the tool's schema (f, target, backup_path), with or
// without the reviewed key, is the write of that file in every spelling of
// the path and every profile. The same key holding a file of the project,
// or a directory key holding the state directory, stays allowed.
func TestG235bExtraKeyNamingStateIsSelfProtection(t *testing.T) {
	type system struct{ name, home, cwd, state, project, stateDir string }
	posixHome, posixProject := dynamicWordParityProject(t)
	systems := []system{{"windows", `C:\Users\vn`, `C:\Users\vn\proj`, `C:\Users\vn\.defenseclaw\config.yaml`, `C:\Users\vn\proj\notes.txt`, `C:\Users\vn\.defenseclaw`},
		{"posix", posixHome, posixProject, posixHome + "/.defenseclaw/config.yaml", posixProject + "/notes.txt", posixHome + "/.defenseclaw"}}
	for _, sys := range systems {
		spellings := []string{sys.state}
		if sys.name == "windows" {
			spellings = windowsVolumeSpellings(sys.state)
		}
		for _, key := range []string{"f", "target", "backup_path"} {
			for _, managed := range []bool{false, true} {
				for _, pack := range []string{"", "strict", "permissive"} {
					for _, file := range spellings {
						for _, withTarget := range []bool{true, false} {
							input := map[string]any{"content": "x", key: file}
							if withTarget {
								input["file_path"] = sys.project
							}
							if block, got := postFileToolCell(t, sys.home, sys.cwd, "Write", input, managed, pack); !block {
								t.Errorf("%s key=%s target=%t managed=%t pack=%s %s = %.160s, want protected block", sys.name, key, withTarget, managed, pack, file, got)
							}
						}
						// The reviewed key holding the state with an unrelated extra key.
						input := map[string]any{"file_path": file, "content": "x", "note": "y"}
						if block, got := postFileToolCell(t, sys.home, sys.cwd, "Write", input, managed, pack); !block {
							t.Errorf("%s note managed=%t pack=%s %s = %.160s, want protected block", sys.name, managed, pack, file, got)
						}
					}
					for _, input := range []map[string]any{
						{"file_path": sys.project, "content": "x", key: sys.project},
						{"file_path": sys.project, "content": "x", key: "not a path"},
						{"file_path": sys.project, "content": "x", "cwd": sys.stateDir},
						{"file_path": sys.project, "content": "x", "directory": sys.stateDir},
					} {
						if _, got := postFileToolCell(t, sys.home, sys.cwd, "Write", input, managed, pack); strings.HasPrefix(got, `{"action":"block"`) {
							t.Errorf("%s managed=%t pack=%s %v = %.160s, want allow", sys.name, managed, pack, input, got)
						}
					}
				}
			}
		}
	}
}
