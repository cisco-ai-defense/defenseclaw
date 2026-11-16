// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// TestHomeFindArchiveStripSkipsSiblingsTheNameTestRefuses: find ~ -name
// "*.zip" -exec sh -c 'unzip -d "${1%.zip}" "$1"' strips each archive to
// its name, so only an archive named ~/.defenseclaw<suffix> could strip to
// the state root. A name beside the root that fails the find's name test
// (~/.defenseclaw.bak, ~/.defenseclaw-notes.md) is never handed to the
// script, so the benign watch row allows on OSS and managed (GAP-2597);
// an archive named ~/.defenseclaw.zip, a test after the action or an -o
// keep it blocked. On Windows the per-user gateway also judges the Git Bash
// drive view (/C:/Users/x), whose state root is the drive path the hook
// client listed.
func TestHomeFindArchiveStripSkipsSiblingsTheNameTestRefuses(t *testing.T) {
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		t.Skip("a hidden home is readable by root")
	}
	unzip := `-exec sh -c 'unzip -d "${1%.zip}" "$1"' _ {} \;`
	rows := []struct {
		id, command string
		siblings    []string
		block       bool
	}{
		{"BW2", `find ~ -name "*.zip" ` + unzip, []string{".defenseclaw.bak", ".defenseclaw-notes.md"}, false},
		{"BW2i", `find ~ -iname "*.ZIP" ` + unzip, []string{".defenseclaw.bak"}, false},
		{"BW2t", `find ~ -type f -name "*.zip" ` + unzip, []string{".defenseclaw.bak"}, false},
		{"BW9", `find ~ -name "*.zip" -exec sh -c 'mkdir -p "${1%.zip}"' _ {} \;`, []string{".defenseclaw.bak"}, false},
		{"BW2n", `find ~ -name "*.zip" ` + unzip, nil, false},
		{"A1", `find ~ -name "*.zip" ` + unzip, []string{".defenseclaw.zip"}, true},
		{"A2", `find ~ -iname "*.zip" ` + unzip, []string{".DefenseClaw.ZIP"}, true},
		{"A3", `find ~ -name "*.zip" -o -name "*.bak" ` + unzip, []string{".defenseclaw.bak"}, true},
		{"A4", `find ~ ` + unzip + ` -name "*.zip"`, []string{".defenseclaw.bak"}, true},
		{"A5", `find ~ ! -name "*.txt" ` + unzip, []string{".defenseclaw.bak"}, true},
	}
	// oss-gateway: no client map, so the per-user gateway lists the home
	// itself (a hook that sends the raw payload).
	for _, mode := range []string{"oss", "oss-gateway", "managed"} {
		managed := mode == "managed"
		if managed && runtime.GOOS == "windows" {
			// A Windows home is not hidden by a mode change; the Git Bash
			// drive view of a per-user call is what Windows adds (GAP-2577).
			continue
		}
		for _, connector := range []string{"claudecode", "codex"} {
			installDefaultProfileConnector(t, connector)
			for _, row := range rows {
				home := filepath.Join(t.TempDir(), "home")
				cwd := filepath.Join(home, "project")
				for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(home, ".defenseclaw", "hooks"), cwd} {
					if err := os.MkdirAll(dir, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				files := []string{filepath.Join(home, ".defenseclaw", "config.yaml"), filepath.Join(home, "t7d-scratch.zip")}
				for _, sibling := range row.siblings {
					files = append(files, filepath.Join(home, sibling))
				}
				for _, name := range files {
					if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				t.Setenv("HOME", home)
				payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": cwd,
					"tool_name": "Bash", "tool_input": map[string]string{"command": row.command}})
				targets, ok := hookpaths.Decode(hookpaths.ResolveConnector(connector, "", "", payload))
				if !ok {
					t.Fatalf("%s: client map does not decode", row.id)
				}
				if mode == "oss-gateway" {
					targets = nil
				}
				if managed {
					if err := os.Chmod(filepath.Dir(home), 0); err != nil {
						t.Fatal(err)
					}
				}
				input := actionfacts.Input{Tool: "Bash", Command: row.command, CWD: cwd, ActiveHome: home,
					DialectHint: actionfacts.DialectPOSIX}
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{Input: input, Connector: connector,
					EnforcementCapable: true, ProtectedHomeHook: managed, ResolvedWriteTargets: targets})
				if managed {
					if err := os.Chmod(filepath.Dir(home), 0o700); err != nil {
						t.Fatal(err)
					}
				}
				if blocked := buildVerdict(findings, "tool_call").Action == "block"; blocked != row.block {
					t.Errorf("%s %s %s %q: block=%v, want %v (%s)", mode, connector, row.id, row.command, blocked, row.block,
						strings.Join(FindingStrings(findings), ","))
				}
			}
		}
	}
}
