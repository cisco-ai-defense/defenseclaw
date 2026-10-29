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

// A link the command makes to an outside directory that already holds a
// disk link to ~/.defenseclaw reaches the state file: the write through
// both links is the state write the direct spelling is (GAP-2534), plain,
// after a cd, nested, after an unrelated rename, as an in-place edit or a
// delete. Reads, writes beside the disk link and the links themselves stay
// allowed.
func TestR105CommandLinkThroughDiskLinkToStateBlocks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX link forms")
	}
	home := t.TempDir()
	ext := t.TempDir()
	cwd := filepath.Join(home, "w", "p")
	for _, dir := range []string{filepath.Join(home, ".defenseclaw", "hooks"), filepath.Join(home, ".ssh"),
		filepath.Join(cwd, "src")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{filepath.Join(home, ".defenseclaw", "config.yaml"),
		filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(cwd, "a.txt")} {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(home, ".defenseclaw"), filepath.Join(ext, "y")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(ext, "x")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	rows := []struct {
		command string
		block   bool
		direct  bool // judged without the hook's target map: not run as a managed call
	}{
		{"ln -s {E} e; echo z > e/y/config.yaml", true, false},
		{"ln -s {E} e; cd e/y && echo z > config.yaml", true, false},
		{"ln -s {E} e; bash -c \"cd e/y && echo z > config.yaml\"", true, false},
		{"ln -s {E} e; mv a.txt b.txt; echo z > e/y/config.yaml", true, false},
		{"ln -s {E} e; cp a.txt e/y/config.yaml", true, false},
		// A delete and an in-place edit are not writes the hook's map
		// lists: behind ProtectHome they are judged without it.
		{"ln -s {E} e; sed -i s/a/b/ e/y/config.yaml", true, true},
		{"ln -s {E} e; tee e/y/hooks/x.sh < a.txt", true, false},
		{"ln -s {E}/y e2; echo z > e2/config.yaml", true, false},
		{"ln -s {E} e; rm e/y/config.yaml", true, true},
		{"ln -s {E} e; echo k >> e/x/authorized_keys", true, false},
		{"echo z > {E}/y/config.yaml", true, true},
		{"ln -s {E} e; echo hi > e/notes.txt", false, false},
		{"ln -s {E} e; cat e/y/config.yaml", false, false},
		{"ln -s {E} e; ls e/y", false, false},
		{"ln -s {E}/y e3; rm e3", false, false},
		{"ln -s {E} e; cd e && echo hi > n.txt", false, false},
		{"ln -s src s; echo hi > s/out.txt", false, false},
		{"ln -s ~/.defenseclaw/config.yaml c; sed -i s/a/b/ c", false, false},
		{"ln -s ~/.defenseclaw/config.yaml c; cp a.txt c", true, false},
	}
	replacer := strings.NewReplacer("{E}", ext)
	for _, connector := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connector)
		// A managed hook behind ProtectHome: the gateway reads the client's
		// target map, resolved as the user through the command's links.
		for _, protected := range []bool{false, true} {
			for _, row := range rows {
				if protected && row.direct {
					continue
				}
				command := replacer.Replace(row.command)
				input := actionfacts.Input{Tool: "Bash", Command: command, CWD: cwd, ActiveHome: home}
				request := trustedActionRequest{Input: input, Connector: connector, EnforcementCapable: true,
					ProtectedHomeHook: protected}
				if protected {
					payload, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": cwd,
						"tool_name": "Bash", "tool_input": map[string]string{"command": command}})
					if err != nil {
						t.Fatal(err)
					}
					targets, ok := hookpaths.Decode(hookpaths.Resolve(payload))
					if !ok {
						t.Fatalf("%q: no client target map", command)
					}
					request.ResolvedWriteTargets = targets
				}
				findings := dispatchTrustedAction(t.Context(), request)
				if blocked := buildVerdict(findings, "tool_call").Action == "block"; blocked != row.block {
					ids := ""
					for _, finding := range findings {
						ids += finding.RuleID + " "
					}
					t.Errorf("%s protected=%v %q: block=%v, want %v (%s)", connector, protected, row.command, blocked, row.block, ids)
				}
			}
		}
	}
}
