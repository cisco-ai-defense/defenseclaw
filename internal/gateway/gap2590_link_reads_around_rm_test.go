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

// GAP-2590 (live form): an agent checks the link around its removal (ls -l
// <link> && rm <link> && ls <link>; echo done). A read-only statement
// outside a pipeline that names a link a plain rm in the command removes
// reads the link, before or after the rm, not a key write target. A write
// through a link, a pipe into a writer and a read of the key file through
// the directory link in the same command still block.
func TestGAP2590ChecksAroundTheRmOfALink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX link forms")
	}
	rows := []struct {
		command string
		block   bool
	}{
		{"ls -l keylink && rm keylink", false},
		{"rm keylink && ls keylink", false},
		{"rm -f keylink; ls -l keylink; echo rm-done", false},
		{"ls -l keylink && rm keylink && ls keylink; echo rm-leg-done", false},
		{"cd CWD && ls -l keylink && rm keylink && ls keylink; echo rm-leg-done", false},
		{"rm keylink && echo x >> keylink", true},
		{"rm keylink && cp a.txt keylink", true},
		{"ls -l keylink && rm keylink && cat sshlink/authorized_keys", true},
		{"ls keylink | xargs rm; echo done", true},
		{"cat keylink | tee -a keylink; echo done", true},
		{"echo x | tee keylink; echo done", true},
		{"echo ssh-ed25519 AAAA >> keylink; echo done", true},
		{"echo done; cp a.txt keylink", true},
		{"rm sshlink/authorized_keys; echo done", true},
		{"ls keylink && rm -r sshlink/", true},
		{"echo $(cp a.txt keylink); echo done", true},
		{"cat keylink > out.txt && rm keylink", true},
		{"rm keylink && ln -s ~/.ssh/authorized_keys keylink && echo x >> keylink", true},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connector)
		for _, row := range rows {
			home, cwd := r104ReviewHome(t)
			command := strings.ReplaceAll(row.command, "CWD", cwd)
			sshDir := filepath.Join(home, ".ssh")
			for name, target := range map[string]string{"sshlink": sshDir, "keylink": filepath.Join(sshDir, "authorized_keys")} {
				if err := os.Symlink(target, filepath.Join(cwd, name)); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{"keys.tar", "a.txt"} {
				if err := os.WriteFile(filepath.Join(cwd, name), []byte("x\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": cwd,
				"tool_input": map[string]string{"command": command}})
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := hookpaths.Decode(hookpaths.Resolve(payload))
			if !ok {
				t.Fatal("client proof did not decode")
			}
			for _, hint := range []actionfacts.Dialect{"", actionfacts.DialectPOSIX} {
				input := actionfacts.Input{Tool: "Bash", Command: command, CWD: cwd, ActiveHome: home, DialectHint: hint}
				for route, request := range map[string]trustedActionRequest{
					"per-user": {Input: input, Connector: connector, EnforcementCapable: true},
					"managed": {Input: input, Connector: connector, EnforcementCapable: true,
						ProtectedHomeHook: true, ResolvedWriteTargets: targets},
				} {
					findings := dispatchTrustedAction(t.Context(), request)
					if blocked := buildVerdict(findings, "tool_call").Action == "block"; blocked != row.block {
						t.Errorf("%s %s hint=%q %q: block=%v, want %v (%v)", connector, route, hint, row.command, blocked, row.block, FindingStrings(findings))
					}
				}
			}
		}
	}
}
