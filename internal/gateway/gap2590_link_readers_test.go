// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// GAP-2590: with links to ~/.ssh and to authorized_keys in the project, a
// tar listing, a uniq that prints and an rm of the link (which removes the
// link, not the key file) were denied as authorized-keys writes in action
// mode. They read, or remove only the link entry; writes through the links,
// an extraction into the linked directory, a uniq output file and an rm of
// the key file itself still block, per-user and managed, on both connectors.
func TestGAP2590BenignLinkReadersAndLinkRemoval(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX link forms")
	}
	rows := []struct {
		command string
		block   bool
	}{
		{"tar -C sshlink -tf keys.tar", false},
		{"tar tvf keys.tar -C sshlink", false},
		{"tar --list --file=keys.tar --directory=sshlink", false},
		{"uniq keylink", false},
		{"uniq -c -f 1 keylink", false},
		{"rm keylink", false},
		{"rm -f keylink", false},
		{"unlink keylink", false},
		{"echo x >> keylink", true},
		{"tar -C sshlink -xf keys.tar", true},
		{"tar -C sshlink -tf keys.tar --to-command=sh", true},
		{"uniq a.txt keylink", true},
		{"uniq keylink sshlink/authorized_keys", true},
		{"rm sshlink/authorized_keys", true},
		{"rm -r sshlink/", true},
		{"rm ~/.ssh/authorized_keys", true},
		{"rm keylink && echo x >> sshlink/authorized_keys", true},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connector)
		for _, row := range rows {
			home, cwd := r104ReviewHome(t)
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
				"tool_input": map[string]string{"command": row.command}})
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := hookpaths.Decode(hookpaths.Resolve(payload))
			if !ok {
				t.Fatal("client proof did not decode")
			}
			for _, hint := range []actionfacts.Dialect{"", actionfacts.DialectPOSIX} {
				input := actionfacts.Input{Tool: "Bash", Command: row.command, CWD: cwd, ActiveHome: home, DialectHint: hint}
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
