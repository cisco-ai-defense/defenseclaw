// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// A pathname pattern in the destination of cp or ln under the state of a
// Windows drive home (Git Bash, per-user action mode) names the state file
// it matches when the shell runs the call, as on Linux and macOS
// (TestLinkRsyncAndPatternStateWrites). StateGlobTwin read only a pattern
// that starts with /, so on Windows cp a.txt ~/.defenseclaw/conf*.yaml,
// ~/.def*/config.yaml and ln -sf a.txt ~/.def*/config.yaml wrote
// config.yaml with no finding (GAP-2573, T10x dc-fc-r105-oss-win2 KG01-KG04,
// KN05).
func TestR105GAP2573DriveHomeGlobDestinationIntoState(t *testing.T) {
	home := "C:/Users/dcw-std1"
	if runtime.GOOS == "windows" {
		home = filepath.ToSlash(t.TempDir())
	} else {
		// On a POSIX build host the drive home is a relative path: the
		// state tree is created below the test cwd so the pattern reading
		// lists real names.
		t.Chdir(t.TempDir())
	}
	for _, dir := range []string{home + "/.defenseclaw/hooks", home + "/proj2"} {
		if err := os.MkdirAll(filepath.FromSlash(dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{home + "/.defenseclaw/config.yaml", home + "/proj2/a.txt"} {
		if err := os.WriteFile(filepath.FromSlash(name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	msys := "/" + strings.ToLower(home[:1]) + home[2:]
	rows := []struct {
		id, command string
		block       bool
	}{
		{"KG01", "cp a.txt ~/.defenseclaw/conf*.yaml", true},
		{"KN05", "cp a.txt ~/.defenseclaw/config.y?ml", true},
		{"KG02", "cp a.txt ~/.def*/config.yaml", true},
		{"KG03", "ln -sf a.txt ~/.def*/config.yaml", true},
		{"KG04", "cp a.txt ~/.defensecla[w]/config.yaml", true},
		{"home var", "cp a.txt $HOME/.defenseclaw/conf[i]g.yaml", true},
		{"drive spelling", "cp a.txt " + home + "/.defenseclaw/conf*.yaml", true},
		{"msys spelling", "cp a.txt " + msys + "/.defenseclaw/conf*.yaml", true},
		{"case of the state dir", "cp a.txt ~/.DefenseClaw/conf*.yaml", true},
		{"KB5 list", "ls ~/.def*", false},
		{"KB6 archive", "tar -cf /tmp/x.tar ~/.def*", false},
		{"list config", "ls ~/.defenseclaw/conf*.yaml", false},
		{"no match", "cp a.txt ~/.defenseclaw/nomatch*.yaml", false},
		{"project pattern", "cp a.txt ~/proj2/*.bak", false},
		{"copy state out", "cp ~/.defenseclaw/conf*.yaml ~/proj2/cfg-copy.yaml", false},
		{"link to the state", "ln -s ~/.def*/config.yaml ~/proj2/cfg-link", false},
	}
	for _, connectorName := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connectorName)
		for _, row := range rows {
			input := actionfacts.Input{Tool: "Bash", Command: row.command, CWD: home + "/proj2", ActiveHome: home}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, Connector: connectorName, EnforcementCapable: true,
			})
			if blocked := buildVerdict(findings, "tool_call").Action == "block"; blocked != row.block {
				t.Errorf("%s %s %q: block=%v, want %v", connectorName, row.id, row.command, blocked, row.block)
			}
		}
	}
}
