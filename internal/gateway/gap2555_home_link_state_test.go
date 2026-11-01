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

// A write through a link the command makes to DefenseClaw state is the
// state write however the command spells the link name: relative, ~/,
// $HOME, ${HOME}, quoted "$HOME/..." or the literal home path, in a list,
// after && or in a ( ... ) subshell (GAP-2555, as GAP-2522 for the relative
// name). Links to ordinary directories and home writes beside them stay
// allowed.
func TestR105HomeSpelledLinkToStateBlocks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX link forms")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".defenseclaw", "hooks"), filepath.Join(home, ".ssh"),
		filepath.Join(home, "src"), cwd} {
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
	t.Setenv("HOME", home)
	rows := []struct {
		command string
		block   bool
	}{
		{"ln -s ~/.defenseclaw/hooks hk && cp a.txt hk/x.sh", true},
		{"ln -s ~/.defenseclaw/hooks ~/hk; cp a.txt ~/hk/x.sh", true},
		{"( ln -s ~/.defenseclaw/hooks ~/hk ) ; cp a.txt ~/hk/x.sh", true},
		{"ln -s ~/.defenseclaw/hooks ~/hk && cp a.txt ~/hk/x.sh", true},
		{"ln -s ~/.defenseclaw/hooks $HOME/hk; cp a.txt $HOME/hk/x.sh", true},
		{"ln -s ~/.defenseclaw/hooks ${HOME}/hk; cp a.txt ${HOME}/hk/x.sh", true},
		{"ln -s \"$HOME/.defenseclaw/hooks\" \"$HOME/hk\"; cp a.txt \"$HOME/hk/x.sh\"", true},
		{"ln -s {H}/.defenseclaw/hooks {H}/hk; cp a.txt {H}/hk/x.sh", true},
		{"ln -s ~/.defenseclaw/hooks ~/hk; echo x > ~/hk/x.sh", true},
		{"ln -s ~/.defenseclaw ~/dc; cp a.txt ~/dc/config.yaml", true},
		{"ln -s ~/.defenseclaw/hooks ~/hk; tee ~/hk/x.sh < a.txt", true},
		{"ln -s ~/src ~/hk; cp a.txt ~/hk/x.sh", false},
		{"ln -s ~/src hk; cp a.txt ~/x.sh; ls", false},
		{"ln -s ~/.defenseclaw/hooks ~/hk; ls ~/hk", false},
		{"cp a.txt ~/x.sh", false},
	}
	replacer := strings.NewReplacer("{H}", home)
	for _, connector := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connector)
		for _, hint := range []actionfacts.Dialect{"", actionfacts.DialectPOSIX} {
			for _, row := range rows {
				command := replacer.Replace(row.command)
				input := actionfacts.Input{Tool: "Bash", Command: command, CWD: cwd, ActiveHome: home, DialectHint: hint}
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{Input: input, Connector: connector, EnforcementCapable: true})
				blocked := buildVerdict(findings, "tool_call").Action == "block"
				if blocked != row.block {
					t.Errorf("%s hint=%q %q: block=%v, want %v (%s)", connector, hint, row.command, blocked, row.block,
						strings.Join(FindingStrings(findings), ","))
				}
				if row.block && !strings.Contains(strings.Join(FindingStrings(findings), ","), "tamper.detector_state_write") {
					t.Errorf("%s hint=%q %q: want tamper.detector_state_write, got %s", connector, hint, row.command,
						strings.Join(FindingStrings(findings), ","))
				}
			}
		}
	}
}
