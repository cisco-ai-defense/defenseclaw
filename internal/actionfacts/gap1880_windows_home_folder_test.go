// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path/filepath"
	"slices"
	"testing"
)

// TestGAP1880StatementAfterAMayFailCDIsReadInTheHomeFolder pins
// rel-1-0-10:GAP-1880: after a cd that may fail, a statement is read in
// each folder the shell may be in, the folder an earlier cd under the home
// took it to included. Under a Windows home (C:\Users\alice) the working
// folder tracking gave up on ~ and on a step relative to a Windows folder,
// so that folder was dropped and a write through a variable there was read
// only in the hook's folder and the failed cd's target. The home and cwd are
// native paths of the host, so the rows hold the same on every OS.
func TestGAP1880StatementAfterAMayFailCDIsReadInTheHomeFolder(t *testing.T) {
	home := filepath.Join(t.TempDir(), "homes", "alice")
	cwd := filepath.Join(home, "project")
	state := filepath.Join(home, ".defenseclaw")
	for _, command := range []string{
		"cd ~/.defenseclaw; cd /nonexistent-g1880 || true; x=config.yaml; echo m > $x",
		"cd ~ && cd .defenseclaw; cd /nonexistent-g1880 || true; x=config.yaml; echo m > $x",
		"cd ~/.defenseclaw && f() { cd /nonexistent-g1880 || return; }; f; x=config.yaml; echo m > $x",
	} {
		input := Input{Tool: "Bash", Command: command, CWD: cwd, ActiveHome: home}
		commands := SimpleCommands(input, Analyze(input))
		if !slices.ContainsFunc(commands, func(c SimpleCommand) bool {
			return c.Text == "echo m > 'config.yaml'" && c.CWD == state
		}) {
			t.Errorf("%q: the write is not read in %s: %+v", command, state, commands)
		}
	}
}
