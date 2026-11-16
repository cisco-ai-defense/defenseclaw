// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// A link made after a cd into a directory that does not exist yet, or inside
// a subshell, names the file its target spells from that directory: cd src
// && ln -s ../a.txt b links <cwd>/a.txt whether src exists yet or not, and is
// not an authorized_keys mutation (GAP-2550). A target that climbs out of
// such a directory into ~/.ssh, through a link the command makes, or a write
// through a link made inside a subshell, still blocks, on Windows (Git Bash) too, where the facts leave a relative
// POSIX operand unresolved.
func TestLinkAfterCdIntoMissingOrSubshellDirectory(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
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
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	rows := []struct {
		command string
		block   bool
	}{
		// The T10 Windows rows: newdir and ~/proj2 do not exist.
		{"cd newdir && ln -s ../a.txt b", false},
		{"cd newdir; ln -s ../a.txt b", false},
		{"cd ~/proj2 && ln -s ../a.txt b", false},
		{"cd ~/proj2 && ln -sf ../.defenseclaw/config.yaml cfg", false},
		{"cd newdir && ln -s ../a.txt b && sed -i s/x/y/ b", false},
		{"mkdir newdir && cd newdir && ln -s ../a.txt b && cat b", false},
		{"cd newdir/deeper && ln -s ../../a.txt b", false},
		{"(cd src && ln -s ../a.txt b)", false},
		{"(cd newdir && ln -s ../a.txt b)", false},
		{"(cd src && ln -s ../a.txt b) && ls src", false},
		{"(cd src && ln -s x y); ln -s ../a.txt b", false},
		// Still protected.
		{"cd newdir && ln -s ../../.ssh/authorized_keys k && echo x >> k", true},
		{"mkdir newdir && cd newdir && ln -s ../../.ssh/authorized_keys k && echo x >> k", true},
		{"ln -s ~/.ssh dl; cd dl/sub && ln -s ../authorized_keys k && echo x >> k", true},
		{"(cd src && ln -s ../../.ssh/authorized_keys k) && echo x >> src/k", true},
		{"(cd ~ && ln -s .ssh sd && cp project/a.txt sd/authorized_keys)", true},
		{"(cd ~ && ln -s .ssh sd) && cp a.txt ~/sd/authorized_keys", true},
		{"(cd ~ && ln -s .defenseclaw hc && cp project/a.txt hc/config.yaml)", true},
		{"cd ~ && ln -s .ssh sd && cp project/a.txt sd/authorized_keys", true},
		// A link named by a home path, or made in a subshell, and the write
		// after it through that home path (GAP-2555, RV-p3-1).
		{"ln -s ~/.defenseclaw/hooks ~/hk; cp a.txt ~/hk/x.sh", true},
		{"( ln -s ~/.defenseclaw/hooks ~/hk ) ; cp a.txt ~/hk/x.sh", true},
		{"( cd ~ && ln -s .defenseclaw/hooks hk ) ; cp a.txt ~/hk/x.sh", true},
		{"( cd ~ && ln -s ~/.defenseclaw/hooks hk ) ; cp a.txt ~/hk/x.sh", true},
		{"( cd ~ && ln -s .defenseclaw dc ) ; cp a.txt ~/dc/config.yaml", true},
		{"( cd ~ && ln -s .defenseclaw/config.yaml c ) ; echo x > ~/c", true},
		{"( cd ~ && ln -s .defenseclaw/hooks hk ) && echo x > ~/hk/x.sh", true},
		{"( cd ~ && ln -s .defenseclaw/hooks hk ) ; tee ~/hk/x.sh < a.txt", true},
		{"ln -s ~/.defenseclaw ~/dc && echo x >> ~/dc/config.yaml", true},
		{"( cd ~ && ln -s project/src s ) ; cp a.txt ~/s/b.txt", false},
		{"ln -s ~/project/src ~/s2; cp a.txt ~/s2/b.txt", false},
		{"( cd ~ && ln -s .defenseclaw dc ) ; cat ~/dc/config.yaml", false},
		{"ln -s ~/.defenseclaw/config.yaml ~/c; rm ~/c", false},
		{"ln -s ~/.defenseclaw ~/dc; cp ~/dc/config.yaml backup.yaml", false},
		{"cd ~ && ln -s .defenseclaw hc && cp project/a.txt hc/config.yaml", true},
		{"cd ~; ln -s .defenseclaw hc; cp project/a.txt hc/config.yaml", true},
		{"(cd ~; ln -s .defenseclaw hc; cp project/a.txt hc/config.yaml)", true},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connector)
		for _, hint := range []actionfacts.Dialect{"", actionfacts.DialectPOSIX} {
			for _, row := range rows {
				input := actionfacts.Input{Tool: "Bash", Command: row.command, CWD: cwd, ActiveHome: home, DialectHint: hint}
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{Input: input, Connector: connector, EnforcementCapable: true})
				if blocked := buildVerdict(findings, "tool_call").Action == "block"; blocked != row.block {
					ids := ""
					for _, finding := range findings {
						ids += finding.RuleID + " "
					}
					t.Errorf("%s hint=%q %q: block=%v, want %v (%s)", connector, hint, row.command, blocked, row.block, ids)
				}
			}
		}
	}
}
