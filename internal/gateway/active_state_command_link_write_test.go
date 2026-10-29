// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// A write through a link the same command makes to DefenseClaw state is the
// state write, as the same alias of ~/.ssh is the authorized_keys write
// (GAP-2522, GAP-1521). Links that are not written through, reads through a
// state link, removal of the link itself and links into the project stay
// allowed.
func TestWriteThroughCommandLinkToActiveStateBlocks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX link forms")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".defenseclaw", "hooks"), filepath.Join(home, ".ssh"),
		filepath.Join(home, ".local", "bin"), filepath.Join(cwd, "src")} {
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
		{"ln -s ~/.defenseclaw hc; cp a.txt hc/config.yaml", true},
		{"nohup ln -s ~/.defenseclaw hc; cp a.txt hc/config.yaml", true},
		{"env A=1 ln -s ~/.defenseclaw hc; cp a.txt hc/config.yaml", true},
		{"sudo ln -s ~/.defenseclaw hc; cp a.txt hc/config.yaml", true},
		{"ln -s ~/.defenseclaw/hooks hh; cp a.txt hh/x.sh", true},
		{"ln -s ~/.defenseclaw/config.yaml c; cp a.txt c", true},
		{"ln -s ~/.defenseclaw hc && echo x > hc/config.yaml", true},
		{"busybox ln -s ~/.defenseclaw hc; cp a.txt hc/config.yaml", true},
		{"setsid ln -s ~/.defenseclaw hc; cp a.txt hc/config.yaml", true},
		{"time ln -s ~/.defenseclaw hc; tee hc/config.yaml < a.txt", true},
		{"nice ln -s ~/.defenseclaw hc; cp a.txt hc/config.yaml", true},
		{"ln -s ~/.defenseclaw hc; rm hc/config.yaml", true},
		{"ln -s ~/.defenseclaw hc; mv a.txt hc/config.yaml", true},
		{"ln -s ~/.ssh sd; cp a.txt sd/authorized_keys", true},
		// A link made after a cd is placed in that directory, and an
		// in-place editor through a linked directory writes the state file.
		{"cd ~ && ln -s ~/.defenseclaw hc && cp project/a.txt hc/config.yaml", true},
		{"cd ~ && ln -s .defenseclaw hc && cp project/a.txt hc/config.yaml", true},
		{"cd .. && ln -s .defenseclaw hc && cp project/a.txt hc/config.yaml", true},
		{"cd ~ && ln -s .defenseclaw/hooks hh; cp project/a.txt hh/x.sh", true},
		{"cd ~; ln -s .defenseclaw hc; echo x > hc/config.yaml", true},
		{"ln -s ~/.defenseclaw hc; sed -i s/a/b/ hc/config.yaml", true},
		{"ln -s ~/.defenseclaw hc; perl -pi -e s/a/b/ hc/config.yaml", true},
		{"cd ~ && ln -s .defenseclaw hc && sed -i s/a/b/ hc/config.yaml", true},
		{"cd ~ && ln -s project/src s && cp project/a.txt s/b.txt", false},
		{"cd ~ && ln -s .defenseclaw dc && cat dc/config.yaml", false},
		{"cd ~ && ln -s .defenseclaw dc && cp dc/config.yaml project/backup.yaml", false},
		{"ln -s src s; sed -i s/a/b/ s/b.txt", false},
		{"cd src && ln -s ../a.txt b && sed -i s/x/y/ b", false},
		{"ln -s ~/.defenseclaw/config.yaml ~/project/cfg-link", false},
		{"ln -s ~/.defenseclaw dc; cat dc/config.yaml", false},
		{"ln -s ~/.defenseclaw dc; cp dc/config.yaml backup.yaml", false},
		{"ln -s ~/.defenseclaw/config.yaml c; rm c", false},
		{"ln -s src s; cp a.txt s/b.txt", false},
		{"ln -sf $(pwd)/a.txt ~/.local/bin/tool", false},
		{"nohup ln -s src s; echo x > s/out.txt", false},
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

// GNU sed -i --follow-symlinks rewrites the file a link names, so the
// operand is followed: directly, through an existing link, or through a
// link the same command makes (GAP-2529). Plain sed -i on a link replaces
// the link and leaves the state file alone.
func TestSedFollowSymlinksToActiveStateBlocks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX link forms")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".defenseclaw", "hooks"), filepath.Join(cwd, "src")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{filepath.Join(home, ".defenseclaw", "config.yaml"),
		filepath.Join(home, ".defenseclaw", "hooks", "x.sh"), filepath.Join(cwd, "a.txt"),
		filepath.Join(cwd, "src", "n.txt")} {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(home, ".defenseclaw", "config.yaml"), filepath.Join(cwd, "oldcfg")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(cwd, "a.txt"), filepath.Join(cwd, "alink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	rows := []struct {
		command string
		block   bool
	}{
		{"sed -i --follow-symlinks s/a/b/ ~/.defenseclaw/config.yaml", true},
		{"sed -i --follow-symlinks s/a/b/ oldcfg", true},
		{"ln -s ~/.defenseclaw/hooks/x.sh h; sed --follow-symlinks -i s/a/b/ h", true},
		{"cd ~ && ln -s .defenseclaw/config.yaml c && sed -i --follow-symlinks s/a/b/ c", true},
		{"ln -s ~/.defenseclaw/config.yaml cfg; sed -i --follow-symlinks s/a/b/ cfg", true},
		{"ln -s ~/.defenseclaw hc; gsed -i --follow-symlinks s/a/b/ hc/config.yaml", true},
		{"sed -i s/a/b/ ~/.defenseclaw/config.yaml", true},
		{"ln -s ~/.defenseclaw/config.yaml c; truncate -s0 c", true},
		// Controls: sed without --follow-symlinks replaces the link.
		{"ln -s ~/.defenseclaw/config.yaml c; sed -i s/a/b/ c", false},
		{"sed -i s/a/b/ oldcfg", false},
		// Benign twins on project files.
		{"sed -i --follow-symlinks s/a/b/ a.txt", false},
		{"sed -i --follow-symlinks s/a/b/ alink", false},
		{"ln -s src/n.txt n; sed -i --follow-symlinks s/a/b/ n", false},
		{"ln -s src s; sed --follow-symlinks -i s/a/b/ s/n.txt", false},
		{"sed --follow-symlinks -n 1p ~/.defenseclaw/config.yaml", false},
		// Abbreviated --follow-symlinks and -i clustered after another
		// short option (GAP-2529), and the cluster on the state path (GAP-2531).
		{"sed --fo -i s/a/b/ oldcfg", true},
		{"sed --follow -i s/a/b/ oldcfg", true},
		{"sed --fo -i s/a/b/ ~/.defenseclaw/config.yaml", true},
		{"sed -si --follow-symlinks s/a/b/ oldcfg", true},
		{"sed -ni --follow-symlinks p oldcfg", true},
		{"sed -Ei --follow-symlinks s/a/b/ oldcfg", true},
		{"sed -si --follow-symlinks s/a/b/ ~/.defenseclaw/config.yaml", true},
		{"ln -s ~/.defenseclaw/config.yaml c; sed -si --follow-symlinks s/a/b/ c", true},
		{"sed -si s/a/b/ ~/.defenseclaw/config.yaml", true},
		{"sed -Ei s/a/b/ ~/.defenseclaw/hooks/x.sh", true},
		{"sed -si s/a/b/ oldcfg", false},
		{"sed -si --follow-symlinks s/a/b/ a.txt", false},
		{"sed --fo -i s/a/b/ alink", false},
		{"sed -Ei s/a/b/ a.txt", false},
		{"sed -n -e 1p --fo oldcfg", false},
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
