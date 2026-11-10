// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// linkedScriptFolder writes the writer wk.sh and the ordinary ok.sh below the
// project, and names the folder that holds them through a chain of links:
// the folder c below the project is a link to the real folder: a relative
// link (links below zero), an absolute one (zero) or the first of a chain of
// links links outside the project, the last of which is the real folder.
func linkedScriptFolder(t *testing.T, f b36ManagedHookFixture, links int) {
	t.Helper()
	real := filepath.Join(f.project, "real")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "wk.sh"), []byte("echo marker >> $HOME/.ssh/authorized_keys\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// safe.sh is the file the link chain helper opens to prove the chain works.
	for _, name := range []string{"ok.sh", "safe.sh"} {
		if err := os.WriteFile(filepath.Join(real, name), []byte("echo ordinary >> report.txt\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	target := "real"
	switch {
	case links == 0:
		// One link inside the working folder, to an absolute path.
		target = real
	case links > 0:
		target = gatewayLinkChain(t, links, real)
	}
	if err := os.Symlink(target, filepath.Join(f.project, "c")); err != nil {
		t.Skipf("link unavailable: %v", err)
	}
}

// TestSourcedWriterNamedThroughLinksIsBlockedInEverySpelling: the dot builtin
// and source read a script named by a relative, absolute or home-relative
// path through any number of folder links the system opens (40 on Linux, 32
// on macOS, 63 on Windows), top level or inside bash -c or sh -c, per-user
// and managed, and a write it makes to the keys file is blocked; the
// ordinary script behind the same links is allowed (rel-1-0-9:GAP-1013,
// GAP-1015, GAP-1017). A path through more links than the system opens is
// judged by the tier, see TestScriptNamedThroughLinksOutsideTheWorkingFolderIsReadOrUnread.
func TestSourcedWriterNamedThroughLinksIsBlockedInEverySpelling(t *testing.T) {
	limit := hookpaths.SystemLinkLimit()
	for _, links := range []int{-1, 0, 1, 2, 3, 8, 9, 10, 31, limit - 1} {
		t.Run(fmt.Sprintf("%d links", links), func(t *testing.T) {
			setup := func(t *testing.T, f b36ManagedHookFixture) { linkedScriptFolder(t, f, links) }
			var rows []r106Reader2Row
			for _, builtin := range []string{".", "source"} {
				rows = append(rows,
					r106Reader2Row{builtin + " relative", "project", builtin + ` ./c/wk.sh`, "block"},
					r106Reader2Row{builtin + " relative without dot", "project", builtin + ` c/wk.sh`, "block"},
					r106Reader2Row{builtin + " absolute", "project", builtin + ` {P}/c/wk.sh`, "block"},
					r106Reader2Row{builtin + " home-relative", "home", builtin + ` ~/project/c/wk.sh`, "block"},
					r106Reader2Row{builtin + " bash -c", "project", `bash -c "` + builtin + ` ./c/wk.sh"`, "block"},
					r106Reader2Row{builtin + " sh -c absolute", "project", `sh -c "` + builtin + ` {P}/c/wk.sh"`, "block"},
					r106Reader2Row{builtin + " ordinary relative", "project", builtin + ` ./c/ok.sh`, "allow"},
					r106Reader2Row{builtin + " ordinary absolute", "project", builtin + ` {P}/c/ok.sh`, "allow"},
					r106Reader2Row{builtin + " ordinary home-relative", "home", builtin + ` ~/project/c/ok.sh`, "allow"},
					r106Reader2Row{builtin + " ordinary bash -c", "project", `bash -c "` + builtin + ` ./c/ok.sh"`, "allow"},
				)
			}
			r106Reader2CheckWith(t, rows, setup)
		})
	}
}

// TestSourcedWriterIsJudgedWhereverItSitsInTheCommand: the verdict on a
// sourced writer behind folder links does not depend on the shell wrapper or
// the list it sits in. A block stops the whole call before any of it runs,
// so a source that a list or an exit may keep from running is judged as if
// it runs, at the top level, in a bash -c string and around one, exactly as
// the same command without the links is (rel-1-0-9:GAP-1013).
func TestSourcedWriterIsJudgedWhereverItSitsInTheCommand(t *testing.T) {
	setup := func(t *testing.T, f b36ManagedHookFixture) { linkedScriptFolder(t, f, 3) }
	var rows []r106Reader2Row
	for _, dir := range []string{"c", "real"} {
		rows = append(rows,
			r106Reader2Row{dir + " false and", "project", `false && . ./` + dir + `/wk.sh`, "block"},
			r106Reader2Row{dir + " true or", "project", `true || . ./` + dir + `/wk.sh`, "block"},
			r106Reader2Row{dir + " exit before", "project", `exit 0; . ./` + dir + `/wk.sh`, "block"},
			r106Reader2Row{dir + " wrapped false and", "project", `bash -c "false && . ./` + dir + `/wk.sh"`, "block"},
			r106Reader2Row{dir + " wrapped true or", "project", `bash -c "true || . ./` + dir + `/wk.sh"`, "block"},
			r106Reader2Row{dir + " wrapped exit before", "project", `bash -c "exit 0; . ./` + dir + `/wk.sh"`, "block"},
			r106Reader2Row{dir + " nested false and", "project", `bash -c "sh -c 'false && . ./` + dir + `/wk.sh'"`, "block"},
			r106Reader2Row{dir + " wrapper after false and", "project", `false && bash -c ". ./` + dir + `/wk.sh"`, "block"},
			r106Reader2Row{dir + " wrapper after exit", "project", `exit 0; bash -c ". ./` + dir + `/wk.sh"`, "block"},
			r106Reader2Row{dir + " combined flags", "project", `bash -ec ". ./` + dir + `/wk.sh"`, "block"},
		)
	}
	rows = append(rows,
		r106Reader2Row{"ordinary wrapped false and", "project", `bash -c "false && . ./c/ok.sh"`, "allow"},
		r106Reader2Row{"ordinary wrapper after exit", "project", `exit 0; bash -c ". ./c/ok.sh"`, "allow"},
		r106Reader2Row{"ordinary combined flags", "project", `bash -ec ". ./c/ok.sh"`, "allow"},
	)
	r106Reader2CheckWith(t, rows, setup)
}

// TestSourcedWriterBehindLinksIsBlockedUnderAnyShellLauncher: a login or
// interactive shell, zsh, and a sudo, env, nohup, timeout, command or exec
// launcher around a shell command string read the script behind folder links
// and judge it as the bare bash -c does, with or without the links
// (rel-1-0-9:GAP-1021).
func TestSourcedWriterBehindLinksIsBlockedUnderAnyShellLauncher(t *testing.T) {
	launchers := []string{
		`bash -c`, `bash -l -c`, `bash -lc`, `bash --login -c`, `bash -i -c`, `bash -ec`, `bash -lec`,
		`sh -c`, `zsh -c`, `zsh -ic`,
		`sudo bash -c`, `sudo -u root bash -c`, `env bash -c`, `env -i bash -c`, `env A=1 sh -c`,
		`sudo env bash -c`, `nohup bash -c`, `timeout 5 bash -c`, `command bash -c`, `exec bash -c`,
	}
	for _, links := range []int{3, 9, hookpaths.SystemLinkLimit() - 1} {
		t.Run(fmt.Sprintf("%d links", links), func(t *testing.T) {
			var rows []r106Reader2Row
			for _, launcher := range launchers {
				rows = append(rows,
					r106Reader2Row{launcher + " through links", "project", launcher + ` ". ./c/wk.sh"`, "block"},
					r106Reader2Row{launcher + " without links", "project", launcher + ` ". ./real/wk.sh"`, "block"},
					r106Reader2Row{launcher + " ordinary through links", "project", launcher + ` ". ./c/ok.sh"`, "allow"},
				)
			}
			r106Reader2CheckWith(t, rows, func(t *testing.T, f b36ManagedHookFixture) { linkedScriptFolder(t, f, links) })
		})
	}
}
