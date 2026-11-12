// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// rel-1-0-6:GAP-0630 latency: a login-guess reading of a command proves only a
// write to DefenseClaw state, so the gateway judges it in full only where the
// path decision of its text finds a protected write. A command that names
// USER or LOGNAME where the guess reaches no state (an argument, a log file, a
// project file) is not judged a second time; the state spelled through the
// home login, a link to it and a managed hook reading still are.
func TestLoginGuessReadingIsJudgedOnlyWhereItMayReachState(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell rows")
	}
	home := filepath.Join(t.TempDir(), "alice")
	project := filepath.Join(home, "proj")
	state := filepath.Join(home, ".defenseclaw", "config.yaml")
	for _, dir := range []string{project, filepath.Dir(state)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(state, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(home, "statealias")
	if err := os.Symlink(state, alias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	request := func(managed bool) trustedActionRequest {
		return trustedActionRequest{
			Input: actionfacts.Input{Tool: "Bash", CWD: project, ActiveHome: home,
				DialectHint: actionfacts.DialectPOSIX},
			targetMemo:        hookpaths.NewTargetMemo(),
			ProtectedHomeHook: managed,
		}
	}
	for _, row := range []struct {
		name, text string
		managed    bool
		want       bool
	}{
		{"an argument", "echo marker \x27alice\x27", false, false},
		{"a log file", "echo marker > \x27/var/tmp/dc-alice.log\x27", false, false},
		{"a project file", "echo marker > \x27" + project + "/out.log\x27", false, false},
		{"the config file", "printf x > \x27" + state + "\x27", false, true},
		{"a link to the config file", "printf x > \x27" + alias + "\x27", false, true},
		{"an argument of a managed hook", "echo marker \x27alice\x27", true, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := loginGuessReadingMayProveStateWrite(request(row.managed), actionfacts.SimpleCommand{Text: row.text}, project); got != row.want {
				t.Errorf("%q: judged = %v, want %v", row.text, got, row.want)
			}
		})
	}
}
