// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
)

// TestGAP0713RunnerReadOnlyWhereDefined is the CHK-T6-SCB hold of
// substrate-1:GAP-0713: a call f cd X is read as cd X only where the
// runner definition f() { "$@"; } has surely run. A definition after the
// call (the call runs a builtin of the name), or one in a list or branch
// that may not run, leaves the shell where it was as well, so the next
// relative operand keeps the verdict of its plain form there (strict), and
// never drops to an allow (default).
func TestGAP0713RunnerReadOnlyWhereDefined(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home rows: a relative operand of a home file is not placed from a Windows cwd, at rel 8a1e883539 as here (P49-FIX2 native probe)")
	}
	installCorrelationHMACForTest(t)
	home := filepath.Join(t.TempDir(), "home", "alice")
	if err := os.MkdirAll(filepath.Join(home, ".aws"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	plain := "rm .aws/credentials"
	rows := []string{
		`true cd /tmp && rm .aws/credentials; true() { "$@"; }`,
		`false && true() { "$@"; }; true cd /tmp && rm .aws/credentials`,
		`if false; then f(){ "$@"; }; fi; f cd /tmp && rm .aws/credentials`,
	}
	for _, pack := range []string{"default", "strict"} {
		handler := hostClaudeHookHandlerForTest(t, pack)
		n := 0
		verdict := func(cmd string) string {
			n++
			ev := claudeToolEvent("PreToolUse", "g0713d-"+pack+strconv.Itoa(n), "c"+strconv.Itoa(n), cmd)
			ev["cwd"] = home
			return callAgentHookForTest(t, handler, ev).Action
		}
		want := verdict(plain)
		if want == "allow" {
			t.Fatalf("%s: plain %q = allow, want it judged", pack, plain)
		}
		for index, row := range rows {
			got := verdict(row)
			if pack == "strict" && got != want || got == "allow" {
				t.Errorf("%s: row %d = %s, want %s (the plain form where the shell may stay; at least alert in default)", pack, index+1, got, want)
			}
		}
	}
}
