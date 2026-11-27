// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestGAP0700QuotedRelativeHomeWriteIsItsHomeSpelling is substrate-1:GAP-0700
// (the quoted rows): from the home, a write whose operand names a credential
// file with quotes, in part or whole, gets the verdict of the same write
// spelled from the home, in the default and strict packs. A quoted project
// file stays allowed.
func TestGAP0700QuotedRelativeHomeWriteIsItsHomeSpelling(t *testing.T) {
	installCorrelationHMACForTest(t)
	home := filepath.Join(t.TempDir(), "home", "alice")
	for _, d := range []string{".aws", "proj"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	targets := []struct{ plain, quoted string }{
		{".aws/credentials", `.aws/"credentials"`},
		{".aws/credentials", `".aws/credentials"`},
		{".aws/credentials", `'.aws/credentials'`},
		{".npmrc", `".npmrc"`},
		{".git-credentials", `'.git-credentials'`},
	}
	forms := []string{"cp /tmp/x %s", "echo x > %s"}
	for _, pack := range []string{"default", "strict"} {
		handler := hostClaudeHookHandlerForTest(t, pack)
		n := 0
		verdict := func(cmd string) string {
			n++
			ev := claudeToolEvent("PreToolUse", "g0700q-"+pack+strconv.Itoa(n), "c"+strconv.Itoa(n), cmd)
			ev["cwd"] = home
			return callAgentHookForTest(t, handler, ev).Action
		}
		for _, target := range targets {
			for _, form := range forms {
				spelled := verdict(strings.Replace(form, "%s", "~/"+target.plain, 1))
				if spelled == "allow" {
					t.Fatalf("%s: %s of ~/%s = allow, want it judged", pack, form, target.plain)
				}
				if got := verdict(strings.Replace(form, "%s", target.quoted, 1)); got != spelled {
					t.Errorf("%s: %s of %s = %s, want %s (its ~/ spelling)", pack, form, target.quoted, got, spelled)
				}
			}
		}
		for _, control := range []string{`cp /tmp/x "proj/notes.txt"`, `echo x > 'proj/a b.txt'`} {
			if got := verdict(control); got != "allow" {
				t.Errorf("%s: control %q = %s, want allow", pack, control, got)
			}
		}
	}
}
