// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestGAP0706LinkToProtectedFileIsItsRead is substrate-1:GAP-0706 part 3
// (ruling T6-LEAD10 2026-11-27): ln of a protected file, symbolic or hard,
// gets the verdict of the plain read of its target in each pack (default
// alert, strict block for a credential file, a system file alert,
// permissive allow). A relative target of a symbolic link is read in the
// folder of the link. A link to an ordinary file stays allowed.
func TestGAP0706LinkToProtectedFileIsItsRead(t *testing.T) {
	installCorrelationHMACForTest(t)
	home := filepath.Join(t.TempDir(), "home", "alice")
	for _, d := range []string{".aws", ".kube", "proj/app"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	app := filepath.Join(home, "proj", "app")
	rows := []struct{ cwd, link, read string }{
		{home, "ln -s ~/.aws/credentials /tmp/l", "cat ~/.aws/credentials"},
		{home, "ln -sf ~/.aws/credentials l", "cat ~/.aws/credentials"},
		{home, "ln -s ~/.aws/credentials /tmp/", "cat ~/.aws/credentials"},
		{home, "ln .aws/credentials /tmp/h", "cat .aws/credentials"},
		{home, "ln -s -t /tmp ~/.kube/config", "cat ~/.kube/config"},
		{home, "ln -s /etc/shadow /tmp/s", "cat /etc/shadow"},
		{app, "ln -s ../../.aws/credentials c", "cat ../../.aws/credentials"},
	}
	allowed := []struct{ cwd, cmd string }{
		{home, "ln -s ~/proj/README.md /tmp/r"},
		{app, "ln -s ../README.md README.md"},
		{home, "ln -s .aws/credentials /tmp/l"},
	}
	for _, pack := range []string{"default", "permissive", "strict"} {
		handler := hostClaudeHookHandlerForTest(t, pack)
		n := 0
		verdict := func(cwd, cmd string) string {
			n++
			ev := claudeToolEvent("PreToolUse", "g0706l-"+pack+strconv.Itoa(n), "c"+strconv.Itoa(n), cmd)
			ev["cwd"] = cwd
			return callAgentHookForTest(t, handler, ev).Action
		}
		for _, row := range rows {
			want := verdict(row.cwd, row.read)
			if pack != "permissive" && want == "allow" {
				t.Fatalf("%s: plain read %q = allow, want it judged", pack, row.read)
			}
			if got := verdict(row.cwd, row.link); got != want {
				t.Errorf("%s: %q = %s, want %s (the plain read of its target)", pack, row.link, got, want)
			}
		}
		for _, control := range allowed {
			if got := verdict(control.cwd, control.cmd); got != "allow" {
				t.Errorf("%s: control %q = %s, want allow", pack, control.cmd, got)
			}
		}
	}
}
