// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestGAP0711SplitGapReadAsRel: a call the split cannot read is judged at
// least as rel 740c0de8fd judged it, where a call of a function whose body
// moves the folder leaves the folder unresolved. A relative cd after such a
// call (`f(){ cd /tmp && "$@"; }; f cd && cd .aws && rm credentials` from the
// home) reached the home's credentials file and was an allow at FU11
// c8090b1056 and t6/fix-0690 71a784ca0e, where rel alerts in default and
// blocks in strict (substrate-1:GAP-0711, 40 rows). Many mode changes after
// such a call stay an allow as at rel: each is judged by its own command, in
// one twin per shape and folder, never by the call's text
// (substrate-1:GAP-0712, 15 rows).
func TestGAP0711SplitGapReadAsRel(t *testing.T) {
	installCorrelationHMACForTest(t)
	home := filepath.Join(t.TempDir(), "home", "alice")
	project := filepath.Join(home, "proj")
	names := []string{"proj/README.md", "proj/build.sh", "proj/.env", "proj/build/out.o", "proj/scripts/run.sh", ".aws/credentials", ".kube/config"}
	for i := 0; i < 20; i++ {
		names = append(names, "proj/a"+strconv.Itoa(i)+".txt", "a"+strconv.Itoa(i)+".txt")
	}
	for _, name := range names {
		file := filepath.Join(home, name)
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	// The four mover bodies of RV4 (N34and, A03, A06, A12).
	movers := []string{
		`f(){ cd /tmp && "$@"; }; f cd && `,
		`f(){ cd /tmp && $y; }; f && `,
		`f(){ pushd /tmp >/dev/null && "$@"; }; f cd && `,
		`f(){ cd /tmp; cd /var && "$@"; }; f cd && `,
	}
	type row struct{ cwd, tail string }
	security := []row{
		{home, "cd .aws && rm credentials"}, {home, "cd .aws && cat credentials"},
		{home, "cd .aws && echo x > credentials"}, {home, "{ cd .aws; rm credentials; }"},
		{home, "(cd .aws && rm credentials)"}, {home, "cd .aws; rm credentials"},
		{home, "pushd .aws && rm credentials"}, {home, "cd .aws && truncate -s 0 credentials"},
		{project, "cd ../.aws && rm credentials"}, {project, "cd .. && cd .aws && rm credentials"},
	}
	chain := func(sep string, n int) string {
		var commands []string
		for i := 0; i < n; i++ {
			commands = append(commands, "chmod +x a"+strconv.Itoa(i)+".txt")
		}
		return strings.Join(commands, sep)
	}
	mixed := "chmod +x a0.txt; chmod +x a1.txt; chmod 644 a2.txt a3.txt; chmod 755 scripts/run.sh; chmod +x build.sh; " +
		"chown nobody a4.txt; chmod 600 .env; chmod 644 README.md; chmod +x a5.txt; chmod +x a6.txt; chmod 644 a7.txt; chmod +x a8.txt"
	var controls []row
	for _, shape := range []string{`f(){ cd /tmp && "$@"; }; f make && `, movers[0]} {
		controls = append(controls,
			row{project, shape + "cd build && rm -f out.o"}, row{project, shape + "cd scripts && chmod +x run.sh"})
	}
	for _, shape := range []string{
		`f(){ cd /tmp; $r ~; }; f && `, movers[3], `f(){ $y; }; f && `, `f(){ eval [ -e .bashrc ]; }; f && `,
	} {
		controls = append(controls,
			row{project, shape + chain(" && ", 11)}, row{project, shape + chain(" && ", 20)}, row{project, shape + mixed})
	}
	for _, shape := range []string{movers[0], movers[1], movers[2], movers[3], `f(){ cd /tmp; "$@"; }; f cd && `, `f(){ cd /tmp; $r ~; }; f && `} {
		controls = append(controls, row{home, shape + chain(" && ", 20)})
	}
	rank := map[string]int{"allow": 0, "alert": 1, "block": 2}
	tier := map[string]string{"default": "alert", "strict": "block"}
	for _, pack := range []string{"default", "strict"} {
		handler := hostClaudeHookHandlerForTest(t, pack)
		n := 0
		decide := func(cwd, command string) string {
			n++
			ev := claudeToolEvent("PreToolUse", "gap0711-"+pack+strconv.Itoa(n), "c"+strconv.Itoa(n), command)
			ev["cwd"] = cwd
			return callAgentHookForTest(t, handler, ev).Action
		}
		for _, mover := range movers {
			for _, r := range security {
				if got := decide(r.cwd, mover+r.tail); rank[got] < rank[tier[pack]] {
					t.Errorf("%s: %q in %s is %s, want at least %s (rel)", pack, mover+r.tail, filepath.Base(r.cwd), got, tier[pack])
				}
			}
		}
		for _, r := range controls {
			if got := decide(r.cwd, r.tail); got != "allow" {
				t.Errorf("%s: control %q in %s is %s, want allow (rel)", pack, r.tail, filepath.Base(r.cwd), got)
			}
		}
	}
}
