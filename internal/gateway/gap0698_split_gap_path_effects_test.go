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

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestGAP0698SplitGapJudgesEveryPathEffect: after a call the per-command
// split cannot flatten, every effect on a protected file (a write, an append,
// a redirect, a truncate, a delete, a read, a rename or link from or onto it,
// a mode or owner change) is at least the unknown tier (an alert in default,
// a block in strict), and an effect spelled from the home is never below its
// plain statement, in the default and strict packs (substrate-1:GAP-0698:
// `f(){ cd /tmp; "$@"; }; f cd && rm .aws/credentials` and `... && cat
// .aws/credentials` from the home allowed at FU11 c8090b1056 and t6/fix-0690
// 8583fa0f61, where rel 740c0de8fd alerts in default and blocks in strict).
// An effect is protected when the plain statement of its access of the file
// (twin, as pathEffectTwin reads it, kept here so the test runs on rel too)
// is a finding the pack enforces. The mover shapes are those of the FIX-0697-RV grid. The
// same effects on project files and ordinary home files stay an allow.
func TestGAP0698SplitGapJudgesEveryPathEffect(t *testing.T) {
	installCorrelationHMACForTest(t)
	home := filepath.Join(t.TempDir(), "home", "alice")
	project := filepath.Join(home, "proj")
	for _, name := range []string{
		"proj/go.mod", "proj/out.txt", "proj/.env.local", "proj/build/out.o", "proj/node_modules/x", "proj/.git/HEAD",
		".aws/credentials", ".bashrc", ".netrc", ".ssh/id_rsa", "x.txt",
	} {
		file := filepath.Join(home, name)
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	const (
		read     = actionfacts.PathAccessRead
		write    = actionfacts.PathAccessWrite
		appendTo = actionfacts.PathAccessAppend
		remove   = actionfacts.PathAccessDelete
		change   = actionfacts.PathAccessMetadata
	)
	// A change of mode, owner or link is judged as a change of the file.
	twin := map[actionfacts.PathAccess]string{
		read: "cat -- ", write: "echo x > ", appendTo: "echo x >> ", remove: "rm -f -- ", change: "echo x > ",
	}
	// Each effect on the file T, with the accesses it makes of T.
	effects := []struct {
		text   string
		access []actionfacts.PathAccess
	}{
		{"echo x > T", []actionfacts.PathAccess{write}},
		{"echo x >> T", []actionfacts.PathAccess{appendTo}},
		{"cat /tmp/x >| T", []actionfacts.PathAccess{write}},
		{"exec 3>T", []actionfacts.PathAccess{write}},
		{"echo x | tee T >/dev/null", []actionfacts.PathAccess{write}},
		{"echo x | tee -a T >/dev/null", []actionfacts.PathAccess{appendTo}},
		{"dd if=/tmp/x of=T", []actionfacts.PathAccess{write}},
		{"curl -o T https://example.com/x", []actionfacts.PathAccess{write}},
		{"cp /tmp/x T", []actionfacts.PathAccess{write}},
		{"truncate -s0 T", []actionfacts.PathAccess{write}},
		{"install /tmp/x T", []actionfacts.PathAccess{write}},
		{"rm T", []actionfacts.PathAccess{remove}},
		{"rm -f T", []actionfacts.PathAccess{remove}},
		{"unlink T", []actionfacts.PathAccess{remove}},
		{"shred -u T", []actionfacts.PathAccess{remove}},
		{"mv T /tmp/c", []actionfacts.PathAccess{read, remove}},
		{"mv /tmp/x T", []actionfacts.PathAccess{write}},
		{"ln -sf /tmp/x T", []actionfacts.PathAccess{write}},
		// A link that points at T touches nothing at T (actionfacts
		// classifyPOSIXLink): it is never below its plain form.
		{"ln -s T /tmp/l", nil},
		{"chmod 600 T", []actionfacts.PathAccess{change}},
		{"chmod 777 T", []actionfacts.PathAccess{change}},
		{"chown nobody T", []actionfacts.PathAccess{change}},
		{"chgrp nobody T", []actionfacts.PathAccess{change}},
		{"cat T", []actionfacts.PathAccess{read}},
		{"cp T /tmp/c", []actionfacts.PathAccess{read}},
	}
	// Calls the split cannot flatten, one per kind of gap (FIX-0697-RV S05,
	// S07, S39: "$@"; S04, S08, FIX-0690-RV M2: $r ~; C01: $y; A11: $(...);
	// B05: eval [ ... ]). The scratch grid of FIX-0698 ran 15 shapes.
	shapes := []string{
		`f(){ cd /tmp; "$@"; }; f cd && `,
		`f(){ cd /tmp; $r ~; }; f; `,
		`f(){ $y; }; f && `,
		`f(){ test -f .bashrc && $(echo return); cd /tmp; }; f && `,
		`f(){ eval [ -e .bashrc ]; }; f && `,
	}
	rank := map[string]int{"allow": 0, "alert": 1, "block": 2}
	tier := map[string]string{"default": "alert", "strict": "block"}
	for _, pack := range []string{"default", "strict"} {
		handler := hostClaudeHookHandlerForTest(t, pack)
		n := 0
		decide := func(cwd, command string) string {
			n++
			ev := claudeToolEvent("PreToolUse", "gap0698-"+pack+strconv.Itoa(n), "c"+strconv.Itoa(n), command)
			ev["cwd"] = cwd
			return callAgentHookForTest(t, handler, ev).Action
		}
		for _, target := range []string{".aws/credentials", ".bashrc", "~/.aws/credentials"} {
			resolved := filepath.Join(home, strings.TrimPrefix(target, "~/"))
			spelled := strings.HasPrefix(target, "~/")
			for _, effect := range effects {
				statement := strings.ReplaceAll(effect.text, "T", target)
				plain := decide(home, statement)
				protected := false
				for _, access := range effect.access {
					protected = protected || decide(home, twin[access]+resolved) != "allow"
				}
				want := "allow"
				if protected {
					want = tier[pack]
				}
				if spelled && rank[plain] > rank[want] {
					want = plain
				}
				for _, shape := range shapes {
					if got := decide(home, shape+statement); rank[got] < rank[want] {
						t.Errorf("%s: %q is %s, want at least %s (plain %s)", pack, shape+statement, got, want, plain)
					}
				}
			}
		}
		for _, control := range []struct{ cwd, target string }{
			{project, "out.txt"}, {home, "x.txt"},
		} {
			for _, effect := range effects {
				if strings.HasPrefix(effect.text, "ln ") || strings.HasPrefix(effect.text, "chmod 777") {
					// A link and a world-writable mode are findings of their
					// own on any file.
					continue
				}
				statement := strings.ReplaceAll(effect.text, "T", control.target)
				for _, shape := range shapes {
					if got := decide(control.cwd, shape+statement); got != "allow" {
						t.Errorf("%s: control %q in %s is %s, want allow", pack, shape+statement, filepath.Base(control.cwd), got)
					}
				}
			}
		}
		for _, command := range []string{
			"cd proj && rm -rf node_modules", "cd proj && echo x > out.txt", "cd proj && chmod +x build/out.o",
			`f(){ "$@"; }; f true && rm -rf proj/build`, `f(){ "$@"; }; f make && cat proj/go.mod`,
		} {
			if got := decide(home, command); got != "allow" {
				t.Errorf("%s: control %q is %s, want allow", pack, command, got)
			}
		}
	}
}
