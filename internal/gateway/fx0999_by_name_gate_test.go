// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/fixturefs"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// fx0999GateCommands are the calls the by-name gate is pinned on: the
// FIX-0999 probe's 105 (testdata/fx0999_by_name_gate.json: the folder's
// spellings and the RV-0922 ordinary rows), and the GAP-1022 classes with
// each copy verb: a name built from the call's own variables, any pattern
// once the call may turn on dotglob, and a nested shell.
func fx0999GateCommands(t *testing.T, home string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "fx0999_by_name_gate.json"))
	if err != nil {
		t.Fatal(err)
	}
	var commands []string
	if err := json.Unmarshal(data, &commands); err != nil {
		t.Fatal(err)
	}
	for i, command := range commands {
		commands[i] = strings.ReplaceAll(command, "{cwd}", home)
	}
	for _, verb := range []string{"tar cz %s", "cp -r %s /tmp/x", "zip -r /tmp/k.zip %s", "rsync -a %s/ /tmp/b/"} {
		v := func(operand string) string { return fmt.Sprintf(verb, operand) }
		commands = append(commands,
			"x=s; "+v("~/.s${x}h"), "x=s; "+v("~/.s$x\"h\""), "S=.s; "+v("~/${S}sh"), "S=.ss; "+v("~/${S}h"),
			"a=.s b=s c=h; "+v("~/$a$b$c"), "P=s; "+v("~/.${P}${P}h"), "x=s; "+v("~/.s${x:-s}h"), v("~/.s${x:-s}h"),
			"x=s; "+v("${HOME}/.s${x}h"), "x=s; "+v("$HOME/.s${x}h"), "D=~/.s; "+v("${D}sh"),
			"for x in s; do "+v("~/.s${x}h")+"; done", "read x <<< s; "+v("~/.s${x}h"), "x=s; cd ~ && "+v(".s${x}h"),
			"shopt -s dotglob; "+v("*"), "GLOBIGNORE=x; "+v("*"), "shopt -s dotglob; "+v("?ssh"),
			"GLOBIGNORE=.; "+v("~/*"), "setopt globdots; "+v("*"), "shopt -s dotglob; cd ~ && "+v("*"),
			"sh -c \"x=s; "+v("~/.s\\${x}h")+"\"", "bash -c \"x=s; "+v("~/.s\\${x}h")+"\"",
			"bash -c 'S=.s; "+v("~/${S}sh")+"'", "sh -c \"shopt -s dotglob; "+v("*")+"\"",
			// GAP-1023: no dotglob, so none of these selects .ssh.
			v("~/*"), v("~/?ssh"), v("*"), v("?ssh"))
	}
	return commands
}

// TestFX0999GateNeverSkipsAByNameDecision: the lexical gate on the by-name
// reading (copyModeCallMayNameSSHFolder) is for speed only, so it never says
// "cannot name the SSH folder" for a call the reading itself decides
// protected (substrate-1 GAP-1022: 13 such calls, 11 of which the actor
// then allowed where the laptop blocks).
func TestFX0999GateNeverSkipsAByNameDecision(t *testing.T) {
	home := sandboxauth.SandboxHome
	commands := fx0999GateCommands(t, home)
	rows, passed, decided := 0, 0, 0
	for _, cwd := range []string{home, home + "/src"} {
		for _, command := range commands {
			rows++
			gate := copyModeCallMayNameSSHFolder(command, cwd, home)
			var decision string
			fixturefs.Unread(func() {
				decision = hookpaths.NewTargetMemo().ActionCommandDecisionInShell(command, cwd, home, nil, true)
			})
			if gate {
				passed++
			}
			if decision != "" {
				decided++
				if !gate {
					t.Errorf("cwd %s: %q: the reading decides %q, the gate skips it", cwd, command, decision)
				}
			}
		}
	}
	t.Logf("FX0999GATE rows=%d gate=%d decided=%d", rows, passed, decided)
}

// TestGAP1022And1023ActorAnswersAsTheLaptop: every connector's copy-mode
// actor answers these own SSH folder spellings as the laptop does. The
// GAP-1022 rows build the name from the call's variables, turn dotglob on
// or nest a shell: the laptop blocks them, the actor allowed them. The
// GAP-1023 rows name no .ssh, as bash's * and ? skip a leading dot: the
// laptop, the parent and rel allow them, the actor blocked them.
func TestGAP1022And1023ActorAnswersAsTheLaptop(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	rows := []string{
		"x=s; tar cz ~/.s${x}h", "S=.s; tar cz ~/${S}sh", "S=.ss; tar cz ~/${S}h", "a=.s; b=s; c=h; tar cz ~/$a$b$c",
		"P=s; tar cz ~/.${P}${P}h", "x=s; tar cz ~/.s${x:-s}h", "x=s; tar cz ${HOME}/.s${x}h", "D=~/.s; tar cz ${D}sh",
		"shopt -s dotglob; tar cz *", "GLOBIGNORE=x; tar cz *", "sh -c \"x=s; tar cz ~/.s\\${x}h\"",
	}
	// The GAP-1023 rows also cover Codex exec_command: a missing guest home
	// has no startup files that could enable dotglob (GAP-1024).
	benign := []string{"tar cz ~/*", "cp -r ~/?ssh /tmp/x", "tar cz *"}
	for _, s := range gap0545Shapes() {
		rows := append(slices.Clone(rows), benign...)
		t.Run(s.name, func(t *testing.T) {
			api, actor, home, _ := gap0545API(t, s.connector, "default")
			gap0922Layout(t, home)
			for _, command := range rows {
				body := func(cwd string) []byte { b, _ := json.Marshal(s.body(command, cwd)); return b }
				la, lr := gap0545Verdict(t, api, context.Background(), s, body(home))
				ca, cr := gap0545Verdict(t, api, actor, s, body(sandboxauth.SandboxHome))
				if gap0545Rank(ca, cr) != gap0545Rank(la, lr) {
					t.Errorf("%q: actor %s %v, laptop %s %v", command, ca, cr, la, lr)
				}
			}
		})
	}
}

// TestFX0999GateInheritedDotglob keeps the speed gate aligned with the
// by-name decision when shell options were inherited by the gateway.
func TestFX0999GateInheritedDotglob(t *testing.T) {
	home := sandboxauth.SandboxHome
	command := strings.Join([]string{"tar", "cz", "*"}, " ")
	for _, tc := range []struct{ name, bashopts, globignore string }{
		{"BASHOPTS", "dotglob", ""},
		{"GLOBIGNORE", "", "x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("BASHOPTS", tc.bashopts)
			t.Setenv("GLOBIGNORE", tc.globignore)
			if !copyModeCallMayNameSSHFolder(command, home, home) {
				t.Fatal("the gate skipped an inherited dotglob pattern")
			}
			var decision string
			fixturefs.Unread(func() {
				decision = hookpaths.NewTargetMemo().ActionCommandDecisionInShell(command, home, home, nil, true)
			})
			if decision == "" {
				t.Fatal("the by-name decision did not see an inherited dotglob pattern")
			}
		})
	}
}
