// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"reflect"
	"strings"
	"testing"
)

const staticRedirectTarget = "/var/tmp/dc-static-target.txt"

func TestDynamicRedirectTargetReduction(t *testing.T) {
	tests := []struct {
		name    string
		command string
		// static is the same command with every runtime-expanded target
		// replaced by staticRedirectTarget; the view must equal its complete
		// analysis without that target's redirects and paths.
		static  string
		reduced bool
		// kept is the number of static redirects left on the first command.
		kept int
		// programs are the view's commands, in order.
		programs []string
		// homeExact is set for a lone command whose only dynamic word is a
		// "~/" target: with an active home its analysis is complete
		// (rewriteTrustedPOSIXHomeTilde), so there is nothing to reduce.
		homeExact bool
	}{
		{name: "tilde target", command: "echo dc-block-marker > ~/dc-x.txt", static: "echo dc-block-marker > " + staticRedirectTarget, reduced: true, programs: []string{"echo"}, homeExact: true},
		{name: "HOME target", command: "echo dc-block-marker > $HOME/dc-x.txt", static: "echo dc-block-marker > " + staticRedirectTarget, reduced: true, programs: []string{"echo"}},
		{name: "quoted HOME append", command: `echo dc-block-marker >> "$HOME/dc-x.txt"`, static: "echo dc-block-marker >> " + staticRedirectTarget, reduced: true, programs: []string{"echo"}},
		{name: "glob target", command: "echo dc-block-marker > dc-*.txt", static: "echo dc-block-marker > " + staticRedirectTarget, reduced: true, programs: []string{"echo"}},
		{name: "static stderr kept", command: "echo dc-block-marker 2>/dev/null > ~/dc-x.txt", static: "echo dc-block-marker 2>/dev/null > " + staticRedirectTarget, reduced: true, kept: 1, programs: []string{"echo"}, homeExact: true},
		{name: "pipeline", command: "echo dc-block-marker | cat > ~/dc-x.txt", static: "echo dc-block-marker | cat > " + staticRedirectTarget, reduced: true, programs: []string{"echo", "cat"}},
		// A complete analysis expands these wrappers; the view has their
		// child commands, as the static-target form does.
		{name: "shell wrapper", command: "bash -c 'echo hi' > ~/x.txt", static: "bash -c 'echo hi' > " + staticRedirectTarget, reduced: true, programs: []string{"bash", "echo"}, homeExact: true},
		{name: "sudo wrapper", command: "sudo systemctl status sshd > ~/x.txt", static: "sudo systemctl status sshd > " + staticRedirectTarget, reduced: true, programs: []string{"sudo", "systemctl"}, homeExact: true},

		{name: "static directory with a parameter", command: "echo dc-block-marker > /tmp/dc-x-$USER.txt", static: "echo dc-block-marker > " + staticRedirectTarget, reduced: true, programs: []string{"echo"}},
		{name: "quoted static directory with a parameter", command: `echo dc-block-marker > "/tmp/dc-x-${USER}.txt"`, static: "echo dc-block-marker > " + staticRedirectTarget, reduced: true, programs: []string{"echo"}},

		{name: "dev directory with a parameter", command: "echo dc-block-marker > /dev/$OUT"},
		{name: "globbed dev directory with a parameter", command: "echo dc-block-marker > /d?v/tcp/$OUT"},
		{name: "root file with a parameter", command: "echo dc-block-marker > /dc-x-$USER.txt"},
		{name: "complete action", command: "echo dc-block-marker > /tmp/dc-x.txt"},
		{name: "any parameter", command: "echo dc-block-marker > $OUT"},
		{name: "parameter directory", command: "echo dc-block-marker > $OUT/dc-x.txt"},
		{name: "HOME with an operator", command: "echo dc-block-marker > ${HOME:-/tmp}/dc-x.txt"},
		{name: "substitution in the target", command: "echo dc-block-marker > ~/$(id -un).txt"},
		{name: "expanding argument", command: "echo $MARKER > /tmp/dc-x.txt"},
		{name: "expanding argument and target", command: "echo dc-block-marker $SUFFIX > ~/dc-x.txt"},
		{name: "expanding program", command: "$ECHO dc-block-marker > ~/dc-x.txt"},
		// && and || lists are read as sequences.
		{name: "chained with and", command: "cd /tmp && echo dc-block-marker > ~/dc-x.txt", static: "cd /tmp; echo dc-block-marker > " + staticRedirectTarget, reduced: true, programs: []string{"cd", "echo"}},
		{name: "chained with or", command: "echo dc-block-marker > ~/dc-x.txt || true", static: "echo dc-block-marker > " + staticRedirectTarget + "; true", reduced: true, programs: []string{"echo", "true"}},
		{name: "background", command: "echo dc-block-marker > ~/dc-x.txt &"},
		{name: "negated", command: "! echo dc-block-marker > ~/dc-x.txt"},
		{name: "descriptor copy", command: "echo dc-block-marker 2>&1 > ~/dc-x.txt"},
		{name: "prefix assignment", command: "MARKER=1 echo dc-block-marker > ~/dc-x.txt"},
		{name: "command substitution", command: "echo $(id -un) > ~/dc-x.txt"},
		{name: "wrapped target", command: "bash -lc 'echo dc-block-marker > ~/dc-x.txt'"},
		{name: "env wrapper", command: "env A=1 echo hi > ~/x.txt"},
		{name: "placeholder text in the command", command: "echo " + dynamicRedirectPlaceholderPrefix + "1 > ~/x.txt"},
	}
	for _, test := range tests {
		for _, home := range []string{"/home/alice", ""} {
			t.Run(test.name+"/home="+home, func(t *testing.T) {
				input := Input{
					Tool:        "shell",
					Command:     test.command,
					CWD:         "/repo",
					ActiveHome:  home,
					DialectHint: DialectPOSIX,
				}
				facts := Analyze(input)
				before := Analyze(input)
				reduced, twin, ok := DynamicRedirectTargetReduction(input, facts)
				if test.homeExact && home != "" {
					if !facts.Authoritative() || ok {
						t.Fatalf("parse=%+v reduced=%t, want a complete analysis and no reduction", facts.Parse, ok)
					}
					return
				}
				if ok != test.reduced {
					t.Fatalf("reduced = %t, want %t; parse=%+v commands=%+v",
						ok, test.reduced, facts.Parse, facts.Commands)
				}
				if !reflect.DeepEqual(facts, before) {
					t.Fatal("reduction changed its input")
				}
				if !ok {
					if !reflect.DeepEqual(reduced, Facts{}) || !reflect.DeepEqual(twin, Facts{}) {
						t.Fatalf("declined reduction returned facts: %+v %+v", reduced, twin)
					}
					return
				}
				if facts.Authoritative() || !reduced.Authoritative() ||
					len(reduced.Parse.Issues) != 0 ||
					reduced.Parse.Dialect != facts.Parse.Dialect {
					t.Fatalf("parse: action=%+v view=%+v", facts.Parse, reduced.Parse)
				}
				if !reduced.EnforcementEligible() {
					t.Fatalf("view is not enforcement eligible: %+v", reduced.Commands)
				}
				var programs []string
				for _, command := range reduced.Commands {
					programs = append(programs, command.Program)
					if !command.ArgvComplete {
						t.Fatalf("view command is not complete: %+v", command)
					}
					for _, redirect := range command.Redirects {
						if redirect.Expands || redirect.Target == "" {
							t.Fatalf("view kept a dynamic redirect: %+v", command.Redirects)
						}
					}
				}
				if !reflect.DeepEqual(programs, test.programs) {
					t.Fatalf("view programs = %v, want %v", programs, test.programs)
				}
				if !reflect.DeepEqual(reduced.Commands[0].Argv, facts.Commands[0].Argv) {
					t.Fatalf("first command argv changed: %v, action %v", reduced.Commands[0].Argv, facts.Commands[0].Argv)
				}
				if got := len(reduced.Commands[0].Redirects); got != test.kept {
					t.Fatalf("first command kept %d redirects, want %d", got, test.kept)
				}
				if mentionsString(reflect.ValueOf(reduced), dynamicRedirectPlaceholderPrefix, 0) {
					t.Fatalf("view carries a placeholder: %+v", reduced)
				}
				// The twin is the view with its placeholder targets.
				if !twin.Authoritative() ||
					!mentionsString(reflect.ValueOf(twin), dynamicRedirectPlaceholderPrefix, 0) ||
					!reflect.DeepEqual(withoutRedirectTarget(twin, "").Commands, withoutRedirectTarget(reduced, "").Commands) {
					t.Fatalf("twin is not the view with placeholder targets:\ntwin %+v\nview %+v", twin, reduced)
				}

				// The view is what a complete analysis of the same command
				// with a static target derives, without that target.
				staticInput := input
				staticInput.Command = test.static
				static := Analyze(staticInput)
				if !static.Authoritative() {
					t.Fatalf("static form is not complete: %+v", static.Parse)
				}
				want := withoutRedirectTarget(static, staticRedirectTarget)
				got := withoutRedirectTarget(reduced, staticRedirectTarget)
				if !reflect.DeepEqual(got.Commands, want.Commands) ||
					!reflect.DeepEqual(got.Paths, want.Paths) ||
					!reflect.DeepEqual(got.DataFlows, want.DataFlows) ||
					!reflect.DeepEqual(got.Network, want.Network) {
					t.Fatalf("view differs from the static-target analysis:\nview   %+v\nstatic %+v", got, want)
				}
			})
		}
	}
}

// withoutRedirectTarget drops target's redirects and path facts, and those
// of the placeholder targets.
func withoutRedirectTarget(facts Facts, target string) Facts {
	out := facts
	out.Commands = cloneCommands(facts.Commands)
	for index := range out.Commands {
		kept := []RedirectFact{}
		for _, redirect := range out.Commands[index].Redirects {
			if redirect.Target != target &&
				!strings.HasPrefix(redirect.Target, dynamicRedirectPlaceholderPrefix) {
				kept = append(kept, redirect)
			}
		}
		out.Commands[index].Redirects = kept
	}
	out.Paths = []PathFact{}
	for _, path := range facts.Paths {
		if path.Value != target && !strings.HasPrefix(path.Value, dynamicRedirectPlaceholderPrefix) {
			out.Paths = append(out.Paths, path)
		}
	}
	return out
}
