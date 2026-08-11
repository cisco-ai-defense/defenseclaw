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

import "testing"

func TestParsePOSIXShellInvocationModesAndFinalNoExecState(t *testing.T) {
	tests := []struct {
		name             string
		program          string
		argv             []string
		wantMode         posixShellMode
		wantCommandIndex int
		wantScriptIndex  int
		wantNoExec       bool
	}{
		{
			name:             "bare bash reads stdin",
			program:          "bash",
			argv:             []string{"bash"},
			wantMode:         posixShellModeStdin,
			wantCommandIndex: -1,
			wantScriptIndex:  -1,
		},
		{
			name:             "plus ordinary option still reads stdin",
			program:          "bash",
			argv:             []string{"bash", "+e"},
			wantMode:         posixShellModeStdin,
			wantCommandIndex: -1,
			wantScriptIndex:  -1,
		},
		{
			name:             "short noexec is finally disabled for stdin",
			program:          "bash",
			argv:             []string{"bash", "-n", "+n"},
			wantMode:         posixShellModeStdin,
			wantCommandIndex: -1,
			wantScriptIndex:  -1,
		},
		{
			name:             "short noexec is finally enabled for stdin",
			program:          "bash",
			argv:             []string{"bash", "+n", "-n"},
			wantMode:         posixShellModeStdin,
			wantCommandIndex: -1,
			wantScriptIndex:  -1,
			wantNoExec:       true,
		},
		{
			name:             "named noexec is finally disabled for stdin",
			program:          "bash",
			argv:             []string{"bash", "-o", "noexec", "+o", "noexec"},
			wantMode:         posixShellModeStdin,
			wantCommandIndex: -1,
			wantScriptIndex:  -1,
		},
		{
			name:             "named noexec is finally enabled for stdin",
			program:          "bash",
			argv:             []string{"bash", "+o", "noexec", "-o", "noexec"},
			wantMode:         posixShellModeStdin,
			wantCommandIndex: -1,
			wantScriptIndex:  -1,
			wantNoExec:       true,
		},
		{
			name:             "shopt enable consumes its operand",
			program:          "bash",
			argv:             []string{"bash", "-O", "nullglob"},
			wantMode:         posixShellModeStdin,
			wantCommandIndex: -1,
			wantScriptIndex:  -1,
		},
		{
			name:             "shopt disable consumes its operand",
			program:          "bash",
			argv:             []string{"bash", "+O", "nullglob"},
			wantMode:         posixShellModeStdin,
			wantCommandIndex: -1,
			wantScriptIndex:  -1,
		},
		{
			name:             "bundled named options consume one operand each",
			program:          "bash",
			argv:             []string{"bash", "-oo", "errexit", "pipefail"},
			wantMode:         posixShellModeStdin,
			wantCommandIndex: -1,
			wantScriptIndex:  -1,
		},
		{
			name:             "bundled command and named option select body after value",
			program:          "bash",
			argv:             []string{"bash", "-oc", "pipefail", "printf safe"},
			wantMode:         posixShellModeCommand,
			wantCommandIndex: 3,
			wantScriptIndex:  -1,
		},
		{
			name:             "script follows consumed named option",
			program:          "bash",
			argv:             []string{"bash", "-eo", "pipefail", "/tmp/payload.sh"},
			wantMode:         posixShellModeScript,
			wantCommandIndex: -1,
			wantScriptIndex:  3,
		},
		{
			name:             "short noexec is finally disabled for command",
			program:          "sh",
			argv:             []string{"sh", "-n", "+n", "-c", "printf safe"},
			wantMode:         posixShellModeCommand,
			wantCommandIndex: 4,
			wantScriptIndex:  -1,
		},
		{
			name:             "named noexec is finally enabled for command",
			program:          "bash",
			argv:             []string{"bash", "+o", "noexec", "-oc", "noexec", "printf safe"},
			wantMode:         posixShellModeCommand,
			wantCommandIndex: 5,
			wantScriptIndex:  -1,
			wantNoExec:       true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			invocation := parsePOSIXShellInvocation(test.program, test.argv)
			if !invocation.valid ||
				invocation.mode != test.wantMode ||
				invocation.commandIndex != test.wantCommandIndex ||
				invocation.scriptIndex != test.wantScriptIndex ||
				invocation.noExec != test.wantNoExec {
				t.Fatalf("invocation = %#v", invocation)
			}
		})
	}
}

func TestProvesPOSIXInteractiveShellUsesRecognizedFinalState(t *testing.T) {
	for _, test := range []struct {
		name    string
		program string
		argv    []string
		want    bool
	}{
		{name: "exact bash", program: "bash", argv: []string{"bash", "-i"}, want: true},
		{
			name:    "bash startup disabled before interactive",
			program: "bash", argv: []string{"bash", "--norc", "-i"}, want: true,
		},
		{name: "bundled login interactive", program: "bash", argv: []string{"bash", "-li"}, want: true},
		{name: "exact sh", program: "sh", argv: []string{"sh", "-i"}, want: true},
		{
			name:    "interactive disabled later",
			program: "bash", argv: []string{"bash", "-i", "+i", "-c", "cat"},
		},
		{name: "terminal option", program: "bash", argv: []string{"bash", "--version", "-i"}},
		{
			name:    "invalid option",
			program: "bash", argv: []string{"bash", "--definitely-invalid", "-i"},
		},
		{name: "script positional", program: "sh", argv: []string{"sh", "script", "-i"}},
		{name: "end of options", program: "sh", argv: []string{"sh", "--", "-i"}},
		{
			name:    "command positional",
			program: "bash", argv: []string{"bash", "-c", "cat", "-i"},
		},
		{
			name:    "interactive command mode",
			program: "bash", argv: []string{"bash", "-ic", "printf fixed"},
		},
		{
			name:    "interactive script mode",
			program: "bash", argv: []string{"bash", "-i", "local.sh"},
		},
		{name: "unmodeled zsh", program: "zsh", argv: []string{"zsh", "-i"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := CommandFact{
				Dialect: DialectPOSIX, Effect: EffectExecute,
				Program: test.program, Argv: test.argv, ArgvComplete: true,
			}
			if got := ProvesPOSIXInteractiveShell(command); got != test.want {
				t.Fatalf("interactive proof = %t, want %t", got, test.want)
			}
		})
	}
}

func TestProvesPOSIXInteractiveShellRejectsGuardFailures(t *testing.T) {
	positive := CommandFact{
		Dialect: DialectPOSIX, Effect: EffectExecute,
		Program: "bash", Argv: []string{"bash", "-i"}, ArgvComplete: true,
	}
	for _, test := range []struct {
		name   string
		mutate func(*CommandFact)
	}{
		{
			name: "non POSIX dialect",
			mutate: func(command *CommandFact) {
				command.Dialect = DialectCMD
			},
		},
		{
			name: "non execute effect",
			mutate: func(command *CommandFact) {
				command.Effect = EffectPreview
			},
		},
		{
			name: "incomplete argv",
			mutate: func(command *CommandFact) {
				command.ArgvComplete = false
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := positive
			test.mutate(&command)
			invocation := parsePOSIXShellInvocation(command.Program, command.Argv)
			if !invocation.recognized || !invocation.interactive ||
				invocation.mode != posixShellModeStdin {
				t.Fatalf("guard fixture lost its positive parser state: %#v", invocation)
			}
			if ProvesPOSIXInteractiveShell(command) {
				t.Fatal("interactive proof accepted a failed command guard")
			}
		})
	}
}

func TestParsePOSIXShellInvocationRejectsUnsafeOrInvalidForms(t *testing.T) {
	tests := []struct {
		name    string
		program string
		argv    []string
	}{
		{
			name:    "unsupported command long option",
			program: "bash",
			argv:    []string{"bash", "--command", "printf unsafe"},
		},
		{
			name:    "bash rejects empty script after terminator",
			program: "bash",
			argv:    []string{"bash", "--", ""},
		},
		{
			name:    "dash rejects empty script after dash",
			program: "dash",
			argv:    []string{"dash", "-", ""},
		},
		{
			name:    "bash long option after short option",
			program: "bash",
			argv:    []string{"bash", "-e", "--noprofile", "-c", "printf unsafe"},
		},
		{
			name:    "dash rejects bash short option",
			program: "dash",
			argv:    []string{"dash", "-Bc", "printf unsafe"},
		},
		{
			name:    "dash rejects bash long option",
			program: "dash",
			argv:    []string{"dash", "--noprofile", "-c", "printf unsafe"},
		},
		{
			name:    "zsh rejects bash long option",
			program: "zsh",
			argv:    []string{"zsh", "--noprofile", "-c", "printf unsafe"},
		},
		{
			name:    "zsh command cannot suppress system zshenv",
			program: "zsh",
			argv:    []string{"zsh", "-fc", "printf unsafe"},
		},
		{
			name:    "ksh rejects unsupported short option",
			program: "ksh",
			argv:    []string{"ksh", "-Pc", "printf unsafe"},
		},
		{
			name:    "login shell can execute startup files",
			program: "bash",
			argv:    []string{"bash", "-lc", "printf unsafe"},
		},
		{
			name:    "interactive shell can execute startup files",
			program: "bash",
			argv:    []string{"bash", "-ic", "printf unsafe"},
		},
		{
			name:    "debugger can execute startup file",
			program: "bash",
			argv:    []string{"bash", "--debugger", "-c", "printf unsafe"},
		},
		{
			name:    "rcfile operand remains non-authoritative",
			program: "bash",
			argv:    []string{"bash", "--rcfile", "/tmp/bashrc", "-ic", "printf unsafe"},
		},
		{
			name:    "ksh explicit startup option remains non-authoritative",
			program: "ksh",
			argv:    []string{"ksh", "-Ec", "printf unsafe"},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if invocation := parsePOSIXShellInvocation(test.program, test.argv); invocation.valid {
				t.Fatalf("unsafe invocation accepted: %#v", invocation)
			}
		})
	}
}

func TestPOSIXShellUnsafeInvocationDoesNotPublishNestedFacts(t *testing.T) {
	tests := []string{
		`bash --command 'rm -rf /tmp/victim'`,
		`bash -e --noprofile -c 'rm -rf /tmp/victim'`,
		`bash -lc 'rm -rf /tmp/victim'`,
		`bash -ic 'rm -rf /tmp/victim'`,
		`bash --debugger -c 'rm -rf /tmp/victim'`,
		`bash --rcfile /tmp/bashrc -ic 'rm -rf /tmp/victim'`,
		`BASH_ENV=/tmp/bashenv bash -c 'rm -rf /tmp/victim'`,
		`env BASH_ENV=/tmp/bashenv bash -c 'rm -rf /tmp/victim'`,
		`env -- BASH_ENV=/tmp/bashenv bash -c 'rm -rf /tmp/victim'`,
		`dash -Bc 'rm -rf /tmp/victim'`,
		`dash --noprofile -c 'rm -rf /tmp/victim'`,
		`dash --version`,
		`zsh --noprofile -c 'rm -rf /tmp/victim'`,
		`zsh -b -c 'rm -rf /tmp/victim'`,
		`ksh -Pc 'rm -rf /tmp/victim'`,
		`ksh -Ec 'rm -rf /tmp/victim'`,
	}

	for _, source := range tests {
		source := source
		t.Run(source, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{
				Tool:        "exec",
				Command:     source,
				DialectHint: DialectPOSIX,
			})
			if facts.Parse.Status != StatusPartial ||
				facts.Authoritative() ||
				facts.EnforcementEligible() ||
				hasExecutable(facts.Commands, "rm") ||
				factsHavePath(facts, PathAccessDelete, "/tmp/victim") {
				t.Fatalf("unsafe shell facts = %#v", facts)
			}
		})
	}
}

func TestPOSIXShellOptionOperandsDoNotBecomeScriptPaths(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		wantScript string
	}{
		{
			name:       "named set option",
			command:    `bash -eo pipefail /tmp/payload.sh`,
			wantScript: "/tmp/payload.sh",
		},
		{
			name:       "shopt option",
			command:    `bash -eO nullglob /tmp/payload.sh`,
			wantScript: "/tmp/payload.sh",
		},
		{
			name:       "mixed bundled value options",
			command:    `bash -oO pipefail nullglob /tmp/payload.sh`,
			wantScript: "/tmp/payload.sh",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{
				Tool:        "exec",
				Command:     test.command,
				DialectHint: DialectPOSIX,
			})
			if facts.Parse.Status != StatusPartial ||
				!factsHavePath(facts, PathAccessExecute, test.wantScript) ||
				factsHavePath(facts, PathAccessExecute, "pipefail") ||
				factsHavePath(facts, PathAccessExecute, "nullglob") {
				t.Fatalf("script option facts = %#v", facts)
			}
		})
	}

	rcfile := Analyze(Input{
		Tool:        "exec",
		Command:     `bash --rcfile /tmp/bashrc -i /tmp/payload.sh`,
		DialectHint: DialectPOSIX,
	})
	if rcfile.Parse.Status != StatusPartial ||
		factsHavePath(rcfile, PathAccessExecute, "/tmp/bashrc") ||
		factsHavePath(rcfile, PathAccessExecute, "/tmp/payload.sh") {
		t.Fatalf("rcfile operand became script path: %#v", rcfile)
	}
}

func TestPOSIXShellCommandOptionOperandsSelectCommandBody(t *testing.T) {
	tests := []struct {
		name  string
		input Input
	}{
		{
			name: "raw named option before command",
			input: Input{
				Tool:        "exec",
				Command:     `bash -o pipefail -c 'rm -rf /tmp/victim'`,
				DialectHint: DialectPOSIX,
			},
		},
		{
			name: "raw bundled named option and command",
			input: Input{
				Tool:        "exec",
				Command:     `bash -oc pipefail 'rm -rf /tmp/victim'`,
				DialectHint: DialectPOSIX,
			},
		},
		{
			name: "raw shopt before command",
			input: Input{
				Tool:        "exec",
				Command:     `bash -O nullglob -c 'rm -rf /tmp/victim'`,
				DialectHint: DialectPOSIX,
			},
		},
		{
			name: "structured bundled named option and command",
			input: Input{
				Tool: "exec",
				Argv: []string{
					"bash", "-oc", "pipefail",
					"rm -rf /tmp/victim",
				},
			},
		},
		{
			name: "structured shopt before command",
			input: Input{
				Tool: "exec",
				Argv: []string{
					"bash", "-O", "nullglob", "-c",
					"rm -rf /tmp/victim",
				},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(test.input)
			if facts.Parse.Status != StatusComplete ||
				!facts.Authoritative() ||
				!facts.EnforcementEligible() ||
				!hasExecutable(facts.Commands, "rm") ||
				!factsHavePath(facts, PathAccessDelete, "/tmp/victim") {
				t.Fatalf("command option facts = %#v", facts)
			}
		})
	}
}
