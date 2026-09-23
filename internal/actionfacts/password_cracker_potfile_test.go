// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

func TestCanonicalPasswordCrackerPotfileReadsAreCredentialReads(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input Input
	}{
		{
			name: "john under trusted home",
			input: Input{
				Command:    `cat /home/alice/.john/john.pot`,
				ActiveHome: "/home/alice",
			},
		},
		{
			name: "hashcat modern location",
			input: Input{
				Argv: []string{
					"head", "/home/alice/.local/share/hashcat/hashcat.potfile",
				},
				ActiveHome: "/home/alice",
			},
		},
		{
			name: "hashcat legacy location from closed read tool",
			input: Input{
				Tool:       "read_file",
				Args:       json.RawMessage(`{"path":"/home/alice/.hashcat/hashcat.potfile"}`),
				ActiveHome: "/home/alice",
			},
		},
		{
			name: "root is canonical without active home",
			input: Input{
				Command: `/usr/bin/cat -- /root/.john/john.pot`,
			},
		},
		{
			name: "unquoted tilde resolves from trusted home",
			input: Input{
				Command:    `cat ~/.john/john.pot`,
				ActiveHome: "/home/alice",
			},
		},
		{
			name: "structured argv relative to trusted home cwd",
			input: Input{
				Argv:       []string{"tail", ".john/john.pot"},
				CWD:        "/home/alice",
				ActiveHome: "/home/alice",
			},
		},
		{
			name: "result-backed john read through bounded pipeline",
			input: Input{
				Command:    `cat ~/.john/john.pot | tail -5`,
				ActiveHome: "/home/alice",
			},
		},
		{
			name: "result-backed hashcat read through sudo wrapper",
			input: Input{
				Command: `sudo cat /root/.local/share/hashcat/hashcat.potfile`,
			},
		},
		{
			name: "result-backed grep before fallback",
			input: Input{
				Command: `grep "EXAMPLE" /root/.local/share/hashcat/hashcat.potfile || sudo grep "EXAMPLE" /root/.local/share/hashcat/hashcat.potfile`,
			},
		},
		{
			name: "result-backed read among sibling commands",
			input: Input{
				Command: `ls /tmp; echo marker; cat /root/.hashcat/hashcat.potfile | head -10`,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(test.input)
			credentialRead := false
			for _, command := range facts.Commands {
				credentialRead = credentialRead ||
					hasFactOperation(command, OperationCredentialRead)
			}
			if !credentialRead {
				t.Fatalf("facts = %#v", facts)
			}
			readPath := false
			for _, candidate := range facts.Paths {
				readPath = readPath || candidate.Access == PathAccessRead &&
					candidate.Resolved != ""
			}
			if !readPath {
				t.Fatalf("paths = %#v", facts.Paths)
			}
		})
	}
}

func TestCanonicalPasswordCrackerPotfileReadHardNegatives(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input Input
	}{
		{
			name:  "home path without trusted home",
			input: Input{Command: `cat /home/alice/.john/john.pot`},
		},
		{
			name:  "relative path without trusted home resolution",
			input: Input{Argv: []string{"cat", ".john/john.pot"}, CWD: "/home/alice"},
		},
		{
			name: "relative root path still requires trusted home",
			input: Input{
				Argv: []string{"cat", ".john/john.pot"},
				CWD:  "/root",
			},
		},
		{
			name:  "tilde without trusted home resolution",
			input: Input{Command: `cat ~/.john/john.pot`},
		},
		{
			name: "quoted tilde is literal not home expansion",
			input: Input{
				Command:    `cat '~/.john/john.pot'`,
				ActiveHome: "/home/alice",
			},
		},
		{
			name: "dynamic home",
			input: Input{
				Command:    `cat "$HOME/.john/john.pot"`,
				ActiveHome: "/home/alice",
			},
		},
		{
			name: "traversal",
			input: Input{
				Argv:       []string{"cat", "/home/alice/tmp/../.john/john.pot"},
				ActiveHome: "/home/alice",
			},
		},
		{
			name: "noncanonical dot spelling",
			input: Input{
				Argv:       []string{"cat", "/home/alice/./.john/john.pot"},
				ActiveHome: "/home/alice",
			},
		},
		{
			name: "fixture path",
			input: Input{
				Argv: []string{"cat", "/tmp/fixture/root/.john/john.pot"},
			},
		},
		{
			name: "backup lookalike",
			input: Input{
				Argv: []string{"cat", "/root/.john/john.pot.bak"},
			},
		},
		{
			name: "case lookalike",
			input: Input{
				Argv: []string{"cat", "/root/.John/john.pot"},
			},
		},
		{
			name: "echo is not a read",
			input: Input{
				Argv: []string{"echo", "/root/.john/john.pot"},
			},
		},
		{
			name: "printf is not a read",
			input: Input{
				Argv: []string{"printf", "%s", "/root/.john/john.pot"},
			},
		},
		{
			name: "list is not a content read",
			input: Input{
				Argv: []string{"ls", "/root/.john/john.pot"},
			},
		},
		{
			name: "metadata is not a content read",
			input: Input{
				Argv: []string{"stat", "/root/.john/john.pot"},
			},
		},
		{
			name: "test is not a content read",
			input: Input{
				Argv: []string{"test", "-f", "/root/.john/john.pot"},
			},
		},
		{
			name: "find is search not a content read",
			input: Input{
				Argv: []string{"find", "/root/.john", "-name", "john.pot"},
			},
		},
		{
			name: "write tool",
			input: Input{
				Tool: "write_file",
				Args: json.RawMessage(
					`{"path":"/root/.john/john.pot","content":"placeholder"}`,
				),
			},
		},
		{
			name: "preview flag",
			input: Input{
				Argv: []string{"cat", "--help", "/root/.john/john.pot"},
			},
		},
		{
			name: "conditional flow",
			input: Input{
				Command: `true && cat /root/.john/john.pot`,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(test.input)
			for _, command := range facts.Commands {
				if hasFactOperation(command, OperationCredentialRead) {
					t.Fatalf("unexpected credential read: %#v", facts)
				}
			}
		})
	}
}
