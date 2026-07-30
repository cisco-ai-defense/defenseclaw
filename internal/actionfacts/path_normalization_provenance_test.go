// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestPathNormalizationPreservesStaticPOSIXSyntax(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		command        string
		activeHome     string
		wantNormalized string
		wantResolved   string
	}{
		{
			name:           "single quoted dollar is literal",
			command:        `cat '$HOME/fixture/../secret.txt'`,
			wantNormalized: "$HOME/secret.txt",
			wantResolved:   "/workspace/$HOME/secret.txt",
		},
		{
			name:           "single quoted bang pair is literal",
			command:        `cat '/tmp/!fixture!/../secret.txt'`,
			wantNormalized: "/tmp/secret.txt",
			wantResolved:   "/tmp/secret.txt",
		},
		{
			name:           "single quoted tilde is literal",
			command:        `cat '~/.ssh/../id_ed25519'`,
			activeHome:     "/home/fixture",
			wantNormalized: "~/id_ed25519",
			wantResolved:   "/workspace/~/id_ed25519",
		},
		{
			name:           "double quoted tilde is literal",
			command:        `cat "~/.ssh/../id_ed25519"`,
			activeHome:     "/home/fixture",
			wantNormalized: "~/id_ed25519",
			wantResolved:   "/workspace/~/id_ed25519",
		},
		{
			name:           "single quoted redirect dollar is literal",
			command:        `printf fixture > '$HOME/output/../secret.txt'`,
			wantNormalized: "$HOME/secret.txt",
			wantResolved:   "/workspace/$HOME/secret.txt",
		},
		{
			name:           "single quoted redirect tilde is literal",
			command:        `printf fixture > '~/.cache/../output.txt'`,
			activeHome:     "/home/fixture",
			wantNormalized: "~/output.txt",
			wantResolved:   "/workspace/~/output.txt",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			facts := Analyze(Input{
				Tool:        "bash",
				Command:     test.command,
				CWD:         "/workspace",
				ActiveHome:  test.activeHome,
				DialectHint: DialectPOSIX,
			})
			if !facts.Authoritative() || len(facts.Paths) != 1 {
				t.Fatalf("facts = %#v", facts)
			}
			got := facts.Paths[0]
			if got.Flavor != PathFlavorPOSIX ||
				got.Normalized != test.wantNormalized ||
				got.Resolved != test.wantResolved {
				t.Fatalf(
					"path = %#v, want POSIX normalized=%q resolved=%q",
					got,
					test.wantNormalized,
					test.wantResolved,
				)
			}
		})
	}
}

func TestPathNormalizationPreservesIntendedTildeSemantics(t *testing.T) {
	t.Parallel()

	structuredPOSIX := Analyze(Input{
		Argv:        []string{"cat", "~/.ssh/../id_ed25519"},
		CWD:         "/workspace",
		ActiveHome:  "/home/fixture",
		DialectHint: DialectPOSIX,
	})
	if !structuredPOSIX.Authoritative() ||
		len(structuredPOSIX.Paths) != 1 ||
		structuredPOSIX.Paths[0].Resolved != "/home/fixture/id_ed25519" {
		t.Fatalf("structured POSIX tilde lost home semantics: %#v", structuredPOSIX)
	}

	powerShell := Analyze(Input{
		Tool:        "powershell",
		Argv:        []string{"Get-Content", `~\.ssh\..\id_ed25519`},
		CWD:         `C:\workspace`,
		ActiveHome:  `C:\Users\fixture`,
		DialectHint: DialectPowerShell,
	})
	if !powerShell.Authoritative() || len(powerShell.Paths) != 1 ||
		powerShell.Paths[0].Flavor != PathFlavorWindows ||
		powerShell.Paths[0].Resolved != "C:/Users/fixture/id_ed25519" {
		t.Fatalf("PowerShell tilde lost home semantics: %#v", powerShell)
	}

	cmd := Analyze(Input{
		Tool:        "cmd",
		Command:     `type ~\secret\..\token.txt`,
		CWD:         `C:\workspace`,
		ActiveHome:  `C:\Users\fixture`,
		DialectHint: DialectCMD,
	})
	if !cmd.Authoritative() || len(cmd.Paths) != 1 ||
		cmd.Paths[0].Flavor != PathFlavorWindows ||
		cmd.Paths[0].Normalized != "~/token.txt" ||
		cmd.Paths[0].Resolved != "C:/workspace/~/token.txt" {
		t.Fatalf("CMD tilde was not preserved as literal path data: %#v", cmd)
	}

	unproven, _, resolved := derivePath(PathFact{
		Flavor: PathFlavorPOSIX,
		Value:  "/tmp/!fixture!/../secret.txt",
	}, "")
	if unproven != "/tmp/!fixture!/../secret.txt" || resolved != "" {
		t.Fatalf(
			"unproven expansion syntax was normalized: (%q, %q)",
			unproven,
			resolved,
		)
	}
}

func TestStructuredWindowsExpansionCharactersAreLiteral(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input Input
		want  string
	}{
		{
			name: "structured tool dollar",
			input: Input{
				Tool: "Read",
				Args: []byte(
					`{"path":"C:\\Users\\$fixture\\..\\secret.txt"}`,
				),
				CWD: `C:\workspace`,
			},
			want: "C:/Users/secret.txt",
		},
		{
			name: "CMD bang pair",
			input: Input{
				Tool: "exec",
				Argv: []string{
					"type", `C:\work\!fixture!\..\secret.txt`,
				},
				CWD:         `C:\workspace`,
				DialectHint: DialectCMD,
			},
			want: "C:/work/secret.txt",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			facts := Analyze(test.input)
			if !facts.Authoritative() || len(facts.Paths) != 1 ||
				facts.Paths[0].Flavor != PathFlavorWindows ||
				facts.Paths[0].Resolved != test.want {
				t.Fatalf("structured literal was unresolved: %#v", facts)
			}
		})
	}
}

func TestPathNormalizationSyntaxFollowsCommandDialect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		command        string
		wantNormalized string
		wantResolved   string
	}{
		{
			name:           "POSIX backslashes are literal",
			command:        `cat 'dir\child\..\secret.txt'`,
			wantNormalized: `dir\child\..\secret.txt`,
			wantResolved:   `/workspace/dir\child\..\secret.txt`,
		},
		{
			name:           "registry lookalike is a POSIX path",
			command:        `cat 'HKEY_fixture/../secret.txt'`,
			wantNormalized: "secret.txt",
			wantResolved:   "/workspace/secret.txt",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			facts := Analyze(Input{
				Tool:        "bash",
				Command:     test.command,
				CWD:         "/workspace",
				DialectHint: DialectPOSIX,
			})
			if !facts.Authoritative() || len(facts.Paths) != 1 {
				t.Fatalf("facts = %#v", facts)
			}
			got := facts.Paths[0]
			if got.Flavor != PathFlavorPOSIX ||
				got.Normalized != test.wantNormalized ||
				got.Resolved != test.wantResolved {
				t.Fatalf(
					"path = %#v, want POSIX normalized=%q resolved=%q",
					got,
					test.wantNormalized,
					test.wantResolved,
				)
			}
		})
	}
}

func TestDirectToolForwardSlashUNCRequiresWindowsCWD(t *testing.T) {
	t.Parallel()

	const rawArgs = `{"path":"//server/share/secret.txt"}`
	posix := Analyze(Input{
		Tool: "Read",
		Args: []byte(rawArgs),
		CWD:  "/workspace",
	})
	if !posix.Authoritative() || len(posix.Paths) != 1 ||
		posix.Paths[0].Flavor != PathFlavorPOSIX ||
		posix.Paths[0].Resolved != "/server/share/secret.txt" {
		t.Fatalf("POSIX tool context minted a UNC target: %#v", posix)
	}

	noContext := Analyze(Input{
		Tool: "Read",
		Args: []byte(rawArgs),
	})
	if !noContext.Authoritative() || len(noContext.Paths) != 1 ||
		noContext.Paths[0].Flavor != PathFlavorPOSIX ||
		noContext.Paths[0].Resolved != "/server/share/secret.txt" {
		t.Fatalf("context-free tool call minted a UNC target: %#v", noContext)
	}

	windows := Analyze(Input{
		Tool: "Read",
		Args: []byte(rawArgs),
		CWD:  `C:\workspace`,
	})
	if !windows.Authoritative() || len(windows.Paths) != 1 ||
		windows.Paths[0].Flavor != PathFlavorWindows ||
		windows.Paths[0].Resolved != "//server/share/secret.txt" {
		t.Fatalf("Windows tool context did not retain UNC target: %#v", windows)
	}
}
