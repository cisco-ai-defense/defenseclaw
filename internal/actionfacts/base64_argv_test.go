// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestParsePortableBase64DecodeArgv(t *testing.T) {
	tests := []struct {
		name       string
		argv       []string
		complete   bool
		decode     bool
		inputSet   bool
		input      string
		readsStdin bool
	}{
		{
			name:       "single decode flag reads stdin",
			argv:       []string{"base64", "-d"},
			complete:   true,
			decode:     true,
			readsStdin: true,
		},
		{
			name:       "long decode flag reads stdin",
			argv:       []string{"base64", "--decode"},
			complete:   true,
			decode:     true,
			readsStdin: true,
		},
		{
			name:       "repeated decode bundle reads stdin",
			argv:       []string{"base64", "-dd"},
			complete:   true,
			decode:     true,
			readsStdin: true,
		},
		{
			name:       "long repeated decode bundle reads stdin",
			argv:       []string{"base64", "-ddd"},
			complete:   true,
			decode:     true,
			readsStdin: true,
		},
		{
			name:       "terminal input flag bundle owns file",
			argv:       []string{"base64", "-di", "payload.b64"},
			complete:   true,
			decode:     true,
			inputSet:   true,
			input:      "payload.b64",
			readsStdin: false,
		},
		{
			name:       "repeated decode with terminal input flag owns file",
			argv:       []string{"base64", "-ddi", "payload.b64"},
			complete:   true,
			decode:     true,
			inputSet:   true,
			input:      "payload.b64",
			readsStdin: false,
		},
		{
			name:       "separate input option after repeated decode owns file",
			argv:       []string{"base64", "-dd", "-i", "payload.b64"},
			complete:   true,
			decode:     true,
			inputSet:   true,
			input:      "payload.b64",
			readsStdin: false,
		},
		{
			name:       "explicit dash input reads stdin",
			argv:       []string{"base64", "-di", "-"},
			complete:   true,
			decode:     true,
			inputSet:   true,
			input:      "-",
			readsStdin: true,
		},
		{
			name:       "portable input without decode is complete but not decode mode",
			argv:       []string{"base64", "-i", "payload.b64"},
			complete:   true,
			decode:     false,
			inputSet:   true,
			input:      "payload.b64",
			readsStdin: false,
		},
		{
			name:       "portable input before short decode",
			argv:       []string{"base64", "-i", "payload.b64", "-d"},
			complete:   true,
			decode:     true,
			inputSet:   true,
			input:      "payload.b64",
			readsStdin: false,
		},
		{
			name:       "portable input before long decode",
			argv:       []string{"base64", "-i", "payload.b64", "--decode"},
			complete:   true,
			decode:     true,
			inputSet:   true,
			input:      "payload.b64",
			readsStdin: false,
		},
		{
			name:       "option terminator without operand is harmless",
			argv:       []string{"base64", "-d", "--"},
			complete:   true,
			decode:     true,
			readsStdin: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed := parsePortableBase64DecodeArgv(test.argv)
			if parsed.Complete != test.complete || parsed.Decode != test.decode {
				t.Fatalf("complete/decode = (%t, %t), want (%t, %t): %#v", parsed.Complete, parsed.Decode, test.complete, test.decode, parsed)
			}
			if parsed.InputSet != test.inputSet || parsed.Input != test.input {
				t.Fatalf("input = (%t, %q), want (%t, %q): %#v", parsed.InputSet, parsed.Input, test.inputSet, test.input, parsed)
			}
			if parsed.ReadsStdin != test.readsStdin {
				t.Fatalf("ReadsStdin = %t, want %t: %#v", parsed.ReadsStdin, test.readsStdin, parsed)
			}
			if parsed.provesDecodedStdout() != (test.complete && test.decode) {
				t.Fatalf("provesDecodedStdout() = %t, want %t", parsed.provesDecodedStdout(), test.complete && test.decode)
			}
		})
	}
}

func TestParsePortableBase64DecodeArgvRejectsNonPortableGrammar(t *testing.T) {
	tests := []struct {
		name string
		argv []string
	}{
		{
			name: "gnu only positional file after repeated decode",
			argv: []string{"base64", "-dd", "payload.b64"},
		},
		{
			name: "gnu only positional file after decode",
			argv: []string{"base64", "-d", "payload.b64"},
		},
		{
			name: "missing input operand",
			argv: []string{"base64", "-d", "-i"},
		},
		{
			name: "missing bundled input operand",
			argv: []string{"base64", "-di"},
		},
		{
			name: "option shaped input differs across implementations",
			argv: []string{"base64", "-ddi", "--decode"},
		},
		{
			name: "input option is not terminal",
			argv: []string{"base64", "-id", "payload.b64"},
		},
		{
			name: "input option occurs inside bundle",
			argv: []string{"base64", "-did", "payload.b64"},
		},
		{
			name: "duplicate terminal input flag",
			argv: []string{"base64", "-dii", "payload.b64"},
		},
		{
			name: "uppercase decode is not portable",
			argv: []string{"base64", "-D"},
		},
		{
			name: "gnu long ignore garbage is not portable",
			argv: []string{"base64", "-d", "--ignore-garbage", "payload.b64"},
		},
		{
			name: "duplicate portable input",
			argv: []string{"base64", "-d", "-i", "first.b64", "-i", "second.b64"},
		},
		{
			name: "positional operand after terminator",
			argv: []string{"base64", "-d", "--", "payload.b64"},
		},
		{
			name: "empty portable input",
			argv: []string{"base64", "-d", "-i", ""},
		},
		{
			name: "bare positional dash is not in both option grammars",
			argv: []string{"base64", "-d", "-"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed := parsePortableBase64DecodeArgv(test.argv)
			if parsed.Complete {
				t.Fatalf("parse unexpectedly complete: %#v", parsed)
			}
			if parsed.provesDecodedStdout() {
				t.Fatalf("incomplete parse proved decoded stdout: %#v", parsed)
			}
		})
	}
}

func TestParsePortableBase64DecodeArgvInputTokenMetadata(t *testing.T) {
	parsed := parsePortableBase64DecodeArgv([]string{
		"base64", "-ddi", "payload.b64",
	})
	if !parsed.Complete {
		t.Fatalf("parse incomplete: %#v", parsed)
	}
	if parsed.InputOptionIndex != 1 || parsed.InputValueIndex != 2 {
		t.Fatalf("input indexes = (%d, %d), want (1, 2): %#v", parsed.InputOptionIndex, parsed.InputValueIndex, parsed)
	}
}
