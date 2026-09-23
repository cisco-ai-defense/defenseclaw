// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"reflect"
	"testing"
)

func TestParseWgetArgvJoinedOperandBoundaries(t *testing.T) {
	tests := []struct {
		name       string
		argv       []string
		complete   bool
		outputSet  bool
		output     string
		valueCount int
	}{
		{
			name:       "flags before joined output",
			argv:       []string{"wget", "-dO-", "https://example.test/payload"},
			complete:   true,
			outputSet:  true,
			output:     "-",
			valueCount: 1,
		},
		{
			name:       "flags before separated output",
			argv:       []string{"wget", "-dO", "-", "https://example.test/payload"},
			complete:   true,
			outputSet:  true,
			output:     "-",
			valueCount: 1,
		},
		{
			name:       "joined timeout owns bundle suffix",
			argv:       []string{"wget", "-qT5", "-O-", "https://example.test/payload"},
			complete:   true,
			outputSet:  true,
			output:     "-",
			valueCount: 2,
		},
		{
			name:       "separated timeout owns next token",
			argv:       []string{"wget", "-qT", "5", "-O-", "https://example.test/payload"},
			complete:   true,
			outputSet:  true,
			output:     "-",
			valueCount: 2,
		},
		{
			name:       "time suffix is part of timeout",
			argv:       []string{"wget", "-T10s", "-O-", "https://example.test/payload"},
			complete:   true,
			outputSet:  true,
			output:     "-",
			valueCount: 2,
		},
		{
			name:       "value option terminates short bundle parsing",
			argv:       []string{"wget", "-T5O-", "https://example.test/payload"},
			complete:   false,
			outputSet:  false,
			valueCount: 1,
		},
		{
			name:       "leading dash remains joined output value",
			argv:       []string{"wget", "-O-file", "https://example.test/payload"},
			complete:   true,
			outputSet:  true,
			output:     "-file",
			valueCount: 1,
		},
		{
			name:       "option shaped token remains separated output value",
			argv:       []string{"wget", "-O", "--help", "https://example.test/payload"},
			complete:   true,
			outputSet:  true,
			output:     "--help",
			valueCount: 1,
		},
		{
			name:       "compatibility no bundle updates final verbose state",
			argv:       []string{"wget", "-qv", "-nv", "-O-", "https://example.test/payload"},
			complete:   true,
			outputSet:  true,
			output:     "-",
			valueCount: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed := parseWgetArgv(test.argv)
			if parsed.Complete != test.complete {
				t.Fatalf("Complete = %t, want %t: %#v", parsed.Complete, test.complete, parsed)
			}
			if parsed.OutputSet != test.outputSet || parsed.Output != test.output {
				t.Fatalf("output = (%t, %q), want (%t, %q): %#v", parsed.OutputSet, parsed.Output, test.outputSet, test.output, parsed)
			}
			if len(parsed.Values) != test.valueCount {
				t.Fatalf("len(Values) = %d, want %d: %#v", len(parsed.Values), test.valueCount, parsed.Values)
			}
		})
	}
}

func TestParseWgetArgvValueTokenMetadata(t *testing.T) {
	parsed := parseWgetArgv([]string{
		"wget", "-qT5", "-O", "-", "https://example.test/payload",
	})
	want := []wgetArgvValue{
		{
			Option:      "--timeout",
			Value:       "5",
			OptionIndex: 1,
			ValueIndex:  1,
			Joined:      true,
		},
		{
			Option:      "--output-document",
			Value:       "-",
			OptionIndex: 2,
			ValueIndex:  3,
			Joined:      false,
		},
	}
	if !parsed.Complete {
		t.Fatalf("parse incomplete: %#v", parsed)
	}
	if !reflect.DeepEqual(parsed.Values, want) {
		t.Fatalf("Values = %#v, want %#v", parsed.Values, want)
	}
}

func TestParseWgetArgvProtocolCredentialOwnership(t *testing.T) {
	parsed := parseWgetArgv([]string{
		"wget", "--http-user=http-agent", "--http-password", "http-secret",
		"--ftp-user=ftp-agent", "--ftp-password", "ftp-secret",
		"https://example.test/payload",
	})
	want := []wgetArgvValue{
		{
			Option: "--http-user", Value: "http-agent",
			OptionIndex: 1, ValueIndex: 1, Joined: true,
		},
		{
			Option: "--http-password", Value: "http-secret",
			OptionIndex: 2, ValueIndex: 3,
		},
		{
			Option: "--ftp-user", Value: "ftp-agent",
			OptionIndex: 4, ValueIndex: 4, Joined: true,
		},
		{
			Option: "--ftp-password", Value: "ftp-secret",
			OptionIndex: 5, ValueIndex: 6,
		},
	}
	if !parsed.Complete || !reflect.DeepEqual(parsed.Values, want) {
		t.Fatalf("parse = %#v, want values %#v", parsed, want)
	}
}

func TestParseWgetArgvFinalOutputWins(t *testing.T) {
	tests := []struct {
		name         string
		argv         []string
		output       string
		provesStdout bool
	}{
		{
			name: "stdout wins",
			argv: []string{
				"wget", "-O", "download.bin", "--output-document=-",
				"https://example.test/payload",
			},
			output:       "-",
			provesStdout: true,
		},
		{
			name: "file wins",
			argv: []string{
				"wget", "-O-", "--output-document", "download.bin",
				"https://example.test/payload",
			},
			output: "download.bin",
		},
		{
			name: "valid final output replaces empty value",
			argv: []string{
				"wget", "--output-document=", "--output-document=-",
				"https://example.test/payload",
			},
			output:       "-",
			provesStdout: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed := parseWgetArgv(test.argv)
			if !parsed.Complete {
				t.Fatalf("parse incomplete: %#v", parsed)
			}
			if !parsed.OutputSet || parsed.Output != test.output {
				t.Fatalf("final output = (%t, %q), want (true, %q)", parsed.OutputSet, parsed.Output, test.output)
			}
			if parsed.provesResponseStdout() != test.provesStdout {
				t.Fatalf("provesResponseStdout() = %t, want %t", parsed.provesResponseStdout(), test.provesStdout)
			}
			if len(parsed.Values) != 2 {
				t.Fatalf("len(Values) = %d, want 2: %#v", len(parsed.Values), parsed.Values)
			}
		})
	}
}

func TestParseWgetArgvFinalLogOutputWins(t *testing.T) {
	parsed := parseWgetArgv([]string{
		"wget", "-o", "-", "--append-output=wget.log", "-O-", "https://example.test",
	})
	if !parsed.Complete || !parsed.LogOutputSet || parsed.LogOutput != "wget.log" {
		t.Fatalf("final log output was not retained: %#v", parsed)
	}
	if !parsed.provesResponseStdout() {
		t.Fatalf("overridden stdout log blocked response proof: %#v", parsed)
	}
}

func TestParseWgetArgvAppendLogModeIsSticky(t *testing.T) {
	t.Parallel()

	parsed := parseWgetArgv([]string{
		"wget", "-a", "old.log", "-o", "final.log",
		"https://files.invalid/run",
	})
	if !parsed.Complete || !parsed.LogOutputSet ||
		parsed.LogOutput != "final.log" || !parsed.AppendLog {
		t.Fatalf("parse=%#v", parsed)
	}
}

func TestWgetArgvParseProvesResponseStdoutRejectsIndirectAndControlModes(t *testing.T) {
	tests := []struct {
		name string
		argv []string
	}{
		{
			name: "config indirection",
			argv: []string{"wget", "--config=wgetrc", "-O-", "https://example.test"},
		},
		{
			name: "execute indirection",
			argv: []string{"wget", "--no-config", "-e", "quiet=on", "-O-", "https://example.test"},
		},
		{
			name: "input file target indirection",
			argv: []string{"wget", "--no-config", "-i", "urls.txt", "-O-"},
		},
		{
			name: "background mode",
			argv: []string{"wget", "--no-config", "--background", "-O-", "https://example.test"},
		},
		{
			name: "spider mode",
			argv: []string{"wget", "--no-config", "--spider", "-O-", "https://example.test"},
		},
		{
			name: "head method",
			argv: []string{"wget", "--no-config", "--method=HEAD", "-O-", "https://example.test"},
		},
		{
			name: "log output contaminates stdout",
			argv: []string{"wget", "--no-config", "-o", "-", "-O-", "https://example.test"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed := parseWgetArgv(test.argv)
			if !parsed.Complete {
				t.Fatalf("parse incomplete: %#v", parsed)
			}
			if parsed.provesResponseStdout() {
				t.Fatalf("indirect/control mode proved stdout: %#v", parsed)
			}
		})
	}
}

func TestParseWgetArgvConfigPrepass(t *testing.T) {
	tests := []struct {
		name           string
		argv           []string
		preview        bool
		indirect       bool
		configDisabled bool
	}{
		{
			name:     "explicit config after help is still read first",
			argv:     []string{"wget", "--help", "--config=wgetrc"},
			preview:  true,
			indirect: true,
		},
		{
			name:           "no config optional false still suppresses prepass",
			argv:           []string{"wget", "--no-config=off", "-O-", "https://example.test"},
			configDisabled: true,
		},
		{
			name:           "generated no no config alias suppresses prepass",
			argv:           []string{"wget", "--no-no-config", "-O-", "https://example.test"},
			configDisabled: true,
		},
		{
			name:           "no config prepass still exposes explicit config token",
			argv:           []string{"wget", "--no-config", "--config=wgetrc", "-O-", "https://example.test"},
			indirect:       true,
			configDisabled: true,
		},
		{
			name:     "explicit config before no config wins prepass",
			argv:     []string{"wget", "--config=wgetrc", "--no-config", "-O-", "https://example.test"},
			indirect: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed := parseWgetArgv(test.argv)
			if !parsed.Complete {
				t.Fatalf("parse incomplete: %#v", parsed)
			}
			if parsed.Preview != test.preview || parsed.ConfigIndirect != test.indirect || parsed.ConfigDisabled != test.configDisabled {
				t.Fatalf("preview/config = (%t, %t, %t), want (%t, %t, %t): %#v", parsed.Preview, parsed.ConfigIndirect, parsed.ConfigDisabled, test.preview, test.indirect, test.configDisabled, parsed)
			}
		})
	}
}

func TestParseWgetArgvMethodAndBodyConstraints(t *testing.T) {
	tests := []struct {
		name      string
		argv      []string
		complete  bool
		bodyValid bool
		issue     wgetRequestBodyIssue
		method    string
		spider    bool
	}{
		{
			name:      "post data selects final post method",
			argv:      []string{"wget", "--post-data=x", "https://example.test"},
			complete:  true,
			bodyValid: true,
			method:    "POST",
		},
		{
			name:      "custom method with body data",
			argv:      []string{"wget", "--method=POST", "--body-data=payload", "https://example.test"},
			complete:  true,
			bodyValid: true,
			method:    "POST",
		},
		{
			name:      "empty custom body data is legal",
			argv:      []string{"wget", "--method", "PATCH", "--body-data=", "https://example.test"},
			complete:  true,
			bodyValid: true,
			method:    "PATCH",
		},
		{
			name:      "body requires explicit method",
			argv:      []string{"wget", "--body-data=payload", "https://example.test"},
			complete:  false,
			bodyValid: false,
			issue:     wgetRequestBodyIssueMissingMethod,
		},
		{
			name:      "missing method precedes empty body file usability",
			argv:      []string{"wget", "--body-file=", "https://example.test"},
			complete:  false,
			bodyValid: false,
			issue:     wgetRequestBodyIssueMissingMethod,
		},
		{
			name:      "post data and post file conflict",
			argv:      []string{"wget", "--post-data=x", "--post-file=payload", "https://example.test"},
			complete:  false,
			bodyValid: false,
			issue:     wgetRequestBodyIssuePostConflict,
		},
		{
			name:      "post conflict precedes empty file usability",
			argv:      []string{"wget", "--post-data=x", "--post-file=", "https://example.test"},
			complete:  false,
			bodyValid: false,
			issue:     wgetRequestBodyIssuePostConflict,
		},
		{
			name:      "post form conflicts with custom method",
			argv:      []string{"wget", "--method=PUT", "--post-data=x", "https://example.test"},
			complete:  false,
			bodyValid: false,
			issue:     wgetRequestBodyIssuePostWithMethod,
			method:    "PUT",
		},
		{
			name:      "body conflict precedes empty file usability",
			argv:      []string{"wget", "--method=PUT", "--body-data=x", "--body-file=", "https://example.test"},
			complete:  false,
			bodyValid: false,
			issue:     wgetRequestBodyIssueBodyConflict,
			method:    "PUT",
		},
		{
			name:      "body data and body file conflict",
			argv:      []string{"wget", "--method=PUT", "--body-data=x", "--body-file=payload", "https://example.test"},
			complete:  false,
			bodyValid: false,
			issue:     wgetRequestBodyIssueBodyConflict,
			method:    "PUT",
		},
		{
			name:      "missing method precedes body conflict",
			argv:      []string{"wget", "--body-data=x", "--body-file=payload", "https://example.test"},
			complete:  false,
			bodyValid: false,
			issue:     wgetRequestBodyIssueMissingMethod,
		},
		{
			name:      "final head method selects spider",
			argv:      []string{"wget", "--method=GET", "--method=head", "https://example.test"},
			complete:  true,
			bodyValid: true,
			method:    "HEAD",
			spider:    true,
		},
		{
			name:      "final get method replaces head",
			argv:      []string{"wget", "--method=HEAD", "--method=GET", "https://example.test"},
			complete:  true,
			bodyValid: true,
			method:    "GET",
			spider:    false,
		},
		{
			name:      "valid final method replaces empty value",
			argv:      []string{"wget", "--method=", "--method=GET", "https://example.test"},
			complete:  true,
			bodyValid: true,
			method:    "GET",
			spider:    false,
		},
		{
			name:      "empty custom method remains parser complete",
			argv:      []string{"wget", "--method=", "https://example.test"},
			complete:  true,
			bodyValid: true,
		},
		{
			name:      "final explicit no spider wins without head",
			argv:      []string{"wget", "--spider", "--no-spider", "--method=GET", "https://example.test"},
			complete:  true,
			bodyValid: true,
			method:    "GET",
			spider:    false,
		},
		{
			name:      "head overrides explicit no spider during finalization",
			argv:      []string{"wget", "--method=HEAD", "--no-spider", "https://example.test"},
			complete:  true,
			bodyValid: true,
			method:    "HEAD",
			spider:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed := parseWgetArgv(test.argv)
			if parsed.Complete != test.complete || parsed.RequestBodyValid != test.bodyValid {
				t.Fatalf("parse validity = (%t, %t), want (%t, %t): %#v", parsed.Complete, parsed.RequestBodyValid, test.complete, test.bodyValid, parsed)
			}
			if parsed.RequestBodyIssue != test.issue {
				t.Fatalf("RequestBodyIssue = %q, want %q", parsed.RequestBodyIssue, test.issue)
			}
			if parsed.Method != test.method || parsed.Spider != test.spider {
				t.Fatalf("method/spider = (%q, %t), want (%q, %t): %#v", parsed.Method, parsed.Spider, test.method, test.spider, parsed)
			}
		})
	}
}

func TestWgetDedicatedRequestByteGrammar(t *testing.T) {
	if !validWgetUserAgent("agent\tvalue") || validWgetUserAgent("agent\nvalue") ||
		validWgetUserAgent("agent"+string(rune(0))+"value") {
		t.Fatal("Wget user-agent byte grammar mismatch")
	}
	if !wgetRefererBytesPreserved("source\nvalue") ||
		wgetRefererBytesPreserved("source"+string(rune(0))+"value") {
		t.Fatal("Wget referer byte grammar mismatch")
	}
	if !validWgetMethod("") || !validWgetMethod("x-method\t") ||
		validWgetMethod("x-method"+string(rune(0))) {
		t.Fatal("Wget method byte grammar mismatch")
	}
	if got, want := wgetUpperASCII("x-é\t"), "X-é\t"; got != want {
		t.Fatalf("bytewise uppercase = %q, want %q", got, want)
	}
}

func TestParseWgetArgvEmptyAndValidatedValues(t *testing.T) {
	tests := []struct {
		name      string
		argv      []string
		complete  bool
		bodyValid bool
		issue     wgetRequestBodyIssue
	}{
		{
			name:      "empty header is legal",
			argv:      []string{"wget", "--header=", "https://example.test"},
			complete:  true,
			bodyValid: true,
		},
		{
			name:      "empty post data is legal",
			argv:      []string{"wget", "--post-data=", "https://example.test"},
			complete:  true,
			bodyValid: true,
		},
		{
			name:      "empty output is invalid",
			argv:      []string{"wget", "--output-document=", "https://example.test"},
			complete:  false,
			bodyValid: true,
		},
		{
			name:      "empty post file is invalid",
			argv:      []string{"wget", "--post-file=", "https://example.test"},
			complete:  false,
			bodyValid: false,
			issue:     wgetRequestBodyIssueInvalidFileValue,
		},
		{
			name:      "invalid timeout",
			argv:      []string{"wget", "--timeout=soon", "https://example.test"},
			complete:  false,
			bodyValid: true,
		},
		{
			name:      "negative tries",
			argv:      []string{"wget", "--tries=-1", "https://example.test"},
			complete:  false,
			bodyValid: true,
		},
		{
			name:      "invalid quota",
			argv:      []string{"wget", "--quota=bogus", "https://example.test"},
			complete:  false,
			bodyValid: true,
		},
		{
			name:      "valid fractional quota",
			argv:      []string{"wget", "--quota=1.5G", "https://example.test"},
			complete:  true,
			bodyValid: true,
		},
		{
			name:      "valid timeout and infinite tries",
			argv:      []string{"wget", "--timeout=0.5s", "--tries=inf", "https://example.test"},
			complete:  true,
			bodyValid: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed := parseWgetArgv(test.argv)
			if parsed.Complete != test.complete || parsed.RequestBodyValid != test.bodyValid {
				t.Fatalf("parse validity = (%t, %t), want (%t, %t): %#v", parsed.Complete, parsed.RequestBodyValid, test.complete, test.bodyValid, parsed)
			}
			if parsed.RequestBodyIssue != test.issue {
				t.Fatalf("RequestBodyIssue = %q, want %q", parsed.RequestBodyIssue, test.issue)
			}
		})
	}
}

func TestParseWgetArgvFinalRequestBodyFileWins(t *testing.T) {
	post := parseWgetArgv([]string{
		"wget", "--post-file=", "--post-file=payload.bin", "https://example.test",
	})
	if !post.Complete || !post.RequestBodyValid || post.PostFile != "payload.bin" {
		t.Fatalf("final post file did not replace empty value: %#v", post)
	}

	body := parseWgetArgv([]string{
		"wget", "--method=PUT", "--body-file=", "--body-file=payload.bin", "https://example.test",
	})
	if !body.Complete || !body.RequestBodyValid || body.BodyFile != "payload.bin" {
		t.Fatalf("final body file did not replace empty value: %#v", body)
	}
}

func TestParseWgetArgvFinalProxyState(t *testing.T) {
	tests := []struct {
		name        string
		argv        []string
		proxy       bool
		optionIndex int
		valueIndex  int
	}{
		{"long disabled", []string{"wget", "--proxy=off", "https://example.test"}, false, 1, -1},
		{"negated disabled", []string{"wget", "--no-proxy", "https://example.test"}, false, 1, -1},
		{"short disabled", []string{"wget", "-Y", "off", "https://example.test"}, false, 1, 2},
		{"final enabled", []string{"wget", "--proxy=off", "--proxy", "https://example.test"}, true, 2, -1},
		{"final disabled", []string{"wget", "--proxy", "--no-proxy", "https://example.test"}, false, 2, -1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed := parseWgetArgv(test.argv)
			if !parsed.Complete || !parsed.ProxySet || parsed.Proxy != test.proxy ||
				parsed.ProxyOptionIndex != test.optionIndex ||
				parsed.ProxyValueIndex != test.valueIndex {
				t.Fatalf(
					"proxy state = %#v, want enabled=%t option index=%d value index=%d",
					parsed,
					test.proxy,
					test.optionIndex,
					test.valueIndex,
				)
			}
		})
	}
}

func TestParseWgetArgvRecognizedSanityConflicts(t *testing.T) {
	tests := []struct {
		name     string
		argv     []string
		complete bool
	}{
		{
			name:     "timestamping conflicts with no clobber",
			argv:     []string{"wget", "-N", "-nc", "-O-", "https://example.test"},
			complete: false,
		},
		{
			name:     "convert links resolves no clobber before timestamp check",
			argv:     []string{"wget", "-N", "-nc", "-k", "-O", "output.html", "https://example.test"},
			complete: true,
		},
		{
			name:     "convert links conflicts with recursive output document",
			argv:     []string{"wget", "-k", "-r", "-O-", "https://example.test"},
			complete: false,
		},
		{
			name:     "convert links conflicts with page requisites output document",
			argv:     []string{"wget", "-k", "-p", "-O-", "https://example.test"},
			complete: false,
		},
		{
			name:     "convert links conflicts with multiple output document targets",
			argv:     []string{"wget", "-k", "-O-", "https://example.test/one", "https://example.test/two"},
			complete: false,
		},
		{
			name:     "recursive stdout output is not a regular file",
			argv:     []string{"wget", "-r", "-O-", "https://example.test"},
			complete: false,
		},
		{
			name:     "single target conversion still requires regular output",
			argv:     []string{"wget", "-k", "-O-", "https://example.test"},
			complete: false,
		},
		{
			name:     "later negations clear stdout conflicts",
			argv:     []string{"wget", "-k", "-r", "--no-recursive", "--no-convert-links", "-O-", "https://example.test"},
			complete: true,
		},
		{
			name:     "page requisites alone may stream stdout",
			argv:     []string{"wget", "-p", "-O-", "https://example.test"},
			complete: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed := parseWgetArgv(test.argv)
			if parsed.Complete != test.complete {
				t.Fatalf("Complete = %t, want %t: %#v", parsed.Complete, test.complete, parsed)
			}
		})
	}
}

func TestParseWgetArgvTargetRequirement(t *testing.T) {
	tests := []struct {
		name     string
		argv     []string
		complete bool
		preview  bool
		targets  []string
	}{
		{
			name:     "no target",
			argv:     []string{"wget", "-O-"},
			complete: false,
		},
		{
			name:     "help does not require target",
			argv:     []string{"wget", "--help"},
			complete: true,
			preview:  true,
		},
		{
			name:     "input file supplies targets indirectly",
			argv:     []string{"wget", "-i", "urls.txt"},
			complete: true,
		},
		{
			name:     "option terminator makes help shaped target",
			argv:     []string{"wget", "--", "--help"},
			complete: true,
			targets:  []string{"--help"},
		},
		{
			name:     "unknown option is incomplete",
			argv:     []string{"wget", "--future-mode", "https://example.test"},
			complete: false,
		},
		{
			name:     "spider has no short s alias",
			argv:     []string{"wget", "-s", "-O-", "https://example.test"},
			complete: false,
		},
		{
			name:     "empty target is incomplete",
			argv:     []string{"wget", ""},
			complete: false,
			targets:  []string{""},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed := parseWgetArgv(test.argv)
			if parsed.Complete != test.complete || parsed.Preview != test.preview {
				t.Fatalf("complete/preview = (%t, %t), want (%t, %t): %#v", parsed.Complete, parsed.Preview, test.complete, test.preview, parsed)
			}
			if !reflect.DeepEqual(parsed.Targets, test.targets) {
				t.Fatalf("Targets = %#v, want %#v", parsed.Targets, test.targets)
			}
		})
	}
}
