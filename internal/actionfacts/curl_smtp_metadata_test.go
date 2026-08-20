// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"testing"
)

func TestParseCurlArgvOwnsSMTPOptionValues(t *testing.T) {
	t.Parallel()

	argv := []string{
		"curl",
		"--no-append", "--buffer", "--no-compressed", "--no-globoff",
		"--no-include", "--no-insecure", "--no-junk-session-cookies",
		"--no-list-only", "--no-location", "--no-parallel",
		"--no-progress-bar", "--progress-meter", "--no-remote-time",
		"--no-show-error", "--no-silent", "--no-use-ascii", "--no-verbose",
		"--mail-from", "--help",
		"--mail-rcpt=recipient@example.org",
		"--mail-auth", "--version",
		"--mail-rcpt-allowfails",
		"--no-mail-rcpt-allowfails",
		"smtp://sink.example",
	}
	parsed := parseCurlArgv(argv)
	if !parsed.Complete || parsed.Preview || len(parsed.Targets) != 1 ||
		parsed.Targets[0].Value != "smtp://sink.example" {
		t.Fatalf("parse = %#v", parsed)
	}
	wantValues := map[string][]string{
		"--mail-from": {"--help"},
		"--mail-rcpt": {"recipient@example.org"},
		"--mail-auth": {"--version"},
	}
	gotValues := make(map[string][]string)
	allowFails := 0
	for _, option := range parsed.Options {
		if option.Canonical == "--mail-rcpt-allowfails" {
			allowFails++
			if option.TakesValue || option.ValuePresent {
				t.Fatalf("allow-fails option owns a value: %#v", option)
			}
			continue
		}
		if _, ok := wantValues[option.Canonical]; ok {
			gotValues[option.Canonical] = append(
				gotValues[option.Canonical],
				option.Value,
			)
		}
	}
	if allowFails != 2 {
		t.Fatalf("allow-fails options = %d, want 2: %#v", allowFails, parsed.Options)
	}
	for option, want := range wantValues {
		if got := gotValues[option]; !slices.Equal(got, want) {
			t.Fatalf("%s values = %q, want %q", option, got, want)
		}
	}
	preview, _ := webControlMode(argv, "curl")
	if preview {
		t.Fatal("help-shaped SMTP operands changed the command to preview mode")
	}
	facts := Analyze(Input{Tool: "exec", Argv: argv})
	if len(facts.Commands) != 1 {
		t.Fatalf("commands = %#v", facts.Commands)
	}
	wantComponents := []TransmittedRequestComponent{{
		Value: "recipient@example.org", Scheme: "smtp", Host: "sink.example",
	}}
	if got := StaticCurlSMTPRequestComponents(facts.Commands[0]); !slices.Equal(got, wantComponents) {
		t.Fatalf("components = %#v, want %#v", got, wantComponents)
	}
}

func TestStaticCurlSMTPRequestComponents(t *testing.T) {
	t.Parallel()

	component := func(
		scheme string,
		host string,
		port int64,
		values ...string,
	) []TransmittedRequestComponent {
		result := make([]TransmittedRequestComponent, 0, len(values))
		for _, value := range values {
			result = append(result, TransmittedRequestComponent{
				Value: value, Scheme: scheme, Host: host, Port: port,
			})
		}
		return result
	}
	for _, test := range []struct {
		name              string
		argv              []string
		expandIndex       int
		mixedIndex        int
		want              []TransmittedRequestComponent
		wantNetworkScheme string
		wantNetworkAction NetworkAction
	}{
		{
			name: "reported SMTP envelope",
			argv: []string{
				"curl", "-sk4", "--mail-from", "sender@example.org",
				"--mail-rcpt", "recipient@sink.example",
				"--upload-file", "/dev/null", "smtp://sink.example",
			},
			want: component(
				"smtp", "sink.example", 0,
				"sender@example.org", "recipient@sink.example",
			),
			wantNetworkScheme: "smtp",
			wantNetworkAction: NetworkUpload,
		},
		{
			name: "final sender and appended recipients over SMTPS",
			argv: []string{
				"curl", "--silent", "--show-error", "--verbose",
				"--no-progress-meter", "--progress-bar", "--no-buffer",
				"--mail-from", "old@example.org",
				"--mail-from=final@example.org",
				"--mail-auth", "relay@example.org",
				"--mail-rcpt", "one@example.org",
				"--mail-rcpt=two@example.org",
				"--mail-rcpt-allowfails", "--no-mail-rcpt-allowfails",
				"--upload-file", "-", "--url=smtps://sink.example:465/",
			},
			want: component(
				"smtps", "sink.example", 465,
				"final@example.org", "one@example.org", "two@example.org",
			),
			wantNetworkScheme: "smtps",
			wantNetworkAction: NetworkUpload,
		},
		{
			name: "nonblocking stdin upload",
			argv: []string{
				"curl", "--mail-from", "sender@example.org",
				"--mail-rcpt", "recipient@example.org",
				"--upload-file", ".", "smtp://sink.example/",
			},
			want: component(
				"smtp", "sink.example", 0,
				"sender@example.org", "recipient@example.org",
			),
			wantNetworkScheme: "smtp",
			wantNetworkAction: NetworkUpload,
		},
		{
			name: "conditional mail auth does not suppress envelope",
			argv: []string{
				"curl", "--mail-auth", "<relay@exämple.org>",
				"--mail-from", "sender@example.org",
				"--mail-rcpt", "recipient@example.org",
				"--upload-file", "/dev/null", "smtp://sink.example",
			},
			want: component(
				"smtp", "sink.example", 0,
				"sender@example.org", "recipient@example.org",
			),
			wantNetworkScheme: "smtp",
			wantNetworkAction: NetworkUpload,
		},
		{
			name: "default VRFY sends only first recipient",
			argv: []string{
				"curl", "--mail-from", "ignored@example.org",
				"--mail-rcpt", "first@example.org",
				"--mail-rcpt", "second@example.org", "smtp://sink.example",
			},
			want:              component("smtp", "sink.example", 0, "first@example.org"),
			wantNetworkScheme: "smtp",
			wantNetworkAction: NetworkDownload,
		},
		{
			name: "upload without explicit sender still sends recipients",
			argv: []string{
				"curl", "--mail-rcpt", "recipient@example.org",
				"--upload-file", "/dev/null", "smtp://sink.example",
			},
			want:              component("smtp", "sink.example", 0, "recipient@example.org"),
			wantNetworkScheme: "smtp",
			wantNetworkAction: NetworkUpload,
		},
		{
			name: "empty upload recipient does not hide later recipients",
			argv: []string{
				"curl", "--mail-from", "sender@example.org",
				"--mail-rcpt", "", "--mail-rcpt", "recipient@example.org",
				"--upload-file", "/dev/null", "smtp://sink.example",
			},
			want: component(
				"smtp", "sink.example", 0,
				"sender@example.org", "recipient@example.org",
			),
			wantNetworkScheme: "smtp",
			wantNetworkAction: NetworkUpload,
		},
		{
			name: "empty first VRFY recipient does not expose later recipients",
			argv: []string{
				"curl", "--mail-rcpt", "", "--mail-rcpt", "later@example.org",
				"smtp://sink.example",
			},
		},
		{
			name: "local destination remains target bound",
			argv: []string{
				"curl", "--mail-from", "sender@example.org",
				"--mail-rcpt", "recipient@example.org",
				"--upload-file", "/dev/null", "smtp://127.0.0.1",
			},
			want: component(
				"smtp", "127.0.0.1", 0,
				"sender@example.org", "recipient@example.org",
			),
			wantNetworkScheme: "smtp",
			wantNetworkAction: NetworkUpload,
		},
		{
			name: "mail from without recipient is not sent",
			argv: []string{
				"curl", "--mail-from", "sender@example.org",
				"--upload-file", "/dev/null", "smtp://sink.example",
			},
		},
		{
			name: "arbitrary upload file can fail before connect",
			argv: []string{
				"curl", "--mail-from", "sender@example.org",
				"--mail-rcpt", "recipient@example.org",
				"--upload-file", "/tmp/message", "smtp://sink.example",
			},
		},
		{
			name: "multiple upload files are outside the proof",
			argv: []string{
				"curl", "--mail-from", "sender@example.org",
				"--mail-rcpt", "recipient@example.org",
				"--upload-file", "/dev/null", "--upload-file", "-",
				"smtp://sink.example",
			},
		},
		{
			name: "outer brackets are normalized exactly",
			argv: []string{
				"curl", "--mail-from", "<sender@example.org>",
				"--mail-rcpt", "<recipient%41@example.org>",
				"--upload-file", "/dev/null", "smtp://sink.example",
			},
			want: component(
				"smtp", "sink.example", 0,
				"sender@example.org", "recipient%41@example.org",
			),
			wantNetworkScheme: "smtp",
			wantNetworkAction: NetworkUpload,
		},
		{
			name: "interior brackets are preserved",
			argv: []string{
				"curl", "--mail-from", "send<er@example.org",
				"--mail-rcpt", "recipient@example.org",
				"--upload-file", "/dev/null", "smtp://sink.example",
			},
			want: component(
				"smtp", "sink.example", 0,
				"send<er@example.org", "recipient@example.org",
			),
			wantNetworkScheme: "smtp",
			wantNetworkAction: NetworkUpload,
		},
		{
			name: "ASCII control bytes are preserved",
			argv: []string{
				"curl", "--mail-from", "sender@example.org\t",
				"--mail-rcpt", "recipient@example.org\r\n",
				"--upload-file", "/dev/null", "smtp://sink.example",
			},
			want: component(
				"smtp", "sink.example", 0,
				"sender@example.org\t", "recipient@example.org\r\n",
			),
			wantNetworkScheme: "smtp",
			wantNetworkAction: NetworkUpload,
		},
		{
			name: "empty normalized addresses do not hide later recipients",
			argv: []string{
				"curl", "--mail-from", "<>", "--mail-rcpt", "<>",
				"--mail-rcpt", "recipient@example.org",
				"--upload-file", "/dev/null", "smtp://sink.example",
			},
			want:              component("smtp", "sink.example", 0, "recipient@example.org"),
			wantNetworkScheme: "smtp",
			wantNetworkAction: NetworkUpload,
		},
		{
			name: "empty normalized first VRFY recipient does not fall through",
			argv: []string{
				"curl", "--mail-rcpt", "<>",
				"--mail-rcpt", "later@example.org", "smtp://sink.example",
			},
		},
		{
			name: "IDN sender preserves only exact local prefix",
			argv: []string{
				"curl", "--mail-from", "sender@exämple.org",
				"--mail-rcpt", "recipient@example.org",
				"--upload-file", "/dev/null", "smtp://sink.example",
			},
			want: component(
				"smtp", "sink.example", 0, "sender", "recipient@example.org",
			),
			wantNetworkScheme: "smtp",
			wantNetworkAction: NetworkUpload,
		},
		{
			name: "IDN recipient does not erase exact sender",
			argv: []string{
				"curl", "--mail-from", "sender@example.org",
				"--mail-rcpt", "recipient@exämple.org",
				"--upload-file", "/dev/null", "smtp://sink.example",
			},
			want: component(
				"smtp", "sink.example", 0, "sender@example.org", "recipient",
			),
			wantNetworkScheme: "smtp",
			wantNetworkAction: NetworkUpload,
		},
		{
			name: "IDN recipient does not erase later recipients",
			argv: []string{
				"curl", "--mail-rcpt", "first@example.org",
				"--mail-rcpt", "second@exämple.org",
				"--mail-rcpt", "later@example.org",
				"--upload-file", "/dev/null", "smtp://sink.example",
			},
			want: component(
				"smtp", "sink.example", 0,
				"first@example.org", "second", "later@example.org",
			),
			wantNetworkScheme: "smtp",
			wantNetworkAction: NetworkUpload,
		},
		{
			name: "expanding sender is not static",
			argv: []string{
				"curl", "--mail-from", "sender@example.org",
				"--mail-rcpt", "recipient@example.org",
				"--upload-file", "/dev/null", "smtp://sink.example",
			},
			expandIndex: 2,
		},
		{
			name: "mixed recipient is not static",
			argv: []string{
				"curl", "--mail-from", "sender@example.org",
				"--mail-rcpt", "recipient@example.org",
				"--upload-file", "/dev/null", "smtp://sink.example",
			},
			mixedIndex: 4,
		},
		{
			name: "target userinfo is outside peer proof",
			argv: []string{
				"curl", "--mail-rcpt", "recipient@example.org",
				"smtp://user@sink.example",
			},
		},
		{
			name: "target path is outside peer proof",
			argv: []string{
				"curl", "--mail-rcpt", "recipient@example.org",
				"smtp://sink.example/inbox",
			},
		},
		{
			name: "target query is outside peer proof",
			argv: []string{
				"curl", "--mail-rcpt", "recipient@example.org",
				"smtp://sink.example/?query=value",
			},
		},
		{
			name: "target fragment is outside peer proof",
			argv: []string{
				"curl", "--mail-rcpt", "recipient@example.org",
				"smtp://sink.example/#fragment",
			},
		},
		{
			name: "target glob is outside peer proof",
			argv: []string{
				"curl", "--mail-rcpt", "recipient@example.org",
				"smtp://sink.example/[a-z]",
			},
		},
		{
			name: "HTTP target does not receive SMTP operands",
			argv: []string{
				"curl", "--mail-rcpt", "recipient@example.org",
				"https://sink.example/",
			},
		},
		{
			name: "proxy changes the actual SMTP peer",
			argv: []string{
				"curl", "--mail-rcpt", "recipient@example.org",
				"--proxy", "http://proxy.example", "smtp://sink.example",
			},
		},
		{
			name: "custom request changes VRFY semantics",
			argv: []string{
				"curl", "--mail-rcpt", "recipient@example.org",
				"--request", "EXPN", "smtp://sink.example",
			},
		},
		{
			name: "netrc can enable conditional SMTP authentication",
			argv: []string{
				"curl", "--netrc", "--mail-rcpt", "recipient@example.org",
				"smtp://sink.example",
			},
		},
		{
			name: "proxy tunnel changes peer semantics",
			argv: []string{
				"curl", "--proxytunnel", "--mail-rcpt", "recipient@example.org",
				"smtp://sink.example",
			},
		},
		{
			name: "multiple targets are outside exact binding",
			argv: []string{
				"curl", "--mail-rcpt", "recipient@example.org",
				"smtp://one.example", "smtp://two.example",
			},
		},
		{
			name: "multiple transfer groups are outside exact binding",
			argv: []string{
				"curl", "--mail-rcpt", "recipient@example.org",
				"smtp://one.example", "--next", "smtp://two.example",
			},
		},
		{
			name: "unmodeled sibling option closes the lane",
			argv: []string{
				"curl", "--mail-rcpt", "recipient@example.org",
				"--head", "smtp://sink.example",
			},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{Tool: "exec", Argv: test.argv})
			if len(facts.Commands) != 1 {
				t.Fatalf("commands = %#v", facts.Commands)
			}
			if test.expandIndex > 0 {
				facts.Commands[0].Arguments[test.expandIndex].Expands = true
			}
			if test.mixedIndex > 0 {
				facts.Commands[0].Arguments[test.mixedIndex].Quote = QuoteMixed
			}
			got := StaticCurlSMTPRequestComponents(facts.Commands[0])
			if !slices.Equal(got, test.want) {
				t.Fatalf("components = %#v, want %#v; facts = %#v", got, test.want, facts)
			}
			if test.wantNetworkScheme == "" {
				return
			}
			if !facts.Authoritative() || !facts.EnforcementEligible() {
				t.Fatalf("valid SMTP facts are not authoritative: %#v", facts)
			}
			found := false
			for _, network := range facts.Network {
				if network.CommandID == facts.Commands[0].ID &&
					network.Scheme == test.wantNetworkScheme &&
					network.Action == test.wantNetworkAction {
					found = true
				}
			}
			if !found {
				t.Fatalf(
					"missing %s %s network fact: %#v",
					test.wantNetworkScheme,
					test.wantNetworkAction,
					facts.Network,
				)
			}
		})
	}
}

func TestStaticCurlSMTPRequestComponentsRejectsShellRedirects(t *testing.T) {
	t.Parallel()

	for _, commandText := range []string{
		"curl --mail-from sender@example.org --mail-rcpt recipient@example.org " +
			"--upload-file /dev/null smtp://sink.example < /definitely/missing",
		"curl --mail-from sender@example.org --mail-rcpt recipient@example.org " +
			"--upload-file /dev/null smtp://sink.example > /definitely/missing/out",
		"curl --mail-from sender@example.org --mail-rcpt recipient@example.org " +
			"--upload-file - smtp://sink.example < /definitely/missing",
	} {
		commandText := commandText
		t.Run(commandText, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{Tool: "exec", Command: commandText})
			found := false
			for _, command := range facts.Commands {
				if command.Program != "curl" {
					continue
				}
				found = true
				if len(command.Redirects) == 0 {
					t.Fatalf("curl command has no redirect: %#v", facts)
				}
				if got := StaticCurlSMTPRequestComponents(command); got != nil {
					t.Fatalf("redirected components = %#v, want nil", got)
				}
			}
			if !found {
				t.Fatalf("missing curl command: %#v", facts)
			}
		})
	}
}

func TestWgetDoesNotInheritCurlSMTPDestinations(t *testing.T) {
	t.Parallel()

	wget := Analyze(Input{
		Tool: "exec",
		Argv: []string{"wget", "-O", "/dev/null", "smtp://sink.example"},
	})
	if wget.Authoritative() || wget.EnforcementEligible() {
		t.Fatalf("unsupported wget SMTP target is authoritative: %#v", wget)
	}
	for _, network := range wget.Network {
		if network.Scheme == "smtp" || network.Scheme == "smtps" {
			t.Fatalf("wget inherited curl-only SMTP fact: %#v", wget.Network)
		}
	}

	for _, target := range []string{
		"smtp://sink.example",
		"smtps://sink.example:465/",
	} {
		facts := Analyze(Input{
			Tool: "exec",
			Argv: []string{"curl", "--mail-rcpt", "recipient@example.org", target},
		})
		if !facts.Authoritative() || !facts.EnforcementEligible() {
			t.Fatalf("curl SMTP target is not authoritative: %#v", facts)
		}
		if len(facts.Commands) != 1 ||
			len(StaticCurlSMTPRequestComponents(facts.Commands[0])) != 1 {
			t.Fatalf("curl SMTP target has no request projection: %#v", facts)
		}
	}
}

func TestCurlSMTPTargetUserinfoControlsArePreconnectFailures(t *testing.T) {
	t.Parallel()

	for _, target := range []string{
		"smtp://user:%00@sink.example",
		"smtps://user%0A@sink.example",
	} {
		facts := Analyze(Input{
			Tool: "exec",
			Argv: []string{"curl", "--mail-rcpt", "recipient@example.org", target},
		})
		if facts.Authoritative() || facts.EnforcementEligible() {
			t.Fatalf("control-bearing SMTP userinfo is authoritative: %#v", facts)
		}
		for _, network := range facts.Network {
			if network.Scheme == "smtp" || network.Scheme == "smtps" {
				t.Fatalf("control-bearing userinfo produced SMTP fact: %#v", facts.Network)
			}
		}
	}

	for _, target := range []string{
		"smtp://user:password@sink.example",
		"smtps://user:%7F@sink.example:465/",
		"smtp://user:%zz@sink.example",
	} {
		facts := Analyze(Input{
			Tool: "exec",
			Argv: []string{"curl", "--mail-rcpt", "recipient@example.org", target},
		})
		if !facts.Authoritative() || !facts.EnforcementEligible() {
			t.Fatalf("valid SMTP userinfo lost destination authority: %#v", facts)
		}
		found := false
		for _, network := range facts.Network {
			if network.Scheme == "smtp" || network.Scheme == "smtps" {
				found = true
			}
		}
		if !found {
			t.Fatalf("valid userinfo has no SMTP destination fact: %#v", facts)
		}
		if len(facts.Commands) != 1 ||
			StaticCurlSMTPRequestComponents(facts.Commands[0]) != nil {
			t.Fatalf("userinfo entered strict SMTP component proof: %#v", facts)
		}
	}
}
