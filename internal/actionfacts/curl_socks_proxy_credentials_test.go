// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"strings"
	"testing"
)

func TestStaticCurlSOCKSProxyCredentialComponents(t *testing.T) {
	t.Parallel()

	const token = "AKIA7Q2M9X4B6C8D3F5H"
	components := func(host string, port int64, values ...string) []TransmittedRequestComponent {
		result := make([]TransmittedRequestComponent, 0, len(values))
		for _, value := range values {
			result = append(result, TransmittedRequestComponent{
				Value: value, Scheme: "tcp", Host: host, Port: port,
			})
		}
		return result
	}
	for _, test := range []struct {
		name              string
		argv              []string
		expandIndex       int
		want              []TransmittedRequestComponent
		wantAuthoritative bool
	}{
		{
			name: "reported SOCKS5 hostname credentials",
			argv: []string{
				"curl", "--socks5-hostname", "proxy.example", "--proxy-user",
				"proxy:" + token, "https://origin.example",
			},
			want:              components("proxy.example", 1080, "proxy", token),
			wantAuthoritative: true,
		},
		{
			name: "short proxy user and explicit port",
			argv: []string{
				"curl", "--socks5", "proxy.example:1081", "-Uproxy:" + token,
				"https://origin.example",
			},
			want:              components("proxy.example", 1081, "proxy", token),
			wantAuthoritative: true,
		},
		{
			name: "SOCKS URL credentials are separate decoded fields",
			argv: []string{
				"curl", "--proxy", "socks5h://user%3A" + token + ":pass@proxy.example",
				"https://origin.example",
			},
			want: components(
				"proxy.example", 1080, "user:"+token, "pass",
			),
			wantAuthoritative: true,
		},
		{
			name: "URL credentials override proxy user",
			argv: []string{
				"curl", "--proxy", "socks5://url:safe@proxy.example",
				"--proxy-user", "proxy:" + token, "https://origin.example",
			},
			want:              components("proxy.example", 1080, "url", "safe"),
			wantAuthoritative: true,
		},
		{
			name: "final proxy user wins",
			argv: []string{
				"curl", "--proxy", "socks5://proxy.example", "--proxy-user",
				"proxy:safe", "--proxy-user", "proxy:" + token,
				"https://origin.example",
			},
			want:              components("proxy.example", 1080, "proxy", token),
			wantAuthoritative: true,
		},
		{
			name: "final safe proxy user suppresses stale secret",
			argv: []string{
				"curl", "--proxy", "socks5://proxy.example", "--proxy-user",
				"proxy:" + token, "--proxy-user", "proxy:safe",
				"https://origin.example",
			},
			want:              components("proxy.example", 1080, "proxy", "safe"),
			wantAuthoritative: true,
		},
		{
			name: "SOCKS4 sends username only",
			argv: []string{
				"curl", "--socks4a", "proxy.example", "--proxy-user",
				"safe:" + token, "https://origin.example",
			},
			want:              components("proxy.example", 1080, "safe"),
			wantAuthoritative: true,
		},
		{
			name: "SOCKS4 username can carry secret",
			argv: []string{
				"curl", "--proxy", "socks4://proxy.example", "--proxy-user",
				token + ":safe", "https://origin.example",
			},
			want:              components("proxy.example", 1080, token),
			wantAuthoritative: true,
		},
		{
			name: "SOCKS4 ignores oversized password",
			argv: []string{
				"curl", "--socks4", "proxy.example", "--proxy-user",
				token + ":" + strings.Repeat("p", 256), "https://origin.example",
			},
			want:              components("proxy.example", 1080, token),
			wantAuthoritative: true,
		},
		{
			name: "SOCKS4 accepts a 255 byte decoded username",
			argv: []string{
				"curl", "--socks4a", "proxy.example", "--proxy-user",
				strings.Repeat("%41", 255) + ":safe", "https://origin.example",
			},
			want: components(
				"proxy.example", 1080, strings.Repeat("A", 255),
			),
			wantAuthoritative: true,
		},
		{
			name: "SOCKS4 rejects a 256 byte decoded username",
			argv: []string{
				"curl", "--socks4a", "proxy.example", "--proxy-user",
				strings.Repeat("%41", 256) + ":safe", "https://origin.example",
			},
		},
		{
			name: "SOCKS4 cannot encode an IPv6 literal origin",
			argv: []string{
				"curl", "--globoff", "--socks4", "proxy.example", "--proxy-user",
				token + ":safe", "https://[2001:4860:4860::8888]/",
			},
		},
		{
			name: "SOCKS4a IPv6 remains outside the shared glob boundary",
			argv: []string{
				"curl", "--globoff", "--socks4a", "proxy.example", "--proxy-user",
				token + ":safe", "https://[2001:4860:4860::8888]/",
			},
		},
		{
			name: "SOCKS4 rejects an IPv4 mapped IPv6 literal spelling",
			argv: []string{
				"curl", "--globoff", "--socks4", "proxy.example", "--proxy-user",
				token + ":safe", "https://[::ffff:192.0.2.1]/",
			},
		},
		{
			name: "SOCKS5 oversized password cannot be sent",
			argv: []string{
				"curl", "--socks5", "proxy.example", "--proxy-user",
				"proxy:" + token + strings.Repeat("p", 236),
				"https://origin.example",
			},
			wantAuthoritative: true,
		},
		{
			name: "SOCKS5 accepts a 255 byte decoded username",
			argv: []string{
				"curl", "--socks5", "proxy.example", "--proxy-user",
				strings.Repeat("%41", 255) + ":safe", "https://origin.example",
			},
			want: components(
				"proxy.example", 1080, strings.Repeat("A", 255), "safe",
			),
			wantAuthoritative: true,
		},
		{
			name: "SOCKS5 rejects a 256 byte decoded username",
			argv: []string{
				"curl", "--socks5", "proxy.example", "--proxy-user",
				strings.Repeat("%41", 256) + ":safe", "https://origin.example",
			},
			wantAuthoritative: true,
		},
		{
			name: "SOCKS5 accepts a 255 byte decoded password",
			argv: []string{
				"curl", "--socks5", "proxy.example", "--proxy-user",
				"safe:" + strings.Repeat("%42", 255), "https://origin.example",
			},
			want: components(
				"proxy.example", 1080, "safe", strings.Repeat("B", 255),
			),
			wantAuthoritative: true,
		},
		{
			name: "SOCKS5 rejects a 256 byte decoded password",
			argv: []string{
				"curl", "--socks5", "proxy.example", "--proxy-user",
				"safe:" + strings.Repeat("%42", 256), "https://origin.example",
			},
			wantAuthoritative: true,
		},
		{
			name: "SOCKS5 GSSAPI only suppresses basic fields",
			argv: []string{
				"curl", "--socks5-hostname", "proxy.example", "--socks5-gssapi",
				"--proxy-user", "proxy:" + token, "https://origin.example",
			},
			wantAuthoritative: true,
		},
		{
			name: "SOCKS5 basic restores credential fields",
			argv: []string{
				"curl", "--socks5-hostname", "proxy.example", "--socks5-gssapi",
				"--socks5-basic", "--proxy-user", "proxy:" + token,
				"https://origin.example",
			},
			want:              components("proxy.example", 1080, "proxy", token),
			wantAuthoritative: true,
		},
		{
			name: "zero CLI auth mask uses libcurl default basic",
			argv: []string{
				"curl", "--socks5-hostname", "proxy.example", "--socks5-gssapi",
				"--no-socks5-gssapi", "--proxy-user", "proxy:" + token,
				"https://origin.example",
			},
			want:              components("proxy.example", 1080, "proxy", token),
			wantAuthoritative: true,
		},
		{
			name: "no basic alone leaves the zero mask default",
			argv: []string{
				"curl", "--socks5-hostname", "proxy.example", "--no-socks5-basic",
				"--proxy-user", "proxy:" + token, "https://origin.example",
			},
			want:              components("proxy.example", 1080, "proxy", token),
			wantAuthoritative: true,
		},
		{
			name: "GSSAPI plus no basic remains GSSAPI only",
			argv: []string{
				"curl", "--socks5-hostname", "proxy.example", "--socks5-gssapi",
				"--no-socks5-basic", "--proxy-user", "proxy:" + token,
				"https://origin.example",
			},
			wantAuthoritative: true,
		},
		{
			name: "basic then no basic resets to the zero mask default",
			argv: []string{
				"curl", "--socks5-hostname", "proxy.example", "--socks5-basic",
				"--no-socks5-basic", "--proxy-user", "proxy:" + token,
				"https://origin.example",
			},
			want:              components("proxy.example", 1080, "proxy", token),
			wantAuthoritative: true,
		},
		{
			name: "explicit HTTP scheme does not override SOCKS alias",
			argv: []string{
				"curl", "--socks5", "http://proxy.example", "--proxy-user",
				"proxy:" + token, "https://origin.example",
			},
			want:              components("proxy.example", 1080, "proxy", token),
			wantAuthoritative: true,
		},
		{
			name: "explicit HTTPS scheme overrides SOCKS alias",
			argv: []string{
				"curl", "--socks5", "https://proxy.example", "--proxy-user",
				"proxy:" + token, "https://origin.example",
			},
			wantAuthoritative: true,
		},
		{
			name: "harmless option padding preserves credential proof",
			argv: []string{
				"curl", "--socks5", "proxy.example", "--proxy-user",
				"proxy:" + token, "--insecure", "--proxytunnel",
				"--header", "X-Test: safe", "https://origin.example",
			},
			want:              components("proxy.example", 1080, "proxy", token),
			wantAuthoritative: true,
		},
		{
			name: "same group targets share SOCKS credentials",
			argv: []string{
				"curl", "--socks5", "proxy.example", "--proxy-user",
				"proxy:" + token, "https://one.example", "https://two.example",
			},
			want:              components("proxy.example", 1080, "proxy", token),
			wantAuthoritative: true,
		},
		{
			name: "local proxy remains exactly bound",
			argv: []string{
				"curl", "--socks5", "127.0.0.1", "--proxy-user",
				"proxy:" + token, "https://origin.example",
			},
			want:              components("127.0.0.1", 1080, "proxy", token),
			wantAuthoritative: true,
		},
		{
			name: "external proxy receives credentials for local origin",
			argv: []string{
				"curl", "--proxy", "socks5h://proxy.example", "--proxy-user",
				"proxy:" + token, "https://127.0.0.1",
			},
			want:              components("proxy.example", 1080, "proxy", token),
			wantAuthoritative: true,
		},
		{
			name: "FTP target uses the same SOCKS authentication",
			argv: []string{
				"curl", "--socks5-hostname", "proxy.example", "--proxy-user",
				"proxy:" + token, "ftp://origin.example/file",
			},
			want:              components("proxy.example", 1080, "proxy", token),
			wantAuthoritative: true,
		},
		{
			name: "active ambient netrc can abort before SOCKS authentication",
			argv: []string{
				"curl", "--netrc", "--socks5-hostname", "proxy.example",
				"--proxy-user", "proxy:" + token, "https://origin.example",
			},
		},
		{
			name: "active optional netrc can abort before SOCKS authentication",
			argv: []string{
				"curl", "--netrc-optional", "--socks5-hostname", "proxy.example",
				"--proxy-user", "proxy:" + token, "https://origin.example",
			},
		},
		{
			name: "arbitrary netrc file can abort before SOCKS authentication",
			argv: []string{
				"curl", "--netrc-file", "/dev/stdin", "--socks5-hostname",
				"proxy.example", "--proxy-user", "proxy:" + token,
				"https://origin.example",
			},
		},
		{
			name: "final disabled netrc state preserves SOCKS authentication",
			argv: []string{
				"curl", "--netrc", "--no-netrc", "--netrc-optional",
				"--no-netrc-optional", "--socks5-hostname", "proxy.example",
				"--proxy-user", "proxy:" + token, "https://origin.example",
			},
			want:              components("proxy.example", 1080, "proxy", token),
			wantAuthoritative: true,
		},
		{
			name: "explicit origin user skips active netrc setup",
			argv: []string{
				"curl", "--netrc-file", "/dev/stdin", "--user", "origin:pass",
				"--socks5-hostname", "proxy.example", "--proxy-user",
				"proxy:" + token, "https://origin.example",
			},
			want:              components("proxy.example", 1080, "proxy", token),
			wantAuthoritative: true,
		},
		{
			name: "matching noproxy suppresses SOCKS contact",
			argv: []string{
				"curl", "--proxy", "socks5h://proxy.example", "--noproxy",
				"origin.example", "--proxy-user", "proxy:" + token,
				"https://origin.example",
			},
		},
		{
			name: "nonmatching noproxy preserves SOCKS contact",
			argv: []string{
				"curl", "--proxy", "socks5h://proxy.example", "--noproxy",
				"never.example", "--proxy-user", "proxy:" + token,
				"https://origin.example",
			},
			want:              components("proxy.example", 1080, "proxy", token),
			wantAuthoritative: true,
		},
		{
			name: "mixed targets contact SOCKS for the nonmatch",
			argv: []string{
				"curl", "--proxy", "socks5h://proxy.example", "--noproxy",
				"one.example", "--proxy-user", "proxy:" + token,
				"https://one.example", "https://two.example",
			},
			want:              components("proxy.example", 1080, "proxy", token),
			wantAuthoritative: true,
		},
		{
			name: "final empty noproxy restores exact route",
			argv: []string{
				"curl", "--proxy", "socks5h://proxy.example", "--noproxy", "*",
				"--noproxy", "", "--proxy-user", "proxy:" + token,
				"https://origin.example",
			},
			want:              components("proxy.example", 1080, "proxy", token),
			wantAuthoritative: true,
		},
		{
			name: "standalone explicit SOCKS preproxy uses proxy user",
			argv: []string{
				"curl", "--preproxy", "socks5h://proxy.example", "--proxy-user",
				"proxy:" + token, "https://origin.example",
			},
			want:              components("proxy.example", 1080, "proxy", token),
			wantAuthoritative: true,
		},
		{
			name: "standalone preproxy URL credentials override proxy user",
			argv: []string{
				"curl", "--preproxy", "socks5://url:" + token + "@proxy.example",
				"--proxy-user", "proxy:safe", "https://origin.example",
			},
			want:              components("proxy.example", 1080, "url", token),
			wantAuthoritative: true,
		},
		{
			name: "empty main proxy leaves standalone SOCKS preproxy active",
			argv: []string{
				"curl", "--preproxy", "socks5h://proxy.example", "--proxy", "",
				"--proxy-user", "proxy:" + token, "https://origin.example",
			},
			want:              components("proxy.example", 1080, "proxy", token),
			wantAuthoritative: true,
		},
		{
			name: "decoded control main proxy leaves SOCKS preproxy active",
			argv: []string{
				"curl", "--preproxy", "socks5h://proxy.example", "--proxy",
				"http://u:%01@disabled.example", "--proxy-user", "proxy:" + token,
				"https://origin.example",
			},
			want:              components("proxy.example", 1080, "proxy", token),
			wantAuthoritative: true,
		},
		{
			name: "disabled SOCKS setter type is inherited by bare preproxy",
			argv: []string{
				"curl", "--preproxy", "proxy.example", "--socks5-hostname",
				"u:%01@disabled.example", "--proxy-user", "proxy:" + token,
				"https://origin.example",
			},
			want:              components("proxy.example", 1080, "proxy", token),
			wantAuthoritative: true,
		},
		{
			name: "disabled SOCKS setter survives HTTP preproxy scheme",
			argv: []string{
				"curl", "--preproxy", "http://proxy.example", "--socks4a",
				"u:%01@disabled.example", "--proxy-user", token + ":safe",
				"https://origin.example",
			},
			want:              components("proxy.example", 1080, token),
			wantAuthoritative: true,
		},
		{
			name: "HTTPS preproxy overrides inherited SOCKS setter",
			argv: []string{
				"curl", "--preproxy", "https://proxy.example", "--socks5-hostname",
				"u:%01@disabled.example", "--proxy-user", "proxy:" + token,
				"https://origin.example",
			},
		},
		{
			name: "empty generic proxy resets bare preproxy to HTTP",
			argv: []string{
				"curl", "--preproxy", "proxy.example", "--proxy", "",
				"--proxy-user", "proxy:" + token, "https://origin.example",
			},
		},
		{
			name: "bare standalone preproxy defaults outside SOCKS lane",
			argv: []string{
				"curl", "--preproxy", "proxy.example", "--proxy-user",
				"proxy:" + token, "https://origin.example",
			},
		},
		{
			name: "SOCKS preproxy chain uses a separate credential namespace",
			argv: []string{
				"curl", "--preproxy", "socks5h://pre:" + token + "@first.example",
				"--proxy", "http://proxy.example", "--proxy-user", "main:safe",
				"https://origin.example",
			},
		},
		{
			name: "FTP chain sends preproxy URL credentials to SOCKS peer",
			argv: []string{
				"curl", "--preproxy", "socks5h://pre:" + token + "@first.example",
				"--proxy", "http://main.example", "--proxy-user", "main:safe",
				"ftp://origin.example/file",
			},
			want:              components("first.example", 1080, "pre", token),
			wantAuthoritative: true,
		},
		{
			name: "FTP chain rejects an active arbitrary netrc file",
			argv: []string{
				"curl", "--netrc-file", "/dev/stdin", "--preproxy",
				"socks5h://pre:" + token + "@first.example", "--proxy",
				"http://main.example", "ftp://origin.example/file",
			},
		},
		{
			name: "FTP chain does not give main proxy user to preproxy",
			argv: []string{
				"curl", "--preproxy", "socks5h://pre:safe@first.example",
				"--proxy", "http://main.example", "--proxy-user", "main:" + token,
				"ftp://origin.example/file",
			},
			want:              components("first.example", 1080, "pre", "safe"),
			wantAuthoritative: true,
		},
		{
			name: "FTP chain without preproxy URL credentials has no SOCKS fields",
			argv: []string{
				"curl", "--preproxy", "socks5h://first.example", "--proxy",
				"http://main.example", "--proxy-user", "main:" + token,
				"ftp://origin.example/file",
			},
			wantAuthoritative: true,
		},
		{
			name: "FTP chain GSSAPI only suppresses preproxy basic fields",
			argv: []string{
				"curl", "--preproxy", "socks5h://pre:" + token + "@first.example",
				"--proxy", "http://main.example", "--socks5-gssapi",
				"ftp://origin.example/file",
			},
			wantAuthoritative: true,
		},
		{
			name: "positive GSSAPI NEC option is capability dependent",
			argv: []string{
				"curl", "--socks5", "proxy.example", "--socks5-gssapi-nec",
				"--proxy-user", "proxy:" + token, "https://origin.example",
			},
		},
		{
			name: "negative GSSAPI NEC option is inert",
			argv: []string{
				"curl", "--socks5", "proxy.example", "--no-socks5-gssapi-nec",
				"--proxy-user", "proxy:" + token, "https://origin.example",
			},
			want:              components("proxy.example", 1080, "proxy", token),
			wantAuthoritative: true,
		},
		{
			name: "final disabled GSSAPI NEC option restores credentials",
			argv: []string{
				"curl", "--socks5", "proxy.example", "--socks5-gssapi-nec",
				"--no-socks5-gssapi-nec", "--proxy-user", "proxy:" + token,
				"https://origin.example",
			},
			want:              components("proxy.example", 1080, "proxy", token),
			wantAuthoritative: true,
		},
		{
			name: "final enabled GSSAPI NEC option remains capability dependent",
			argv: []string{
				"curl", "--socks5", "proxy.example", "--no-socks5-gssapi-nec",
				"--socks5-gssapi-nec", "--proxy-user", "proxy:" + token,
				"https://origin.example",
			},
		},
		{
			name: "FTP chain positive GSSAPI NEC option is capability dependent",
			argv: []string{
				"curl", "--preproxy", "socks5h://pre:" + token + "@first.example",
				"--proxy", "http://main.example", "--socks5-gssapi-nec",
				"ftp://origin.example/file",
			},
			wantAuthoritative: true,
		},
		{
			name: "FTP chain disabled GSSAPI NEC option is build independent",
			argv: []string{
				"curl", "--preproxy", "socks5h://pre:" + token + "@first.example",
				"--proxy", "http://main.example", "--no-socks5-gssapi-nec",
				"ftp://origin.example/file",
			},
			want:              components("first.example", 1080, "pre", token),
			wantAuthoritative: true,
		},
		{
			name: "IPv4 only rejects literal IPv6 proxy",
			argv: []string{
				"curl", "--ipv4", "--socks5", "[2001:4860:4860::8888]",
				"--proxy-user", "proxy:" + token, "https://origin.example",
			},
		},
		{
			name: "IPv6 preference permits literal IPv4 proxy",
			argv: []string{
				"curl", "--ipv6", "--socks5-hostname", "127.0.0.1",
				"--proxy-user", "proxy:" + token, "https://origin.example",
			},
			want:              components("127.0.0.1", 1080, "proxy", token),
			wantAuthoritative: true,
		},
		{
			name: "dynamic proxy user is not exact",
			argv: []string{
				"curl", "--socks5", "proxy.example", "--proxy-user",
				"proxy:" + token, "https://origin.example",
			},
			expandIndex: 4,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{Tool: "exec", Argv: test.argv})
			if len(facts.Commands) != 1 {
				t.Fatalf("commands = %#v", facts.Commands)
			}
			if test.expandIndex > 0 {
				facts.Commands[0].Arguments[test.expandIndex].Expands = true
			}
			got := StaticCurlSOCKSProxyCredentialComponents(facts.Commands[0])
			if !slices.Equal(got, test.want) {
				t.Fatalf("components = %#v, want %#v; facts = %#v", got, test.want, facts)
			}
			if test.expandIndex == 0 &&
				facts.Authoritative() != test.wantAuthoritative {
				t.Fatalf(
					"authoritative = %t, want %t; facts = %#v",
					facts.Authoritative(),
					test.wantAuthoritative,
					facts,
				)
			}
		})
	}
}

func TestStaticCurlSOCKSProxyCredentialComponentsRejectsShellSetup(t *testing.T) {
	t.Parallel()

	for _, commandText := range []string{
		"curl --socks5 proxy.example --proxy-user proxy:AKIA7Q2M9X4B6C8D3F5H " +
			"https://origin.example > /missing/out",
		"printf safe | curl --socks5 proxy.example --proxy-user " +
			"proxy:AKIA7Q2M9X4B6C8D3F5H https://origin.example",
	} {
		facts := Analyze(Input{Tool: "exec", Command: commandText})
		seen := false
		for _, command := range facts.Commands {
			if command.Program != "curl" {
				continue
			}
			seen = true
			if StaticCurlSOCKSProxyCredentialComponents(command) != nil {
				t.Fatalf("shell-setup components = %#v; facts = %#v", command, facts)
			}
		}
		if !seen {
			t.Fatalf("no curl command parsed; facts = %#v", facts)
		}
	}
}

func TestStaticCurlSOCKSProxyCredentialComponentsForFactsIsolation(t *testing.T) {
	t.Parallel()

	const token = "AKIA7Q2M9X4B6C8D3F5H"
	for _, test := range []struct {
		name     string
		command  string
		want     bool
		wantSeen bool
	}{
		{name: "env", command: "env curl --socks5-hostname proxy.example --proxy-user proxy:" + token + " https://origin.example", want: true, wantSeen: true},
		{name: "command", command: "command curl --socks5-hostname proxy.example --proxy-user proxy:" + token + " https://origin.example", want: true, wantSeen: true},
		{name: "exec", command: "exec curl --socks5-hostname proxy.example --proxy-user proxy:" + token + " https://origin.example", want: true, wantSeen: true},
		{name: "nested wrappers", command: "env command exec curl --socks5-hostname proxy.example --proxy-user proxy:" + token + " https://origin.example", want: true, wantSeen: true},
		{name: "POSIX null netrc file", command: "curl --netrc-file /dev/null --socks5-hostname proxy.example --proxy-user proxy:" + token + " https://origin.example", want: true, wantSeen: true},
		{name: "active arbitrary netrc file", command: "curl --netrc-file /dev/stdin --socks5-hostname proxy.example --proxy-user proxy:" + token + " https://origin.example", wantSeen: true},
		{name: "sudo is not transparent", command: "sudo -n curl --socks5-hostname proxy.example --proxy-user proxy:" + token + " https://origin.example", wantSeen: true},
		{name: "environment assignment is not transparent", command: "env ALL_PROXY=http://other.example curl --socks5-hostname proxy.example --proxy-user proxy:" + token + " https://origin.example"},
		{name: "parent redirect can fail", command: "env curl --socks5-hostname proxy.example --proxy-user proxy:" + token + " https://origin.example > /missing/out", wantSeen: true},
		{name: "pipeline is not isolated", command: "printf safe | env curl --socks5-hostname proxy.example --proxy-user proxy:" + token + " https://origin.example", wantSeen: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{Tool: "exec", Command: test.command})
			var got []TransmittedRequestComponent
			seen := false
			for _, command := range facts.Commands {
				if command.Program == "curl" {
					seen = true
					got = StaticCurlSOCKSProxyCredentialComponentsForFacts(
						facts,
						command.ID,
					)
				}
			}
			if seen != test.wantSeen {
				t.Fatalf("curl command seen = %t, want %t; facts = %#v", seen, test.wantSeen, facts)
			}
			if test.want {
				if !facts.Authoritative() || len(got) != 2 ||
					got[1].Value != token || got[1].Host != "proxy.example" {
					t.Fatalf("facts = %#v, components = %#v", facts, got)
				}
				return
			}
			if len(got) != 0 {
				t.Fatalf("components = %#v, want none; facts = %#v", got, facts)
			}
		})
	}
}
