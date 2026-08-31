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

func TestParseCurlArgvOwnsFTPControlOptionValues(t *testing.T) {
	t.Parallel()

	parsed := parseCurlArgv([]string{
		"curl", "--ftp-account", "--help",
		"--ftp-alternative-to-user", "SITE fixture", "ftp://sink.example/",
	})
	if !parsed.Complete || parsed.Preview || len(parsed.Targets) != 1 ||
		parsed.Targets[0].Value != "ftp://sink.example/" {
		t.Fatalf("parse = %#v", parsed)
	}
	want := map[string]string{
		"--ftp-account":             "--help",
		"--ftp-alternative-to-user": "SITE fixture",
	}
	for _, option := range parsed.Options {
		value, ok := want[option.Canonical]
		if !ok {
			continue
		}
		if !option.Known || !option.TakesValue || !option.ValuePresent ||
			option.Value != value {
			t.Fatalf("%s option = %#v, want value %q", option.Canonical, option, value)
		}
		delete(want, option.Canonical)
	}
	if len(want) != 0 {
		t.Fatalf("missing options: %#v", want)
	}
	for _, argv := range [][]string{
		{"curl", "--ftp-account", "", "ftp://sink.example/"},
		{"curl", "--ftp-alternative-to-user", "", "ftp://sink.example/"},
	} {
		if parsed := parseCurlArgv(argv); !parsed.Complete || parsed.hasValidOptionValues() {
			t.Fatalf("empty FTP control value parse = %#v", parsed)
		}
	}
	for _, argv := range [][]string{
		{"curl", "--ftp-account=fixture", "ftp://sink.example/"},
		{"curl", "--ftp-alternative-to-user=SITE fixture", "ftp://sink.example/"},
	} {
		if parsed := parseCurlArgv(argv); parsed.Complete {
			t.Fatalf("joined FTP control value unexpectedly complete: %#v", parsed)
		}
	}
}

func TestStaticCurlFTPControlRequestComponents(t *testing.T) {
	t.Parallel()

	const token = "test-ftp-control-metadata"
	components := func(
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
		name        string
		argv        []string
		expandIndex int
		mixedIndex  int
		posix       bool
		want        []TransmittedRequestComponent
	}{
		{
			name: "reported account after explicit user",
			argv: []string{
				"curl", "--user", "user:pass", "--ftp-account", token,
				"ftp://sink.example/",
			},
			want: components("ftp", "sink.example", 0, token),
		},
		{
			name: "default anonymous authentication can receive account challenge",
			argv: []string{"curl", "--ftp-account", token, "ftp://sink.example/"},
			want: components("ftp", "sink.example", 0, token),
		},
		{
			name: "joined account syntax aborts before network",
			argv: []string{"curl", "--ftp-account=" + token, "ftp://sink.example/"},
		},
		{
			name: "joined alternative syntax aborts before network",
			argv: []string{
				"curl", "--ftp-alternative-to-user=SITE " + token,
				"ftp://sink.example/",
			},
		},
		{
			name: "FTPS URL credentials and explicit port",
			argv: []string{
				"curl", "--ftp-account", token,
				"ftps://user:pass@sink.example:990/",
			},
			want: components("ftps", "sink.example", 990, token),
		},
		{
			name: "final account wins",
			argv: []string{
				"curl", "--ftp-account", "fixture", "--ftp-account", token,
				"ftp://sink.example/",
			},
			want: components("ftp", "sink.example", 0, token),
		},
		{
			name: "earlier account is replaced",
			argv: []string{
				"curl", "--ftp-account", token, "--ftp-account", "fixture",
				"ftp://sink.example/",
			},
			want: components("ftp", "sink.example", 0, "fixture"),
		},
		{
			name: "alternative login command remains exact",
			argv: []string{
				"curl", "--ftp-alternative-to-user", "SITE " + token,
				"ftp://sink.example/",
			},
			want: components("ftp", "sink.example", 0, "SITE "+token),
		},
		{
			name: "both conditional control paths remain distinct",
			argv: []string{
				"curl", "--ftp-account", token,
				"--ftp-alternative-to-user", "SITE fixture",
				"ftp://sink.example/",
			},
			want: components("ftp", "sink.example", 0, token, "SITE fixture"),
		},
		{
			name: "multiple FTP targets receive the effective account",
			argv: []string{
				"curl", "--ftp-account", token,
				"ftp://one.example:2121/", "ftps://127.0.0.1:990/",
			},
			want: append(
				components("ftp", "one.example", 2121, token),
				components("ftps", "127.0.0.1", 990, token)...,
			),
		},
		{
			name: "HTTP sibling does not receive FTP control bytes",
			argv: []string{
				"curl", "--ftp-account", token,
				"https://one.example/", "ftp://two.example/",
			},
			want: components("ftp", "two.example", 0, token),
		},
		{
			name: "local target remains target bound",
			argv: []string{"curl", "--ftp-account", token, "ftp://127.0.0.1/"},
			want: components("ftp", "127.0.0.1", 0, token),
		},
		{
			name: "HTTP target ignores account",
			argv: []string{"curl", "--ftp-account", token, "https://sink.example/"},
		},
		{
			name: "forward HTTP proxy converts FTP request",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--ftp-account", token,
				"ftp://sink.example/",
			},
		},
		{
			name: "scheme relative proxy aborts FTPS before login",
			argv: []string{
				"curl", "--proxy", "//proxy.example:1080", "--ftp-account", token,
				"ftps://sink.example/",
			},
		},
		{
			name: "scheme relative tunnel proxy aborts FTP before login",
			argv: []string{
				"curl", "--proxy", "//proxy.example:1080", "--proxytunnel",
				"--ftp-account", token, "ftp://sink.example/",
			},
		},
		{
			name: "wildcard IPv4 interface preserves literal IPv4 reachability",
			argv: []string{
				"curl", "--interface", "0.0.0.0", "--ftp-account", token,
				"ftp://8.8.8.8/",
			},
			want: components("ftp", "8.8.8.8", 0, token),
		},
		{
			name: "wildcard IPv4 interface cannot prove hostname family",
			argv: []string{
				"curl", "--interface", "0.0.0.0", "--ftp-account", token,
				"ftp://sink.example/",
			},
		},
		{
			name: "wildcard IPv4 interface rejects literal IPv6 target",
			argv: []string{
				"curl", "--interface", "0.0.0.0", "--ftp-account", token,
				"ftp://[2606:4700:4700::1111]/",
			},
		},
		{
			name: "ambient interface name remains uncertain",
			argv: []string{
				"curl", "--interface", "missing-interface", "--ftp-account", token,
				"ftp://sink.example/",
			},
		},
		{
			name: "proxy tunnel preserves FTP origin protocol",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "-p",
				"--ftp-account", token, "ftp://sink.example/",
			},
			want: components("ftp", "sink.example", 0, token),
		},
		{
			name: "IPv4 only rejects literal IPv6 origin",
			argv: []string{
				"curl", "--ipv4", "--ftp-account", token,
				"ftp://[2606:4700:4700::1111]/",
			},
		},
		{
			name: "IPv4 only rejects literal IPv6 proxy",
			argv: []string{
				"curl", "--ipv4", "--proxy", "socks5h://[2001:4860:4860::8888]",
				"--ftp-account", token, "ftp://sink.example/",
			},
		},
		{
			name: "config indirection closes control proof",
			argv: []string{
				"curl", "--config", "curlrc", "--ftp-account", token,
				"ftp://sink.example/",
			},
		},
		{
			name: "next preserves prior group account binding",
			argv: []string{
				"curl", "--ftp-account", token, "ftp://one.example/", "--next",
				"ftp://two.example/",
			},
			want: components("ftp", "one.example", 0, token),
		},
		{
			name: "later malformed form type aborts before prior login",
			argv: []string{
				"curl", "--ftp-account", token, "ftp://one.example/", "--next",
				"--form", "x=@/dev/null;type=bogus", "https://two.example/",
			},
			posix: true,
		},
		{
			name:        "dynamic effective account is not static",
			argv:        []string{"curl", "--ftp-account", token, "ftp://sink.example/"},
			expandIndex: 2,
		},
		{
			name: "mixed-quote effective alternative is not static",
			argv: []string{
				"curl", "--ftp-alternative-to-user", "SITE " + token,
				"ftp://sink.example/",
			},
			mixedIndex: 2,
		},
		{
			name:        "dynamic target closes exact binding",
			argv:        []string{"curl", "--ftp-account", token, "ftp://sink.example/"},
			expandIndex: 3,
		},
		{
			name: "blank final account aborts before network",
			argv: []string{
				"curl", "--ftp-account", token, "--ftp-account", "",
				"ftp://sink.example/",
			},
		},
		{
			name: "arbitrary upload file can fail before login",
			argv: []string{
				"curl", "--ftp-account", token, "--upload-file", "/missing/payload",
				"ftp://sink.example/file",
			},
		},
		{
			name: "null upload source is available before login",
			argv: []string{
				"curl", "--ftp-account", token, "--upload-file", "/dev/null",
				"ftp://sink.example/file",
			},
			posix: true,
			want:  components("ftp", "sink.example", 0, token),
		},
		{
			name: "empty upload source clears upload mode",
			argv: []string{
				"curl", "--ftp-account", token, "--upload-file", "",
				"ftp://sink.example/file",
			},
			want: components("ftp", "sink.example", 0, token),
		},
		{
			name: "POSIX null config is inert",
			argv: []string{
				"curl", "--config", "/dev/null", "--ftp-account", token,
				"ftp://sink.example/",
			},
			posix: true,
			want:  components("ftp", "sink.example", 0, token),
		},
		{
			name: "argv dialect cannot assume POSIX null config",
			argv: []string{
				"curl", "--config", "/dev/null", "--ftp-account", token,
				"ftp://sink.example/",
			},
		},
		{
			name: "POSIX null URL query source is finite",
			argv: []string{
				"curl", "--url-query", "name@/dev/null", "--ftp-account", token,
				"ftp://sink.example/",
			},
			posix: true,
			want:  components("ftp", "sink.example", 0, token),
		},
		{
			name: "GET inline data remains login reachable",
			argv: []string{
				"curl", "--get", "--data", "safe", "--ftp-account", token,
				"ftp://sink.example/",
			},
			want: components("ftp", "sink.example", 0, token),
		},
		{
			name: "numeric download resume is post login",
			argv: []string{
				"curl", "--continue-at", "1", "--ftp-account", token,
				"ftp://sink.example/file",
			},
			want: components("ftp", "sink.example", 0, token),
		},
		{
			name: "numeric resume file output opens before login",
			argv: []string{
				"curl", "--continue-at", "1", "--output", "/missing/out",
				"--ftp-account", token, "ftp://sink.example/file",
			},
		},
		{
			name: "automatic resume remains outside the exact lane",
			argv: []string{
				"curl", "--continue-at", "-", "--ftp-account", token,
				"ftp://sink.example/file",
			},
		},
		{
			name: "numeric resume with active upload remains outside the exact lane",
			argv: []string{
				"curl", "--continue-at", "1", "--upload-file", "/dev/null",
				"--ftp-account", token, "ftp://sink.example/file",
			},
			posix: true,
		},
		{
			name: "final no get restores invalid raw query failure",
			argv: []string{
				"curl", "--get", "--no-get", "--data", "safe",
				"--url-query", "+a b", "--ftp-account", token,
				"ftp://sink.example/",
			},
		},
		{
			name: "POSIX null netrc file is finite",
			argv: []string{
				"curl", "--netrc-file", "/dev/null", "--ftp-account", token,
				"ftp://sink.example/",
			},
			posix: true,
			want:  components("ftp", "sink.example", 0, token),
		},
		{
			name: "ambient netrc remains uncertain",
			argv: []string{
				"curl", "--netrc", "--ftp-account", token,
				"ftp://sink.example/",
			},
		},
		{
			name: "explicit user makes ambient netrc inert",
			argv: []string{
				"curl", "--netrc", "--user", "user:pass",
				"--ftp-account", token, "ftp://sink.example/",
			},
			want: components("ftp", "sink.example", 0, token),
		},
		{
			name: "bearer suppresses origin password prompt",
			argv: []string{
				"curl", "--user", "rawuser", "--oauth2-bearer", "fixture",
				"--ftp-account", token, "ftp://sink.example/",
			},
			want: components("ftp", "sink.example", 0, token),
		},
		{
			name: "header file can fail during CLI parsing",
			argv: []string{
				"curl", "--ftp-account", token, "--header", "@/missing/headers",
				"ftp://sink.example/",
			},
		},
		{
			name: "proxy header file can fail during CLI parsing",
			argv: []string{
				"curl", "--ftp-account", token, "--proxy-header", "@/missing/headers",
				"ftp://sink.example/",
			},
		},
		{
			name: "write out file can fail during CLI parsing",
			argv: []string{
				"curl", "--ftp-account", token, "--write-out", "@/missing/format",
				"ftp://sink.example/",
			},
		},
		{
			name: "data file can fail during CLI parsing",
			argv: []string{
				"curl", "--ftp-account", token, "--data", "@/missing/data",
				"ftp://sink.example/",
			},
		},
		{
			name: "dump header output can fail before network",
			argv: []string{
				"curl", "--ftp-account", token, "--dump-header", "/missing/out",
				"ftp://sink.example/",
			},
		},
		{
			name: "FTPS certificate source can fail before USER",
			argv: []string{
				"curl", "--ftp-account", token, "--cert", "/missing/cert",
				"ftps://sink.example/",
			},
		},
		{
			name: "final empty certificate clears stale FTPS source",
			argv: []string{
				"curl", "--ftp-account", token, "--cert", "/missing/cert",
				"--cert", "", "ftps://sink.example/",
			},
			want: components("ftps", "sink.example", 0, token),
		},
		{
			name: "FTPS CA source can fail before USER",
			argv: []string{
				"curl", "--ftp-account", token, "--cacert", "/missing/ca",
				"ftps://sink.example/",
			},
		},
		{
			name: "insecure makes FTPS CA source inert",
			argv: []string{
				"curl", "--ftp-account", token, "--cacert", "/missing/ca",
				"--insecure", "ftps://sink.example/",
			},
			want: components("ftps", "sink.example", 0, token),
		},
		{
			name: "final no insecure reenables FTPS CA validation",
			argv: []string{
				"curl", "--ftp-account", token, "--cacert", "/missing/ca",
				"--insecure", "--no-insecure", "ftps://sink.example/",
			},
		},
		{
			name: "key alone is inert without an FTPS certificate",
			argv: []string{
				"curl", "--ftp-account", token, "--key", "/missing/key",
				"ftps://sink.example/",
			},
			want: components("ftps", "sink.example", 0, token),
		},
		{
			name: "plain FTP ignores TLS file options",
			argv: []string{
				"curl", "--ftp-account", token, "--cacert", "/missing/ca",
				"--cert", "/missing/cert", "--key", "/missing/key",
				"ftp://sink.example/",
			},
			want: components("ftp", "sink.example", 0, token),
		},
		{
			name: "remote name with derived filename reaches login",
			argv: []string{
				"curl", "--remote-name", "--ftp-account", token,
				"ftp://sink.example/file",
			},
			want: components("ftp", "sink.example", 0, token),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{Tool: "exec", Argv: test.argv})
			if len(facts.Commands) != 1 {
				t.Fatalf("commands = %#v", facts.Commands)
			}
			if test.posix {
				facts.Commands[0].Dialect = DialectPOSIX
			}
			if test.expandIndex > 0 {
				facts.Commands[0].Arguments[test.expandIndex].Expands = true
			}
			if test.mixedIndex > 0 {
				facts.Commands[0].Arguments[test.mixedIndex].Quote = QuoteMixed
			}
			got := StaticCurlFTPControlRequestComponents(facts.Commands[0])
			if !slices.Equal(got, test.want) {
				t.Fatalf("FTP request components = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestStaticCurlFTPControlRequestComponentsTransparentWrappers(t *testing.T) {
	t.Parallel()

	const token = "test-ftp-wrapper-control"
	for _, test := range []struct {
		name    string
		command string
		want    bool
	}{
		{name: "env", command: "env curl --ftp-account " + token + " ftp://sink.example/", want: true},
		{name: "command", command: "command curl --ftp-account " + token + " ftp://sink.example/", want: true},
		{name: "exec", command: "exec curl --ftp-account " + token + " ftp://sink.example/", want: true},
		{name: "nested transparent wrappers", command: "env command exec curl --ftp-account " + token + " ftp://sink.example/", want: true},
		{name: "sudo is not transparent", command: "sudo -n curl --ftp-account " + token + " ftp://sink.example/"},
		{name: "uppercase env is not a POSIX transparent wrapper", command: "ENV curl --ftp-account " + token + " ftp://sink.example/"},
		{name: "uppercase system env path is not transparent", command: "/usr/bin/ENV curl --ftp-account " + token + " ftp://sink.example/"},
		{name: "shell wrapper is not transparent", command: "sh -c 'curl --ftp-account " + token + " ftp://sink.example/'"},
		{name: "environment assignment wrapper is uncertain", command: "env FTP_PROXY=http://proxy.example curl --ftp-account " + token + " ftp://sink.example/"},
		{name: "parent redirect can fail before transparent wrapper", command: "env curl --ftp-account " + token + " ftp://sink.example/ > /missing/dir/out"},
		{name: "pipeline wrapper is not isolated", command: "printf safe | env curl --ftp-account " + token + " ftp://sink.example/"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{Tool: "exec", Command: test.command})
			var got []TransmittedRequestComponent
			for _, command := range facts.Commands {
				if command.Program == "curl" {
					got = StaticCurlFTPControlRequestComponentsForFacts(
						facts,
						command.ID,
					)
				}
			}
			if test.want {
				if !facts.Authoritative() || len(got) != 1 ||
					got[0].Value != token || got[0].Host != "sink.example" {
					t.Fatalf("facts = %#v, components = %#v", facts, got)
				}
				return
			}
			if len(got) != 0 {
				t.Fatalf("components = %#v, want none", got)
			}
		})
	}
}

func TestClassifyCurlFTPInterfaceAuthority(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		interface_ string
		target     string
		want       ParseStatus
	}{
		{name: "portable wildcard bind", interface_: "0.0.0.0", target: "ftp://8.8.8.8/", want: StatusComplete},
		{name: "wildcard bind with hostname", interface_: "0.0.0.0", target: "ftp://sink.example/", want: StatusPartial},
		{name: "wildcard bind with IPv6", interface_: "0.0.0.0", target: "ftp://[2606:4700:4700::1111]/", want: StatusPartial},
		{name: "ambient interface", interface_: "missing-interface", target: "ftp://8.8.8.8/", want: StatusPartial},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{Tool: "exec", Argv: []string{
				"curl", "--interface", test.interface_, "--ftp-account", "fixture",
				test.target,
			}})
			if facts.Parse.Status != test.want {
				t.Fatalf("status = %s, want %s", facts.Parse.Status, test.want)
			}
		})
	}
}

func TestClassifyCurlFTPUpgradeTLSSupportFileAuthority(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		argv []string
		want ParseStatus
	}{
		{
			name: "required FTP TLS CA support file",
			argv: []string{
				"curl", "--ssl-reqd", "--cacert", "/home/alice/.ssh/id_ed25519",
				"--upload-file", "/dev/null", "ftp://sink.example/file",
			},
			want: StatusPartial,
		},
		{
			name: "insecure makes FTP TLS CA support file inert",
			argv: []string{
				"curl", "--ssl-reqd", "--cacert", "/home/alice/.ssh/id_ed25519",
				"--insecure", "--upload-file", "/dev/null",
				"ftp://sink.example/file",
			},
			want: StatusComplete,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{Tool: "exec", Argv: test.argv})
			if facts.Parse.Status != test.want {
				t.Fatalf("status = %s, want %s", facts.Parse.Status, test.want)
			}
		})
	}
}

func TestStaticCurlFTPControlRequestComponentsRejectSyntheticNUL(t *testing.T) {
	t.Parallel()

	facts := Analyze(Input{Tool: "exec", Argv: []string{
		"curl", "--ftp-account", "fixture", "ftp://sink.example/",
	}})
	if len(facts.Commands) != 1 {
		t.Fatalf("commands = %#v", facts.Commands)
	}
	facts.Commands[0].Argv[2] = "fixture\x00tail"
	facts.Commands[0].Arguments[2].Value = "fixture\x00tail"
	if got := StaticCurlFTPControlRequestComponents(
		facts.Commands[0],
	); len(got) != 0 {
		t.Fatalf("FTP request components = %#v, want none", got)
	}
}

func TestStaticCurlFTPControlRequestComponentLengthBounds(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		option    string
		maxLength int
	}{
		{name: "account", option: "--ftp-account", maxLength: 65_528},
		{
			name:   "alternative",
			option: "--ftp-alternative-to-user", maxLength: 65_533,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			for _, length := range []int{test.maxLength, test.maxLength + 1} {
				value := strings.Repeat("x", length)
				facts := Analyze(Input{Tool: "exec", Argv: []string{
					"curl", test.option, "fixture", "ftp://sink.example/",
				}})
				if len(facts.Commands) != 1 {
					t.Fatalf("length %d commands = %d, want one", length, len(facts.Commands))
				}
				facts.Commands[0].Argv[2] = value
				facts.Commands[0].Arguments[2].Value = value
				got := StaticCurlFTPControlRequestComponents(facts.Commands[0])
				if length == test.maxLength {
					if len(got) != 1 || got[0].Value != value ||
						got[0].Scheme != "ftp" || got[0].Host != "sink.example" {
						t.Fatalf("length %d component count = %d, want exact component", length, len(got))
					}
					continue
				}
				if len(got) != 0 {
					t.Fatalf("length %d component count = %d, want none", length, len(got))
				}
			}
		})
	}
}

func TestStaticCurlFTPProxyControlRequestComponents(t *testing.T) {
	t.Parallel()

	const token = "test-ftp-proxy-control"
	component := func(scheme string, host string, port int64) TransmittedRequestComponent {
		return TransmittedRequestComponent{
			Value: token, Scheme: scheme, Host: host, Port: port,
		}
	}
	for _, test := range []struct {
		name string
		argv []string
		want []TransmittedRequestComponent
	}{
		{
			name: "SOCKS observes clear FTP control bytes",
			argv: []string{
				"curl", "--proxy", "socks5h://proxy.example",
				"--ftp-account", token, "ftp://127.0.0.1/",
			},
			want: []TransmittedRequestComponent{component("tcp", "proxy.example", 1080)},
		},
		{
			name: "HTTP CONNECT observes clear FTP control bytes",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--proxytunnel",
				"--ftp-account", token, "ftp://127.0.0.1/",
			},
			want: []TransmittedRequestComponent{component("http", "proxy.example", 1080)},
		},
		{
			name: "FTPS encrypts control bytes from proxy",
			argv: []string{
				"curl", "--proxy", "socks5h://proxy.example",
				"--ftp-account", token, "ftps://127.0.0.1/",
			},
		},
		{
			name: "matching noproxy bypass suppresses observer",
			argv: []string{
				"curl", "--proxy", "socks5h://proxy.example",
				"--noproxy", "127.0.0.1", "--ftp-account", token,
				"ftp://127.0.0.1/",
			},
		},
		{
			name: "nonmatching noproxy retains observer",
			argv: []string{
				"curl", "--proxy", "socks5h://proxy.example",
				"--noproxy", "never.example", "--ftp-account", token,
				"ftp://127.0.0.1/",
			},
			want: []TransmittedRequestComponent{component("tcp", "proxy.example", 1080)},
		},
		{
			name: "standalone preproxy is the observer",
			argv: []string{
				"curl", "--preproxy", "socks5h://preproxy.example",
				"--ftp-account", token, "ftp://127.0.0.1/",
			},
			want: []TransmittedRequestComponent{component("tcp", "preproxy.example", 1080)},
		},
		{
			name: "SOCKS preproxy and HTTP main proxy both observe CONNECT payload",
			argv: []string{
				"curl", "--preproxy", "socks5h://preproxy.example",
				"--proxy", "http://proxy.example", "--proxytunnel",
				"--ftp-account", token, "ftp://127.0.0.1/",
			},
			want: []TransmittedRequestComponent{
				component("tcp", "preproxy.example", 1080),
				component("http", "proxy.example", 1080),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{Tool: "exec", Argv: test.argv})
			if len(facts.Commands) != 1 {
				t.Fatalf("commands = %#v", facts.Commands)
			}
			got := StaticCurlProxyTransmittedMetadata(
				facts.Commands[0],
			).ProxyRequestComponents
			if !slices.Equal(got, test.want) {
				t.Fatalf("proxy components = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestCurlNoProxyIPv4CIDRPortableGrammar(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		value     string
		host      string
		wantMatch bool
		wantValid bool
	}{
		{name: "slash zero is exact", value: "127.0.0.1/0", host: "127.0.0.1", wantMatch: true, wantValid: true},
		{name: "ordinary prefix", value: "127.0.0.0/8", host: "127.0.0.1", wantMatch: true, wantValid: true},
		{name: "negative is nonportable", value: "127.0.0.1/-1", host: "127.0.0.1"},
		{name: "trailing junk is nonportable", value: "127.0.0.1/24junk", host: "127.0.0.1"},
		{name: "atoi overflow is nonportable", value: "127.0.0.1/4294967296", host: "127.0.0.1"},
		{name: "IPv6 CIDR stays outside the exact lane", value: "::1/128", host: "::1"},
		{name: "one trailing host dot is stripped", value: "example.com", host: "example.com.", wantMatch: true, wantValid: true},
		{name: "multiple trailing host dots are preserved", value: "example.com", host: "example.com..", wantValid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			match, valid := curlNoProxyMatches(test.value, test.host)
			if match != test.wantMatch || valid != test.wantValid {
				t.Fatalf("match, valid = %v, %v, want %v, %v", match, valid, test.wantMatch, test.wantValid)
			}
		})
	}
}
