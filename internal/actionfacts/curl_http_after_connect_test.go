// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"testing"
)

func TestStaticCurlHTTPAfterCONNECTRequestComponents(t *testing.T) {
	t.Parallel()

	const token = "AKIA7Q2M9X4B6C8D3F5H"
	for _, test := range []struct {
		name              string
		argv              []string
		caps              []CurlCapability
		want              []string
		wantScheme        string
		wantHost          string
		wantPort          int64
		wantAuthoritative bool
	}{
		{
			name: "HTTP proxy observes tunneled HTTP path and query",
			argv: []string{
				"curl", "--proxytunnel", "--proxy", "http://proxy.example",
				"http://127.0.0.1/secrets/" + token + "?q=" + token,
			},
			want:              []string{"/secrets/" + token, "q=" + token},
			wantScheme:        "http",
			wantHost:          "proxy.example",
			wantPort:          1080,
			wantAuthoritative: true,
		},
		{
			name: "HTTPS proxy after-CONNECT stays closed without capability",
			argv: []string{
				"curl", "-p", "--proxy", "https://proxy.example",
				"--header", "X-Key: " + token, "http://127.0.0.1/upload",
			},
			wantAuthoritative: true,
		},
		{
			name: "attested HTTPS proxy observes tunneled HTTP header",
			argv: []string{
				"curl", "-p", "--proxy", "https://proxy.example",
				"--header", "X-Key: " + token, "http://127.0.0.1/upload",
			},
			caps:              []CurlCapability{testCurlHTTPSProxyCapability()},
			want:              []string{"X-Key: " + token, "/upload"},
			wantScheme:        "https",
			wantHost:          "proxy.example",
			wantPort:          443,
			wantAuthoritative: true,
		},
		{
			name: "two-hop proxytunnel HTTP origin rebinds onto main proxy",
			argv: []string{
				"curl", "--proxytunnel",
				"--preproxy", "socks5h://127.0.0.1",
				"--proxy", "http://proxy.example",
				"--header", "X-Key: " + token,
				"--oauth2-bearer", token,
				"http://origin.example/secrets/" + token + "?q=" + token,
			},
			want: []string{
				"/secrets/" + token, "q=" + token,
				"X-Key: " + token, token,
			},
			wantScheme:        "http",
			wantHost:          "proxy.example",
			wantPort:          1080,
			wantAuthoritative: true,
		},
		{
			name: "two-hop noproxy bypasses after-CONNECT observer",
			argv: []string{
				"curl", "--proxytunnel",
				"--preproxy", "socks5h://127.0.0.1",
				"--proxy", "http://proxy.example",
				"--noproxy", "origin.example",
				"--header", "X-Key: " + token,
				"--oauth2-bearer", token,
				"http://origin.example/secrets/" + token + "?q=" + token,
			},
		},
		{
			name: "tunneled origin user reaches HTTP proxy",
			argv: []string{
				"curl", "--proxytunnel", "--proxy", "http://proxy.example",
				"--user", "agent:" + token, "http://127.0.0.1/safe",
			},
			want:              []string{"agent:" + token, "/safe"},
			wantScheme:        "http",
			wantHost:          "proxy.example",
			wantPort:          1080,
			wantAuthoritative: true,
		},
		{
			name: "tunneled bearer reaches HTTP proxy",
			argv: []string{
				"curl", "--proxytunnel", "--proxy", "http://proxy.example",
				"--oauth2-bearer", token, "http://127.0.0.1/safe",
			},
			want:              []string{token, "/safe"},
			wantScheme:        "http",
			wantHost:          "proxy.example",
			wantPort:          1080,
			wantAuthoritative: true,
		},
		{
			name: "custom Host remains visible after CONNECT",
			argv: []string{
				"curl", "--proxytunnel", "--proxy", "http://proxy.example",
				"--header", "Host: " + token + ".example",
				"http://127.0.0.1/safe",
			},
			want:              []string{"Host: " + token + ".example", "/safe"},
			wantScheme:        "http",
			wantHost:          "proxy.example",
			wantPort:          1080,
			wantAuthoritative: true,
		},
		{
			name: "separate proxy-header does not hide ordinary tunneled header",
			argv: []string{
				"curl", "--proxytunnel", "--proxy", "http://proxy.example",
				"--proxy-header", "X-Proxy: safe", "--header",
				"X-Key: " + token, "http://127.0.0.1/upload",
			},
			want:              []string{"X-Key: " + token, "/upload"},
			wantScheme:        "http",
			wantHost:          "proxy.example",
			wantPort:          1080,
			wantAuthoritative: true,
		},
		{
			name: "HTTPS origin request stays inside TLS after CONNECT",
			argv: []string{
				"curl", "--proxytunnel", "--proxy", "http://proxy.example",
				"--header", "X-Key: " + token, "https://127.0.0.1/secrets",
			},
			wantAuthoritative: true,
		},
		{
			name: "matching noproxy bypasses after-CONNECT observer",
			argv: []string{
				"curl", "--proxytunnel", "--proxy", "http://proxy.example",
				"--noproxy", "127.0.0.1", "--header", "X-Key: " + token,
				"http://127.0.0.1/upload",
			},
		},
		{
			name: "mixed later transfer group closes after-CONNECT observer",
			argv: []string{
				"curl", "--proxytunnel", "--proxy", "http://proxy.example",
				"--header", "X-Key: " + token, "http://127.0.0.1/upload",
				"--next", "https://two.example/",
			},
		},
		{
			name: "header file is a pre-connect failure",
			argv: []string{
				"curl", "--proxytunnel", "--proxy", "http://proxy.example",
				"--header", "@/missing", "--user", "agent:" + token,
				"http://127.0.0.1/safe",
			},
		},
		{
			name: "config remains opaque",
			argv: []string{
				"curl", "--config", "curlrc", "--proxytunnel",
				"--proxy", "http://proxy.example", "--header",
				"X-Key: " + token, "http://127.0.0.1/upload",
			},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{
				Tool:             "exec",
				Argv:             test.argv,
				CurlCapabilities: test.caps,
			})
			if facts.Authoritative() != test.wantAuthoritative {
				t.Fatalf("Authoritative() = %t, want %t status=%s issues=%v",
					facts.Authoritative(), test.wantAuthoritative,
					facts.Parse.Status, facts.Parse.Issues)
			}
			if len(facts.Commands) != 1 {
				t.Fatalf("commands = %#v", facts.Commands)
			}
			got := staticCurlHTTPAfterCONNECTRequestComponents(facts.Commands[0])
			if len(test.want) == 0 {
				if len(got) != 0 {
					t.Fatalf("after-CONNECT components = %#v, want none", got)
				}
				return
			}
			seen := map[string]bool{}
			for _, component := range got {
				if component.Scheme != test.wantScheme ||
					component.Host != test.wantHost ||
					component.Port != test.wantPort {
					t.Fatalf("component = %#v, want %s %s:%d",
						component, test.wantScheme, test.wantHost, test.wantPort)
				}
				seen[component.Value] = true
			}
			for _, value := range test.want {
				if !seen[value] {
					t.Fatalf("missing %q in %#v", value, got)
				}
			}
		})
	}
}
