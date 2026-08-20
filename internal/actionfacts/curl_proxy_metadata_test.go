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
	"slices"
	"testing"
)

func TestStaticCurlProxyTransmittedMetadata(t *testing.T) {
	t.Parallel()

	const token = "AKIA7Q2M9X4B6C8D3F5H"
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
		name              string
		argv              []string
		expandIndex       int
		want              []TransmittedRequestComponent
		wantAuthoritative bool
	}{
		{
			name: "https proxy credentials", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--proxy-user",
				"proxy:" + token, "https://origin.example",
			},
			want:              components("https", "proxy.example", 443, "proxy:"+token),
			wantAuthoritative: true,
		},
		{
			name: "http proxy default port", argv: []string{
				"curl", "-xhttp://proxy.example", "-Uproxy:" + token,
				"https://origin.example",
			},
			want:              components("http", "proxy.example", 1080, "proxy:"+token),
			wantAuthoritative: true,
		},
		{
			name: "literal proxy header", argv: []string{
				"curl", "--proxy", "https://proxy.example:8443",
				"--proxy-header", "X-Proxy-Key: " + token,
				"https://origin.example",
			},
			want: components(
				"https", "proxy.example", 8443, "X-Proxy-Key: "+token,
			),
			wantAuthoritative: true,
		},
		{
			name: "repeated proxy headers are additive", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--proxy-header",
				"X-First: " + token, "--proxy-header", "X-Second: safe",
				"https://origin.example",
			},
			want: components(
				"https", "proxy.example", 443,
				"X-First: "+token, "X-Second: safe",
			),
			wantAuthoritative: true,
		},
		{
			name: "HTTPS proxy H2 drops Host but keeps Content-Type", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--proxy-header",
				"Host: " + token, "--proxy-header", "Content-Type: " + token,
				"https://origin.example",
			},
			want: components(
				"https", "proxy.example", 443,
				"Content-Type: "+token,
			),
			wantAuthoritative: true,
		},
		{
			name: "proxytunnel sends Host on HTTP origin connect", argv: []string{
				"curl", "-p", "--proxy", "http://proxy.example", "--proxy-header",
				"Host: " + token, "http://origin.example",
			},
			want:              components("http", "proxy.example", 1080, "Host: "+token),
			wantAuthoritative: true,
		},
		{
			name: "parser owned inert flags preserve proxy proof", argv: []string{
				"curl", "-s", "--disable", "--insecure", "--compressed", "--head",
				"--proxy",
				"https://proxy.example", "--proxy-user", "proxy:" + token,
				"https://origin.example",
			},
			want:              components("https", "proxy.example", 443, "proxy:"+token),
			wantAuthoritative: true,
		},
		{
			name: "individual fail flag preserves proxy proof", argv: []string{
				"curl", "--fail", "--proxy", "https://proxy.example",
				"--proxy-user", "proxy:" + token, "https://origin.example",
			},
			want:              components("https", "proxy.example", 443, "proxy:"+token),
			wantAuthoritative: true,
		},
		{
			name: "mutually exclusive fail flags abort before proxy", argv: []string{
				"curl", "--fail", "--fail-with-body", "--proxy",
				"https://proxy.example", "--proxy-user", "proxy:" + token,
				"https://origin.example",
			},
		},
		{
			name: "url option preserves proxy proof", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--proxy-user",
				"proxy:" + token, "--url", "https://origin.example",
			},
			want:              components("https", "proxy.example", 443, "proxy:"+token),
			wantAuthoritative: true,
		},
		{
			name: "option terminator preserves proxy proof", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--proxy-user",
				"proxy:" + token, "--", "https://origin.example",
			},
			want:              components("https", "proxy.example", 443, "proxy:"+token),
			wantAuthoritative: true,
		},
		{
			name: "proxy user percent decoding", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--proxy-user",
				"proxy:%41KIA7Q2M9X4B6C8D3F5H%2F", "https://origin.example",
			},
			want: components(
				"https", "proxy.example", 443, "proxy:"+token+"/",
			),
			wantAuthoritative: true,
		},
		{
			name: "malformed percent remains literal", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--proxy-user",
				"proxy:%zz" + token, "https://origin.example",
			},
			want: components(
				"https", "proxy.example", 443, "proxy:%zz"+token,
			),
			wantAuthoritative: true,
		},
		{
			name: "final proxy user wins", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--proxy-user",
				"proxy:safe", "--proxy-user", "proxy:" + token,
				"https://origin.example",
			},
			want:              components("https", "proxy.example", 443, "proxy:"+token),
			wantAuthoritative: true,
		},
		{
			name: "final safe proxy user drops stale secret", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--proxy-user",
				"proxy:" + token, "--proxy-user", "proxy:safe",
				"https://origin.example",
			},
			want:              components("https", "proxy.example", 443, "proxy:safe"),
			wantAuthoritative: true,
		},
		{
			name: "custom authorization suppresses generated credentials", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--proxy-user",
				"proxy:" + token, "--proxy-header",
				"Proxy-Authorization: Basic safe", "https://origin.example",
			},
			want: components(
				"https", "proxy.example", 443,
				"Proxy-Authorization: Basic safe",
			),
			wantAuthoritative: true,
		},
		{
			name: "empty custom authorization removes generated credentials", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--proxy-user",
				"proxy:" + token, "--proxy-header", "Proxy-Authorization:",
				"https://origin.example",
			},
			wantAuthoritative: true,
		},
		{
			name: "final proxy destination wins", argv: []string{
				"curl", "--proxy", "http://127.0.0.1:8080", "--proxy",
				"https://proxy.example", "--proxy-user", "proxy:" + token,
				"https://origin.example",
			},
			want:              components("https", "proxy.example", 443, "proxy:"+token),
			wantAuthoritative: true,
		},
		{
			name: "final empty noproxy preserves explicit proxy", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--noproxy", "*",
				"--noproxy", "", "--proxy-user", "proxy:" + token,
				"https://origin.example",
			},
			want:              components("https", "proxy.example", 443, "proxy:"+token),
			wantAuthoritative: true,
		},
		{
			name: "local proxy remains exactly bound", argv: []string{
				"curl", "--proxy", "http://127.0.0.1:8080", "--proxy-user",
				"proxy:" + token, "https://origin.example",
			},
			want: components(
				"http", "127.0.0.1", 8080, "proxy:"+token,
			),
			wantAuthoritative: true,
		},
		{
			name: "control credential bytes remain auth input", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--proxy-user",
				"proxy:%09" + token, "--proxy-header", "X-Proxy: safe",
				"https://origin.example",
			},
			want: components(
				"https", "proxy.example", 443,
				"X-Proxy: safe", "proxy:\t"+token,
			),
			wantAuthoritative: true,
		},
		{
			name: "leading semicolon avoids password prompt", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--proxy-user",
				";" + token, "https://origin.example",
			},
			want: components(
				"https", "proxy.example", 443, ";"+token+":",
			),
			wantAuthoritative: true,
		},
		{
			name: "proxy header file is opaque", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--proxy-header",
				"@headers.txt", "--proxy-user", "proxy:" + token,
				"https://origin.example",
			},
		},
		{
			name: "proxy URL userinfo overrides option credentials", argv: []string{
				"curl", "--proxy", "https://url:creds@proxy.example",
				"--proxy-user", "proxy:" + token, "https://origin.example",
			},
			want:              components("https", "proxy.example", 443, "url:creds"),
			wantAuthoritative: true,
		},
		{
			name: "proxy URL credentials are decoded", argv: []string{
				"curl", "--proxy", "https://proxy:%41KIA7Q2M9X4B6C8D3F5H@proxy.example",
				"https://origin.example",
			},
			want:              components("https", "proxy.example", 443, "proxy:"+token),
			wantAuthoritative: true,
		},
		{
			name: "malformed proxy URL escapes remain literal", argv: []string{
				"curl", "--proxy", "https://proxy:%zz" + token + "@proxy.example",
				"https://origin.example",
			},
			want:              components("https", "proxy.example", 443, "proxy:%zz"+token),
			wantAuthoritative: true,
		},
		{
			name: "proxy URL credentials retain DEL bytes", argv: []string{
				"curl", "--proxy", "https://proxy:%7F" + token + "@proxy.example",
				"https://origin.example",
			},
			want:              components("https", "proxy.example", 443, "proxy:\x7f"+token),
			wantAuthoritative: true,
		},
		{
			name: "proxy URL credentials retain raw high bytes", argv: []string{
				"curl", "--proxy", "https://proxy:\u0080" + token + "@proxy.example",
				"https://origin.example",
			},
			want:              components("https", "proxy.example", 443, "proxy:\u0080"+token),
			wantAuthoritative: true,
		},
		{
			name: "proxy URL credentials decode encoded space", argv: []string{
				"curl", "--proxy", "https://proxy:%20" + token + "@proxy.example",
				"https://origin.example",
			},
			want:              components("https", "proxy.example", 443, "proxy: "+token),
			wantAuthoritative: true,
		},
		{
			name: "raw space in proxy URL userinfo aborts before peer", argv: []string{
				"curl", "--proxy", "https://bad space:" + token + "@proxy.example",
				"https://origin.example",
			},
		},
		{
			name: "proxy URL suffix does not change peer metadata", argv: []string{
				"curl", "--proxy", "https://proxy:" + token + "@proxy.example/path?x#f",
				"https://origin.example",
			},
			want:              components("https", "proxy.example", 443, "proxy:"+token),
			wantAuthoritative: true,
		},
		{
			name: "nonascii proxy URL suffix does not change peer", argv: []string{
				"curl", "--proxy", "https://proxy:" + token + "@proxy.example/\u2603",
				"https://origin.example",
			},
			want:              components("https", "proxy.example", 443, "proxy:"+token),
			wantAuthoritative: true,
		},
		{
			name: "raw whitespace in proxy URL suffix aborts before peer", argv: []string{
				"curl", "--proxy", "https://proxy:" + token + "@proxy.example/ bad",
				"https://origin.example",
			},
		},
		{
			name: "proxy URL credentials override safe option", argv: []string{
				"curl", "--proxy", "https://proxy:" + token + "@proxy.example",
				"--proxy-user", "proxy:safe", "https://origin.example",
			},
			want:              components("https", "proxy.example", 443, "proxy:"+token),
			wantAuthoritative: true,
		},
		{
			name: "custom authorization suppresses proxy URL credentials", argv: []string{
				"curl", "--proxy", "https://proxy:" + token + "@proxy.example",
				"--proxy-header", "Proxy-Authorization: Basic safe",
				"https://origin.example",
			},
			want: components(
				"https", "proxy.example", 443,
				"Proxy-Authorization: Basic safe",
			),
			wantAuthoritative: true,
		},
		{
			name: "control in proxy URL userinfo is invalid", argv: []string{
				"curl", "--proxy", "https://proxy:%09" + token + "@proxy.example",
				"https://origin.example",
			},
		},
		{
			name: "NUL in proxy URL userinfo is invalid", argv: []string{
				"curl", "--proxy", "https://proxy:%00" + token + "@proxy.example",
				"https://origin.example",
			},
		},
		{
			name: "control in proxy URL userinfo is invalid", argv: []string{
				"curl", "--proxy", "https://proxy:%0A" + token + "@proxy.example",
				"https://origin.example",
			},
		},
		{
			name: "valid origin userinfo does not change proxy egress", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--proxy-user",
				"proxy:" + token, "https://user:pass@origin.example",
			},
			want:              components("https", "proxy.example", 443, "proxy:"+token),
			wantAuthoritative: true,
		},
		{
			name: "invalid origin userinfo aborts before proxy", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--proxy-user",
				"proxy:" + token, "https://user:%00pass@origin.example",
			},
		},
		{
			name: "scheme relative target is not a curl HTTP URL", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--proxy-user",
				"proxy:" + token, "//origin.example/path",
			},
		},
		{
			name: "schemeless target is protocol ambiguous", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--proxy-user",
				"proxy:" + token, "origin.example/path",
			},
		},
		{
			name: "nonempty noproxy can bypass proxy", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--noproxy",
				"origin.example", "--proxy-user", "proxy:" + token,
				"https://origin.example",
			},
		},
		{
			name: "preproxy changes first peer", argv: []string{
				"curl", "--preproxy", "socks5://first.example", "--proxy",
				"https://proxy.example", "--proxy-user", "proxy:" + token,
				"https://origin.example",
			},
		},
		{
			name: "SOCKS proxy is outside HTTP metadata lane", argv: []string{
				"curl", "--proxy", "socks5://proxy.example", "--proxy-user",
				"proxy:" + token, "https://origin.example",
			},
		},
		{
			name: "FTP proxy scheme is unsupported", argv: []string{
				"curl", "--proxy", "ftp://proxy.example", "--proxy-header",
				"X-Proxy: " + token, "https://origin.example",
			},
		},
		{
			name: "config is opaque", argv: []string{
				"curl", "--config", "curlrc", "--proxy",
				"https://proxy.example", "--proxy-user", "proxy:" + token,
				"https://origin.example",
			},
		},
		{
			name: "same group targets share proxy metadata", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--proxy-user",
				"proxy:" + token, "https://one.example", "https://two.example",
			},
			want:              components("https", "proxy.example", 443, "proxy:"+token),
			wantAuthoritative: true,
		},
		{
			name: "proxy1.0 uses HTTP proxy metadata lane", argv: []string{
				"curl", "--proxy1.0", "http://proxy.example", "--proxy-user",
				"proxy:" + token, "https://origin.example",
			},
			want:              components("http", "proxy.example", 1080, "proxy:"+token),
			wantAuthoritative: true,
		},
		{
			name: "later HTTP proxy supersedes stale SOCKS setter", argv: []string{
				"curl", "--socks5", "127.0.0.1:1", "--proxy",
				"https://proxy.example", "--proxy-user", "proxy:" + token,
				"https://origin.example",
			},
			want:              components("https", "proxy.example", 443, "proxy:"+token),
			wantAuthoritative: true,
		},
		{
			name: "HTTPS URL overrides SOCKS alias type", argv: []string{
				"curl", "--socks5", "https://proxy.example", "--proxy-user",
				"proxy:" + token, "https://origin.example",
			},
			want:              components("https", "proxy.example", 443, "proxy:"+token),
			wantAuthoritative: true,
		},
		{
			name: "later SOCKS setter supersedes HTTP proxy", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--socks5",
				"http://proxy.example", "--proxy-user", "proxy:" + token,
				"https://origin.example",
			},
		},
		{
			name: "multiple groups are ambiguous", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--proxy-user",
				"proxy:" + token, "https://one.example", "--next",
				"https://two.example",
			},
		},
		{
			name: "NUL proxy credentials abort before request", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--proxy-user",
				"proxy:%00" + token, "https://origin.example",
			},
		},
		{
			name: "no-colon proxy user can prompt", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--proxy-user",
				token, "https://origin.example",
			},
		},
		{
			name: "dynamic proxy user is not literal", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--proxy-user",
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
			got := StaticCurlProxyTransmittedMetadata(facts.Commands[0])
			if !slices.Equal(got.ProxyRequestComponents, test.want) {
				t.Fatalf("metadata = %#v, want %#v; facts = %#v", got, test.want, facts)
			}
			if test.expandIndex == 0 && facts.Authoritative() != test.wantAuthoritative {
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
