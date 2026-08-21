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
	"strings"
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
			name: "credentials remain exact with literal body", argv: []string{
				"curl", "--proxy", "http://proxy.example", "--proxy-user",
				"proxy:" + token, "--data", "safe", "http://origin.example",
			},
			want:              components("http", "proxy.example", 1080, "proxy:"+token),
			wantAuthoritative: true,
		},
		{
			name: "credentials remain exact with output and timeout", argv: []string{
				"curl", "--proxy", "http://proxy.example", "--proxy-user",
				"proxy:" + token, "--data", "safe", "--output", "/tmp/response",
				"--max-time", "5", "http://origin.example",
			},
			want:              components("http", "proxy.example", 1080, "proxy:"+token),
			wantAuthoritative: true,
		},
		{
			name: "exact zero expect timeout preserves proxy projection", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--proxy-user",
				"proxy:" + token, "--expect100-timeout", "0e-4000",
				"https://origin.example",
			},
			want: components("https", "proxy.example", 443, "proxy:"+token),
		},
		{
			name: "normal expect timeout preserves proxy projection", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--proxy-user",
				"proxy:" + token, "--expect100-timeout", "1e-307",
				"https://origin.example",
			},
			want: components("https", "proxy.example", 443, "proxy:"+token),
		},
		{
			name: "underflow expect timeout closes proxy projection", argv: []string{
				"curl", "--proxy", "https://proxy.example", "--proxy-user",
				"proxy:" + token, "--expect100-timeout", "1e-4000",
				"https://origin.example",
			},
		},
		{
			name: "unrelated origin header preserves proxy credentials", argv: []string{
				"curl", "--proxy", "http://proxy.example", "--proxy-user",
				"proxy:" + token, "--header", "X-Test: safe", "--data", "safe",
				"http://origin.example",
			},
			want: components(
				"http", "proxy.example", 1080,
				"X-Test: safe", "proxy:"+token,
			),
			wantAuthoritative: true,
		},
		{
			name: "ordinary proxy authorization overrides generated credentials", argv: []string{
				"curl", "--proxy", "http://proxy.example", "--proxy-user",
				"proxy:" + token, "--header", "Proxy-Authorization: safe",
				"--data", "safe", "http://origin.example",
			},
			want: components(
				"http", "proxy.example", 1080, "Proxy-Authorization: safe",
			),
			wantAuthoritative: true,
		},
		{
			name: "literal proxy header remains exact with body", argv: []string{
				"curl", "--proxy", "http://proxy.example", "--proxy-header",
				"X-Proxy-Key: " + token, "--data", "safe",
				"http://origin.example",
			},
			want: components(
				"http", "proxy.example", 1080, "X-Proxy-Key: "+token,
			),
			wantAuthoritative: true,
		},
		{
			name: "multipart suppresses proxy content type candidate", argv: []string{
				"curl", "--proxy", "http://proxy.example", "--proxy-header",
				"Content-Type: " + token, "--form-string", "key=safe",
				"http://origin.example",
			},
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
			name: "ordinary header reaches forward proxy", argv: []string{
				"curl", "--proxy", "http://proxy.example", "--header",
				"X-Proxy-Key: " + token, "http://origin.example",
			},
			want: components(
				"http", "proxy.example", 1080, "X-Proxy-Key: "+token,
			),
			wantAuthoritative: true,
		},
		{
			name: "URL query reaches external proxy for local HTTP origin", argv: []string{
				"curl", "--noproxy", "", "--proxy", "http://proxy.example",
				"--url-query", "key=" + token + " value", "http://127.0.0.1/",
			},
			want: components(
				"http", "proxy.example", 1080, "key="+token+"+value",
			),
			wantAuthoritative: true,
		},
		{
			name: "path reaches external proxy for local HTTP origin", argv: []string{
				"curl", "--proxy", "http://proxy.example",
				"http://127.0.0.1/secrets/" + token,
			},
			want: components(
				"http", "proxy.example", 1080, "/secrets/"+token,
			),
			wantAuthoritative: true,
		},
		{
			name: "request target replaces proxy path and query", argv: []string{
				"curl", "--proxy", "http://proxy.example", "--url-query",
				"hidden=" + token, "--request-target", "/exact/" + token,
				"http://127.0.0.1/original",
			},
			want: components(
				"http", "proxy.example", 1080, "/exact/"+token,
			),
			wantAuthoritative: true,
		},
		{
			name: "HTTPS local origin query stays inside CONNECT", argv: []string{
				"curl", "--proxy", "http://proxy.example", "--url-query",
				"key=" + token, "https://127.0.0.1/",
			},
			wantAuthoritative: true,
		},
		{
			name: "proxy tunnel hides HTTP origin query", argv: []string{
				"curl", "-p", "--proxy", "http://proxy.example",
				"--url-query", "key=" + token, "http://127.0.0.1/",
			},
			wantAuthoritative: true,
		},
		{
			name: "HTTPS scheme overrides SOCKS option alias", argv: []string{
				"curl", "--socks5", "https://proxy.example", "--url-query",
				"key=" + token, "http://127.0.0.1/",
			},
			want: components(
				"https", "proxy.example", 443, "key="+token,
			),
			wantAuthoritative: true,
		},
		{
			name: "ordinary header reaches CONNECT without separate list", argv: []string{
				"curl", "--proxy", "http://proxy.example", "--header",
				"X-Proxy-Key: " + token, "https://origin.example",
			},
			want: components(
				"http", "proxy.example", 1080, "X-Proxy-Key: "+token,
			),
			wantAuthoritative: true,
		},
		{
			name: "separate proxy list wins CONNECT header selection", argv: []string{
				"curl", "--proxy", "http://proxy.example", "--proxy-user",
				"proxy:" + token, "--header", "Proxy-Authorization: safe",
				"--proxy-header", "X-Proxy: safe", "https://origin.example",
			},
			want: components(
				"http", "proxy.example", 1080, "X-Proxy: safe", "proxy:"+token,
			),
			wantAuthoritative: true,
		},
		{
			name: "ordinary header remains on mixed forward request", argv: []string{
				"curl", "--proxy", "http://proxy.example", "--header",
				"X-Proxy-Key: " + token, "--proxy-header", "X-Proxy: safe",
				"http://one.example", "https://two.example",
			},
			want: components(
				"http", "proxy.example", 1080,
				"X-Proxy-Key: "+token, "X-Proxy: safe",
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
			name: "SOCKS proxy credentials use their own metadata lane", argv: []string{
				"curl", "--proxy", "socks5://proxy.example", "--proxy-user",
				"proxy:" + token, "https://origin.example",
			},
			want:              components("tcp", "proxy.example", 1080, "proxy", token),
			wantAuthoritative: true,
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
			want:              components("tcp", "proxy.example", 1080, "proxy", token),
			wantAuthoritative: true,
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

func TestStaticCurlProxyDestinationInlinePayloadBoundary(t *testing.T) {
	t.Parallel()

	const token = "AKIA7Q2M9X4B6C8D3F5H"
	for _, test := range []struct {
		name             string
		argv             []string
		expandIndex      int
		want             bool
		wantProxyPayload []string
		wantMetadata     []string
	}{
		{
			name: "literal data preserves HTTP proxy destination proof",
			argv: []string{
				"curl", "--noproxy", "", "--proxy", "http://proxy.example",
				"--proxy-user", "proxy:safe", "--data", token,
				"http://origin.example",
			},
			want:             true,
			wantProxyPayload: []string{token},
			wantMetadata:     []string{"proxy:safe"},
		},
		{
			name: "projected URL encoded data preserves HTTPS proxy proof",
			argv: []string{
				"curl", "--proxy", "https://proxy.example", "--data-urlencode",
				"key=" + token + " value", "https://origin.example",
			},
			want: true,
		},
		{
			name: "literal form string preserves HTTP1 proxy proof",
			argv: []string{
				"curl", "--proxy1.0", "http://proxy.example", "--form-string",
				"key=" + token, "http://origin.example",
			},
			want:             true,
			wantProxyPayload: []string{"key", token},
		},
		{
			name: "safe literal multipart form preserves proxy proof",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--form",
				"key=" + token, "http://origin.example",
			},
			want:             true,
			wantProxyPayload: []string{"key", token},
		},
		{
			name: "data raw at prefix remains literal",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--data-raw",
				"@" + token, "http://origin.example",
			},
			want:             true,
			wantProxyPayload: []string{"@" + token},
		},
		{
			name: "output path does not change proxy destination",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--data", token,
				"--output", "/tmp/response", "http://origin.example",
			},
			want:             true,
			wantProxyPayload: []string{token},
		},
		{
			name: "no remote name remains inert",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--data", token,
				"--no-remote-name", "http://origin.example/",
			},
			want:             true,
			wantProxyPayload: []string{token},
		},
		{
			name: "literal origin header does not change proxy destination",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--data", token,
				"--header", "X-Test: safe", "http://origin.example",
			},
			want:             true,
			wantProxyPayload: []string{token},
			wantMetadata:     []string{"X-Test: safe"},
		},
		{
			name: "validated timeout does not change proxy destination",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--data", token,
				"--max-time", "5", "http://origin.example",
			},
			want:             true,
			wantProxyPayload: []string{token},
		},
		{
			name: "bounded URL query does not change proxy destination",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--data", token,
				"--url-query", "+key=safe%2Fvalue", "http://origin.example",
			},
			want:             true,
			wantProxyPayload: []string{token},
			wantMetadata:     []string{"key=safe%2fvalue"},
		},
		{
			name: "invalid raw URL query aborts before proxy",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--data", token,
				"--url-query", "+bad space", "http://origin.example",
			},
		},
		{
			name: "huge retry aborts before proxy",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--data", token,
				"--retry", "999999999999999999999999",
				"http://origin.example",
			},
		},
		{
			name: "huge timeout aborts before proxy",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--data", token,
				"--max-time", "2147483.648", "http://origin.example",
			},
		},
		{
			name: "header file can abort before proxy",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--data", token,
				"--header", "@missing", "http://origin.example",
			},
		},
		{
			name: "remote name without filename aborts before proxy",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--data", token,
				"--remote-name", "http://origin.example/",
			},
		},
		{
			name: "get moves inline data out of body lane",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--get", "--data",
				token, "http://origin.example",
			},
			want:         true,
			wantMetadata: []string{token},
		},
		{
			name: "invalid GET aggregate aborts before proxy",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--get", "--data",
				"bad space", "--proxy-user", token, "http://origin.example",
			},
		},
		{
			name: "GET data ignores wire-invalid replaced URL query at proxy",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--get", "--data",
				"safe=value", "--url-query", "bad name=" + token,
				"--proxy-user", "proxy:safe", "http://origin.example",
			},
			want:         true,
			wantMetadata: []string{"proxy:safe", "safe=value"},
		},
		{
			name: "file backed body cannot prove proxy reachability",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--data-binary",
				"@/tmp/" + token, "http://origin.example",
			},
		},
		{
			name: "stdin body cannot prove proxy reachability",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--data-binary", "@-",
				"http://origin.example/#" + token,
			},
		},
		{
			name: "dynamic body cannot prove proxy reachability",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--data", token,
				"http://origin.example",
			},
			expandIndex: 4,
		},
		{
			name: "encoded multipart body is outside exact projection",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--form",
				"key=" + token + ";encoder=base64", "http://origin.example",
			},
			want:             true,
			wantProxyPayload: []string{"key"},
		},
		{
			name: "malformed form aborts before proxy",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--form", token,
				"http://origin.example",
			},
		},
		{
			name: "malformed form string aborts before proxy",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--form-string", token,
				"http://origin.example",
			},
		},
		{
			name: "opaque sibling body closes destination proof",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--data", token,
				"--data", "@payload.txt", "http://origin.example",
			},
		},
		{
			name: "conflicting request modes abort before proxy",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--data", token,
				"--form-string", "key=safe", "http://origin.example",
			},
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
			proxy, _, got := staticCurlProxyDestination(facts.Commands[0])
			if got != test.want {
				t.Fatalf(
					"proxy proof = %t, want %t; proxy=%#v facts=%#v",
					got,
					test.want,
					proxy,
					facts,
				)
			}
			proxyPayloads := StaticCurlProxyUploadPayloads(facts.Commands[0])
			gotProxyPayload := make([]string, 0, len(proxyPayloads))
			for _, payload := range proxyPayloads {
				gotProxyPayload = append(gotProxyPayload, payload.Value)
				if payload.Scheme != proxy.Scheme || payload.Host != proxy.Host ||
					payload.Port != proxy.Port {
					t.Fatalf("payload target = %#v, proxy = %#v", payload, proxy)
				}
			}
			if !slices.Equal(gotProxyPayload, test.wantProxyPayload) {
				t.Fatalf(
					"proxy payloads = %#v, want %#v",
					gotProxyPayload,
					test.wantProxyPayload,
				)
			}
			metadata := StaticCurlProxyTransmittedMetadata(facts.Commands[0])
			gotMetadata := make([]string, 0, len(metadata.ProxyRequestComponents))
			for _, component := range metadata.ProxyRequestComponents {
				gotMetadata = append(gotMetadata, component.Value)
			}
			if !slices.Equal(gotMetadata, test.wantMetadata) {
				t.Fatalf(
					"proxy metadata = %#v, want %#v",
					gotMetadata,
					test.wantMetadata,
				)
			}
			if test.expandIndex == 0 && facts.Authoritative() != test.want {
				t.Fatalf(
					"authoritative = %t, want %t; facts=%#v",
					facts.Authoritative(),
					test.want,
					facts,
				)
			}
		})
	}
}

func TestCurlProxyURLQueryOptionsValid(t *testing.T) {
	t.Parallel()

	parsed := parseCurlArgv([]string{
		"curl", "--proxy", "http://proxy.example", "--data", "safe",
		"--url-query", "+" + strings.Repeat("a", 50_000),
		"--url-query", "+" + strings.Repeat("b", 50_000),
		"http://origin.example",
	})
	if curlProxyURLQueryOptionsValid(parsed) {
		t.Fatal("repeated 100,001-byte URL query unexpectedly valid")
	}

	parsed = parseCurlArgv([]string{
		"curl", "--proxy", "http://proxy.example", "--data", "safe",
		"--url-query", "key=" + strings.Repeat(" ", 33_332),
		"--url-query", "tail=x", "http://origin.example",
	})
	if !curlProxyURLQueryOptionsValid(parsed) {
		t.Fatal("exact 33,343-byte encoded repeated URL query unexpectedly invalid")
	}
}

func TestCurlProxyNumericBoundsValidateExpect100Timeout(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		value string
		want  bool
	}{
		{name: "exact zero", value: "0e-4000", want: true},
		{name: "normal sub millisecond", value: "1e-307", want: true},
		{name: "underflow", value: "1e-4000"},
		{name: "subnormal", value: "1e-320"},
		{name: "rounded minimum normal", value: "0x1.fffffffffffffp-1023"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			parsed := parseCurlArgv([]string{
				"curl", "--expect100-timeout", test.value,
				"https://origin.example",
			})
			option := requireCurlParsedOption(
				t,
				parsed,
				"--expect100-timeout",
			)
			if got := curlProxyNumericOptionWithinPortableBounds(option); got != test.want {
				t.Fatalf("portable bounds = %t, want %t; parse = %#v", got, test.want, parsed)
			}
		})
	}
}

func TestCurlHTTPRequestProjectionRetainsReplacedURLQueryCaps(t *testing.T) {
	t.Parallel()

	argv := []string{
		"curl", "--get", "--data", "safe=value",
		"--url-query", "+" + strings.Repeat("a", 50_000),
		"--url-query", "+" + strings.Repeat("b", 50_000),
		"https://origin.example/safe",
	}
	arguments := make([]ArgumentFact, 0, len(argv))
	for _, value := range argv {
		arguments = append(arguments, ArgumentFact{Value: value})
	}
	command := CommandFact{
		Program: "curl", Executable: "curl", Argv: argv,
		Arguments: arguments, ArgvComplete: true,
	}
	parsed := parseCurlArgv(argv)
	if len(parsed.Targets) != 1 {
		t.Fatalf("targets = %#v", parsed.Targets)
	}
	if projection, valid := staticCurlHTTPRequestComponentProjection(
		command,
		parsed,
		parsed.Targets[0].Group,
	); valid {
		t.Fatalf("projection = %#v, want prewire cap rejection", projection)
	}
}

func TestCurlURLQueryOptionBytesRawHighByteBoundary(t *testing.T) {
	t.Parallel()

	raw := "+key=token" + string([]byte{0x80, 0xff})
	want := strings.TrimPrefix(raw, "+")
	if got, valid := curlURLQueryOptionBytes(raw); !valid || got != want {
		t.Fatalf("curlURLQueryOptionBytes(raw) = %q, %t; want %q, true", got, valid, want)
	}
	for _, raw := range []string{"+key=bad value", "+key=bad\tvalue", "+key=bad\x7fvalue"} {
		if got, valid := curlURLQueryOptionBytes(raw); valid {
			t.Fatalf("curlURLQueryOptionBytes(%q) = %q, true; want invalid", raw, got)
		}
	}
}

func TestCurlReplacedURLQueryConfigBuilderLengthBoundary(t *testing.T) {
	t.Parallel()

	if !curlURLQueryConfigLengthsValid([]int{24_000_000}) {
		t.Fatal("single ignored config query unexpectedly capped")
	}
	if curlURLQueryConfigLengthsValid([]int{50_000, 50_000}) {
		t.Fatal("repeated config query at builder cap unexpectedly valid")
	}
}

func TestStaticCurlPostDataEightMegabyteBoundary(t *testing.T) {
	t.Parallel()

	postData := strings.Repeat("a", 8_000_000)
	argv := []string{"curl", "--data", postData, "https://origin.example/upload"}
	arguments := make([]ArgumentFact, 0, len(argv))
	for _, value := range argv {
		arguments = append(arguments, ArgumentFact{Value: value})
	}
	command := CommandFact{
		Program: "curl", Executable: "curl", Argv: argv,
		Arguments: arguments, ArgvComplete: true,
	}
	parsed := parseCurlArgv(argv)
	got, present, valid := staticCurlPostDataBytes(command, parsed, 0)
	if !valid || !present || len(got) != len(postData) {
		t.Fatalf("POST aggregate = length %d, present %t, valid %t", len(got), present, valid)
	}

	getArgv := []string{
		"curl", "--get", "--data", postData, "https://origin.example/upload",
	}
	getArguments := make([]ArgumentFact, 0, len(getArgv))
	for _, value := range getArgv {
		getArguments = append(getArguments, ArgumentFact{Value: value})
	}
	getCommand := CommandFact{
		Program: "curl", Executable: "curl", Argv: getArgv,
		Arguments: getArguments, ArgvComplete: true,
	}
	if staticCurlGETPostDataValid(getCommand, parseCurlArgv(getArgv), 0) {
		t.Fatal("8 MB GET aggregate unexpectedly fit final URL cap")
	}
}

func TestStaticCurlUploadPayloadsRejectMalformedMultipart(t *testing.T) {
	t.Parallel()

	for _, option := range []string{"--form", "--form-string"} {
		t.Run(option, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{Tool: "exec", Argv: []string{
				"curl", option, "AKIA7Q2M9X4B6C8D3F5H",
				"https://origin.example",
			}})
			if len(facts.Commands) != 1 {
				t.Fatalf("commands = %#v", facts.Commands)
			}
			if payloads := StaticCurlUploadPayloads(facts.Commands[0]); len(payloads) != 0 {
				t.Fatalf("payloads = %#v", payloads)
			}
		})
	}
}
