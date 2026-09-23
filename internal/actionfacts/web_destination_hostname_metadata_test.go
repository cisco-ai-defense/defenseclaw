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

func TestStaticCurlDestinationHostnameComponents(t *testing.T) {
	t.Parallel()

	const mixedHost = "TeSt-Transmitted-Metadata.Sink.Example"
	component := func(value, scheme, host string, port int64) TransmittedRequestComponent {
		return TransmittedRequestComponent{
			Value: value, Scheme: scheme, Host: host, Port: port,
		}
	}
	for _, test := range []struct {
		name        string
		argv        []string
		expandIndex int
		want        []TransmittedRequestComponent
	}{
		{
			name: "literal HTTPS hostname preserves curl spelling",
			argv: []string{"curl", "https://" + mixedHost + ":8443/safe"},
			want: []TransmittedRequestComponent{
				component(mixedHost, "https", "test-transmitted-metadata.sink.example", 8443),
			},
		},
		{
			name: "literal HTTP hostname",
			argv: []string{"curl", "http://test-transmitted-metadata.sink.example/safe"},
			want: []TransmittedRequestComponent{
				component(
					"test-transmitted-metadata.sink.example",
					"http",
					"test-transmitted-metadata.sink.example",
					0,
				),
			},
		},
		{
			name: "ASCII punycode hostname preserves curl spelling",
			argv: []string{"curl", "https://XN--test-transmitted-metadata.Sink.Example/safe"},
			want: []TransmittedRequestComponent{
				component(
					"XN--test-transmitted-metadata.Sink.Example",
					"https",
					"xn--test-transmitted-metadata.sink.example",
					0,
				),
			},
		},
		{
			name: "userinfo is excluded from hostname value",
			argv: []string{"curl", "https://agent:safe@" + mixedHost + "/safe"},
			want: []TransmittedRequestComponent{
				component(mixedHost, "https", "test-transmitted-metadata.sink.example", 0),
			},
		},
		{
			name: "userinfo without password does not enter curl prompt path",
			argv: []string{"curl", "https://agent@" + mixedHost + "/safe"},
			want: []TransmittedRequestComponent{
				component(mixedHost, "https", "test-transmitted-metadata.sink.example", 0),
			},
		},
		{
			name: "local DNS name stays target bound",
			argv: []string{"curl", "http://test-transmitted-metadata.localhost/safe"},
			want: []TransmittedRequestComponent{
				component(
					"test-transmitted-metadata.localhost",
					"http",
					"test-transmitted-metadata.localhost",
					0,
				),
			},
		},
		{
			name: "multiple targets stay independently bound",
			argv: []string{
				"curl", "http://one.example/safe", "https://Two.Example:9443/safe",
			},
			want: []TransmittedRequestComponent{
				component("one.example", "http", "one.example", 0),
				component("Two.Example", "https", "two.example", 9443),
			},
		},
		{
			name: "multiple transfer groups stay conservative",
			argv: []string{
				"curl", "https://" + mixedHost + "/safe", "--next",
				"https://other.example/safe",
			},
		},
		{
			name: "noproxy HTTP target retains direct origin authority",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--noproxy", "Direct.Example",
				"http://Direct.Example/safe", "http://other.example/safe",
			},
			want: []TransmittedRequestComponent{
				component("Direct.Example", "http", "direct.example", 0),
			},
		},
		{
			name: "HTTPS proxy capability is required before HTTP origin authority",
			argv: []string{
				"curl", "--proxy", "https://proxy.example",
				"http://" + mixedHost + "/safe",
			},
		},
		{
			name: "HTTPS proxy capability is required before HTTPS origin SNI",
			argv: []string{
				"curl", "--proxy", "https://proxy.example",
				"https://" + mixedHost + "/safe",
			},
		},
		{
			name: "HTTPS proxy capability is required before HTTP CONNECT authority",
			argv: []string{
				"curl", "--proxytunnel", "--proxy", "https://proxy.example",
				"http://" + mixedHost + "/safe",
			},
		},
		{
			name: "HTTPS proxy noproxy target retains only direct origin authority",
			argv: []string{
				"curl", "--proxy", "https://proxy.example", "--noproxy", ".example",
				"http://Direct.Example/safe", "https://proxied.invalid/safe",
			},
			want: []TransmittedRequestComponent{
				component("Direct.Example", "http", "direct.example", 0),
			},
		},
		{
			name: "location retains initial generated authority",
			argv: []string{"curl", "--location", "https://" + mixedHost + "/safe"},
			want: []TransmittedRequestComponent{
				component(mixedHost, "https", "test-transmitted-metadata.sink.example", 0),
			},
		},
		{
			name: "URL option owns literal destination authority",
			argv: []string{"curl", "--url", "https://" + mixedHost + "/safe"},
			want: []TransmittedRequestComponent{
				component(mixedHost, "https", "test-transmitted-metadata.sink.example", 0),
			},
		},
		{
			name:        "dynamic URL option is not literal authority",
			argv:        []string{"curl", "--url", "https://" + mixedHost + "/safe"},
			expandIndex: 2,
		},
		{
			name: "trailing dot hostname stays conservative",
			argv: []string{"curl", "https://" + mixedHost + "./safe"},
		},
		{
			name: "Location-like header is not a redirect destination",
			argv: []string{
				"curl", "--location", "--header",
				"Location: https://redirect.example/", "https://safe.example/safe",
			},
			want: []TransmittedRequestComponent{
				component("safe.example", "https", "safe.example", 0),
			},
		},
		{
			name: "HTTPS Host override retains canonical TLS SNI",
			argv: []string{
				"curl", "--header", "Host: safe.example",
				"https://" + mixedHost + "/safe",
			},
			want: []TransmittedRequestComponent{
				component(
					"test-transmitted-metadata.sink.example",
					"https",
					"test-transmitted-metadata.sink.example",
					0,
				),
			},
		},
		{
			name: "HTTP Host override suppresses generated authority",
			argv: []string{
				"curl", "--header", "Host: safe.example",
				"http://" + mixedHost + "/safe",
			},
		},
		{
			name: "HTTPS header file can preempt TLS SNI",
			argv: []string{
				"curl", "--header", "@headers.txt", "https://" + mixedHost + "/safe",
			},
		},
		{
			name: "HTTP header file suppresses generated authority",
			argv: []string{
				"curl", "--header", "@headers.txt", "http://" + mixedHost + "/safe",
			},
		},
		{
			name: "numeric IPv4 is not hostname content",
			argv: []string{"curl", "http://192.0.2.7/safe"},
		},
		{
			name: "numeric IPv6 is not hostname content",
			argv: []string{"curl", "https://[2001:db8::7]/safe"},
		},
		{
			name:        "dynamic target is not literal authority",
			argv:        []string{"curl", "https://" + mixedHost + "/safe"},
			expandIndex: 1,
		},
		{
			name: "config indirection closes hostname authority",
			argv: []string{
				"curl", "--config", "curlrc", "https://" + mixedHost + "/safe",
			},
		},
		{
			name: "resolve override closes hostname authority",
			argv: []string{
				"curl", "--resolve", mixedHost + ":443:192.0.2.7",
				"https://" + mixedHost + "/safe",
			},
		},
		{
			name: "connect-to override closes hostname authority",
			argv: []string{
				"curl", "--connect-to", mixedHost + ":443:other.example:443",
				"https://" + mixedHost + "/safe",
			},
		},
		{
			name: "missing HTTPS CA support can preempt SNI",
			argv: []string{
				"curl", "--cacert", "/missing/ca", "https://" + mixedHost + "/safe",
			},
		},
		{
			name: "missing HTTPS certificate can preempt SNI",
			argv: []string{
				"curl", "--cert", "/missing/cert", "https://" + mixedHost + "/safe",
			},
		},
		{
			name: "missing HTTPS key can preempt SNI",
			argv: []string{
				"curl", "--cert", "client.pem", "--key", "/missing/key",
				"https://" + mixedHost + "/safe",
			},
		},
		{
			name: "invalid HTTPS cipher control can preempt SNI",
			argv: []string{
				"curl", "--ciphers", "invalid", "https://" + mixedHost + "/safe",
			},
		},
		{
			name: "invalid HTTPS curve control can preempt SNI",
			argv: []string{
				"curl", "--curves", "invalid", "https://" + mixedHost + "/safe",
			},
		},
		{
			name: "missing upload file can preempt HTTP Host",
			argv: []string{
				"curl", "--upload-file", "/missing/body", "http://" + mixedHost + "/safe",
			},
		},
		{
			name: "missing data file can preempt HTTP Host",
			argv: []string{
				"curl", "--data-binary", "@/missing/body", "http://" + mixedHost + "/safe",
			},
		},
		{
			name: "promptable user can preempt HTTP Host",
			argv: []string{
				"curl", "--user", "agent", "http://" + mixedHost + "/safe",
			},
		},
		{
			name: "promptable proxy user can preempt direct HTTP Host",
			argv: []string{
				"curl", "--proxy-user", "agent", "http://" + mixedHost + "/safe",
			},
		},
		{
			name: "final explicit proxy password restores first-wire proof",
			argv: []string{
				"curl", "--proxy-user", "agent", "--proxy-user", "agent:password",
				"http://" + mixedHost + "/safe",
			},
			want: []TransmittedRequestComponent{
				component(mixedHost, "http", "test-transmitted-metadata.sink.example", 0),
			},
		},
		{
			name: "positive compression support is capability dependent",
			argv: []string{
				"curl", "--compressed", "https://" + mixedHost + "/safe",
			},
		},
		{
			name: "conflicting fail modes abort before network",
			argv: []string{
				"curl", "--fail", "--fail-with-body",
				"https://" + mixedHost + "/safe",
			},
		},
		{
			name: "eager fail conflict is not cleared by later inverse",
			argv: []string{
				"curl", "--fail", "--fail-with-body", "--no-fail",
				"https://" + mixedHost + "/safe",
			},
		},
		{
			name: "disabled compression is build independent",
			argv: []string{
				"curl", "--no-compressed", "https://" + mixedHost + "/safe",
			},
			want: []TransmittedRequestComponent{
				component(mixedHost, "https", "test-transmitted-metadata.sink.example", 0),
			},
		},
		{
			name: "positive SOCKS GSSAPI compatibility is capability dependent",
			argv: []string{
				"curl", "--socks5-gssapi-nec", "https://" + mixedHost + "/safe",
			},
		},
		{
			name: "disabled SOCKS GSSAPI compatibility is build independent",
			argv: []string{
				"curl", "--no-socks5-gssapi-nec", "https://" + mixedHost + "/safe",
			},
			want: []TransmittedRequestComponent{
				component(mixedHost, "https", "test-transmitted-metadata.sink.example", 0),
			},
		},
		{
			name: "cookie file can preempt HTTP Host",
			argv: []string{
				"curl", "--cookie", "/missing/cookies", "http://" + mixedHost + "/safe",
			},
		},
		{
			name: "literal header preserves first-wire proof",
			argv: []string{
				"curl", "--header", "X-Fixture: safe", "https://" + mixedHost + "/safe",
			},
			want: []TransmittedRequestComponent{
				component(mixedHost, "https", "test-transmitted-metadata.sink.example", 0),
			},
		},
		{
			name: "inline data preserves first-wire proof",
			argv: []string{
				"curl", "--data-raw", "fixture", "https://" + mixedHost + "/safe",
			},
			want: []TransmittedRequestComponent{
				component(mixedHost, "https", "test-transmitted-metadata.sink.example", 0),
			},
		},
		{
			name: "literal cookie preserves first-wire proof",
			argv: []string{
				"curl", "--cookie", "name=value", "http://" + mixedHost + "/safe",
			},
			want: []TransmittedRequestComponent{
				component(mixedHost, "http", "test-transmitted-metadata.sink.example", 0),
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
			got := StaticCurlTransmittedMetadata(facts.Commands[0]).
				HTTPDestinationHostnameComponents
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("hostname components = %#v, want %#v; facts=%#v", got, test.want, facts)
			}
		})
	}
}

func TestStaticCurlProxyDestinationHostnameComponents(t *testing.T) {
	t.Parallel()

	const mixedHost = "TeSt-Transmitted-Metadata.Sink.Example"
	components := func(scheme, host string, port int64, values ...string) []TransmittedRequestComponent {
		result := make([]TransmittedRequestComponent, 0, len(values))
		for _, value := range values {
			result = append(result, TransmittedRequestComponent{
				Value: value, Scheme: scheme, Host: host, Port: port,
			})
		}
		return result
	}
	for _, test := range []struct {
		name string
		argv []string
		want []TransmittedRequestComponent
	}{
		{
			name: "HTTP forward proxy receives absolute-form hostname",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--header",
				"Host: safe.example", "http://" + mixedHost + "/safe",
			},
			want: components("http", "proxy.example", 1080, mixedHost),
		},
		{
			name: "proxy URL userinfo without password does not prompt",
			argv: []string{
				"curl", "--proxy", "http://agent@proxy.example",
				"http://" + mixedHost + "/safe",
			},
			want: components("http", "proxy.example", 1080, mixedHost),
		},
		{
			name: "promptable HTTP proxy user can preempt hostname bytes",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--proxy-user", "agent",
				"http://" + mixedHost + "/safe",
			},
		},
		{
			name: "promptable SOCKS proxy user can preempt hostname bytes",
			argv: []string{
				"curl", "--proxy", "socks5h://proxy.example", "--proxy-user", "agent",
				"http://" + mixedHost + "/safe",
			},
		},
		{
			name: "final explicit HTTP proxy password restores hostname bytes",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--proxy-user", "agent",
				"--proxy-user", "agent:password", "http://" + mixedHost + "/safe",
			},
			want: components("http", "proxy.example", 1080, mixedHost),
		},
		{
			name: "HTTPS proxy origin hostname requires an executable capability fact",
			argv: []string{
				"curl", "--proxy", "https://TeSt-Transmitted-Metadata.Proxy.Example",
				"http://origin.example/safe",
			},
		},
		{
			name: "HTTPS proxy CONNECT origin requires an executable capability fact",
			argv: []string{
				"curl", "--proxytunnel", "--proxy", "https://proxy.example",
				"http://" + mixedHost + "/safe",
			},
		},
		{
			name: "HTTPS proxy peer SNI requires an executable capability fact",
			argv: []string{
				"curl", "--proxy", "https://TeSt-Transmitted-Metadata.Proxy.Example",
				"http://192.0.2.7/safe",
			},
		},
		{
			name: "HTTP proxy peer hostname is not a protocol-visible value",
			argv: []string{
				"curl", "--proxy", "http://TeSt-Transmitted-Metadata.Proxy.Example",
				"http://192.0.2.7/safe",
			},
		},
		{
			name: "numeric HTTPS proxy peer has no TLS SNI hostname",
			argv: []string{
				"curl", "--proxy", "https://192.0.2.8", "http://192.0.2.7/safe",
			},
		},
		{
			name: "generated Host remains with custom request target",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--request-target",
				"/custom", "http://" + mixedHost + "/safe",
			},
			want: components("http", "proxy.example", 1080, mixedHost),
		},
		{
			name: "custom request target and Host remove origin hostname",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--request-target",
				"/custom", "--header", "Host: other.example",
				"http://" + mixedHost + "/safe",
			},
		},
		{
			name: "HTTPS CONNECT carries hostname despite Host overrides",
			argv: []string{
				"curl", "--proxy", "http://proxy.example", "--header",
				"Host: other.example", "--proxy-header", "Host: proxy-header.example",
				"https://" + mixedHost + "/safe",
			},
			want: components("http", "proxy.example", 1080, mixedHost),
		},
		{
			name: "explicit HTTP CONNECT carries hostname",
			argv: []string{
				"curl", "--proxytunnel", "--proxy", "http://proxy.example",
				"--header", "Host: other.example", "http://" + mixedHost + "/safe",
			},
			want: components("http", "proxy.example", 1080, mixedHost),
		},
		{
			name: "SOCKS5h carries literal hostname",
			argv: []string{
				"curl", "--proxy", "socks5h://proxy.example",
				"http://" + mixedHost + "/safe",
			},
			want: components("tcp", "proxy.example", 1080, mixedHost),
		},
		{
			name: "SOCKS4a carries literal hostname",
			argv: []string{
				"curl", "--socks4a", "proxy.example", "http://" + mixedHost + "/safe",
			},
			want: components("tcp", "proxy.example", 1080, mixedHost),
		},
		{
			name: "local-resolving SOCKS5 relay observes generated HTTP Host",
			argv: []string{
				"curl", "--socks5", "proxy.example", "http://" + mixedHost + "/safe",
			},
			want: components("tcp", "proxy.example", 1080, mixedHost),
		},
		{
			name: "local-resolving SOCKS4 relay observes generated HTTP Host",
			argv: []string{
				"curl", "--socks4", "proxy.example", "http://" + mixedHost + "/safe",
			},
			want: components("tcp", "proxy.example", 1080, mixedHost),
		},
		{
			name: "local-resolving SOCKS5 custom HTTP Host removes origin hostname",
			argv: []string{
				"curl", "--socks5", "proxy.example", "--header",
				"Host: safe.example", "http://" + mixedHost + "/safe",
			},
		},
		{
			name: "local-resolving SOCKS5 relay observes canonical HTTPS SNI",
			argv: []string{
				"curl", "--socks5", "proxy.example", "https://" + mixedHost + "/safe",
			},
			want: components(
				"tcp", "proxy.example", 1080,
				"test-transmitted-metadata.sink.example",
			),
		},
		{
			name: "local-resolving SOCKS5 HTTPS Host override retains SNI",
			argv: []string{
				"curl", "--socks5", "proxy.example", "--header",
				"Host: safe.example", "https://" + mixedHost + "/safe",
			},
			want: components(
				"tcp", "proxy.example", 1080,
				"test-transmitted-metadata.sink.example",
			),
		},
		{
			name: "local-resolving SOCKS5 noproxy target stays out of proxy lane",
			argv: []string{
				"curl", "--socks5", "proxy.example", "--noproxy", mixedHost,
				"http://" + mixedHost + "/safe",
			},
		},
		{
			name: "noproxy target is not bound to proxy peer",
			argv: []string{
				"curl", "--proxy", "socks5h://proxy.example", "--noproxy",
				mixedHost, "http://" + mixedHost + "/safe", "http://other.example/safe",
			},
			want: components("tcp", "proxy.example", 1080, "other.example"),
		},
		{
			name: "multiple proxy transfer groups stay conservative",
			argv: []string{
				"curl", "--proxy", "http://proxy.example",
				"http://" + mixedHost + "/safe", "--next",
				"http://other.example/safe",
			},
		},
		{
			name: "proxy certificate input can preempt proxy hostname bytes",
			argv: []string{
				"curl", "--proxy", "https://proxy.example", "--proxy-cert",
				"/missing/cert", "http://" + mixedHost + "/safe",
			},
		},
		{
			name: "proxy cipher control can preempt proxy hostname bytes",
			argv: []string{
				"curl", "--proxy", "https://proxy.example", "--proxy-ciphers",
				"invalid", "http://" + mixedHost + "/safe",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{Tool: "exec", Argv: test.argv})
			if len(facts.Commands) != 1 {
				t.Fatalf("commands = %#v", facts.Commands)
			}
			got := StaticCurlProxyTransmittedMetadata(facts.Commands[0]).
				ProxyDestinationHostnameComponents
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("proxy hostname components = %#v, want %#v; facts=%#v", got, test.want, facts)
			}
		})
	}
}

func TestStaticWgetDestinationHostnameComponents(t *testing.T) {
	t.Parallel()

	const mixedHost = "TeSt-Transmitted-Metadata.Sink.Example"
	component := func(value, scheme, host string, port int64) TransmittedRequestComponent {
		return TransmittedRequestComponent{
			Value: value, Scheme: scheme, Host: host, Port: port,
		}
	}
	for _, test := range []struct {
		name        string
		argv        []string
		expandIndex int
		want        []TransmittedRequestComponent
	}{
		{
			name: "Wget lowercases generated HTTPS authority",
			argv: []string{"wget", "--no-config", "https://" + mixedHost + ":8443/safe"},
			want: []TransmittedRequestComponent{
				component(
					"test-transmitted-metadata.sink.example",
					"https",
					"test-transmitted-metadata.sink.example",
					8443,
				),
			},
		},
		{
			name: "Wget lowercases ASCII punycode authority",
			argv: []string{
				"wget", "--no-config", "http://XN--test-transmitted-metadata.Sink.Example/safe",
			},
			want: []TransmittedRequestComponent{
				component(
					"xn--test-transmitted-metadata.sink.example",
					"http",
					"xn--test-transmitted-metadata.sink.example",
					0,
				),
			},
		},
		{
			name: "ambient wget config keeps authority conservative",
			argv: []string{"wget", "https://" + mixedHost + "/safe"},
		},
		{
			name: "active Wget HTTPS Host header retains TLS SNI",
			argv: []string{
				"wget", "--no-config", "--header", "Host: safe.example",
				"https://" + mixedHost + "/safe",
			},
			want: []TransmittedRequestComponent{
				component(
					"test-transmitted-metadata.sink.example",
					"https",
					"test-transmitted-metadata.sink.example",
					0,
				),
			},
		},
		{
			name: "active Wget HTTP Host header suppresses generated authority",
			argv: []string{
				"wget", "--no-config", "--header", "Host: safe.example",
				"http://" + mixedHost + "/safe",
			},
		},
		{
			name: "cleared Wget header restores generated authority",
			argv: []string{
				"wget", "--no-config", "--header", "Host: safe.example",
				"--header", "", "https://" + mixedHost + "/safe",
			},
			want: []TransmittedRequestComponent{
				component(
					"test-transmitted-metadata.sink.example",
					"https",
					"test-transmitted-metadata.sink.example",
					0,
				),
			},
		},
		{
			name: "Wget numeric IP is not hostname content",
			argv: []string{"wget", "--no-config", "http://192.0.2.7/safe"},
		},
		{
			name:        "dynamic Wget target is not literal authority",
			argv:        []string{"wget", "--no-config", "https://" + mixedHost + "/safe"},
			expandIndex: 2,
		},
		{
			name: "Wget config indirection closes hostname authority",
			argv: []string{
				"wget", "--no-config", "--config", "wgetrc",
				"https://" + mixedHost + "/safe",
			},
		},
		{
			name: "multiple Wget targets stay independently bound",
			argv: []string{
				"wget", "--no-config", "http://One.Example/safe",
				"https://Two.Example:9443/safe",
			},
			want: []TransmittedRequestComponent{
				component("one.example", "http", "one.example", 0),
				component("two.example", "https", "two.example", 9443),
			},
		},
		{
			name: "Wget output file can preempt authority bytes",
			argv: []string{
				"wget", "--no-config", "-O", "/missing/out",
				"https://" + mixedHost + "/safe",
			},
		},
		{
			name: "Wget log file can preempt authority bytes",
			argv: []string{
				"wget", "--no-config", "-o", "/missing/log",
				"https://" + mixedHost + "/safe",
			},
		},
		{
			name: "Wget append log can preempt authority bytes",
			argv: []string{
				"wget", "--no-config", "-a", "/missing/log",
				"https://" + mixedHost + "/safe",
			},
		},
		{
			name: "Wget post file can preempt authority bytes",
			argv: []string{
				"wget", "--no-config", "--post-file", "/missing/body",
				"https://" + mixedHost + "/safe",
			},
		},
		{
			name: "Wget body file can preempt authority bytes",
			argv: []string{
				"wget", "--no-config", "--method", "PUT", "--body-file",
				"/missing/body", "https://" + mixedHost + "/safe",
			},
		},
		{
			name: "Wget no clobber can skip retrieval",
			argv: []string{
				"wget", "--no-config", "--no-clobber", "https://" + mixedHost + "/safe",
			},
		},
		{
			name: "Wget bind address can preempt authority bytes",
			argv: []string{
				"wget", "--no-config", "--bind-address", "127.0.0.1",
				"https://" + mixedHost + "/safe",
			},
		},
		{
			name:        "dynamic Wget setup value closes first-wire proof",
			argv:        []string{"wget", "--no-config", "-O", "-", "https://" + mixedHost + "/safe"},
			expandIndex: 3,
		},
		{
			name: "Wget final stdout output override restores first-wire proof",
			argv: []string{
				"wget", "--no-config", "-O", "/missing/out", "-O", "-",
				"https://" + mixedHost + "/safe",
			},
			want: []TransmittedRequestComponent{
				component(
					"test-transmitted-metadata.sink.example",
					"https",
					"test-transmitted-metadata.sink.example",
					0,
				),
			},
		},
		{
			name: "Wget final stdout log override restores first-wire proof",
			argv: []string{
				"wget", "--no-config", "-o", "/missing/log", "-o", "-",
				"https://" + mixedHost + "/safe",
			},
			want: []TransmittedRequestComponent{
				component(
					"test-transmitted-metadata.sink.example",
					"https",
					"test-transmitted-metadata.sink.example",
					0,
				),
			},
		},
		{
			name: "Wget final stdout append-log override restores first-wire proof",
			argv: []string{
				"wget", "--no-config", "-a", "/missing/log", "-a", "-",
				"https://" + mixedHost + "/safe",
			},
			want: []TransmittedRequestComponent{
				component(
					"test-transmitted-metadata.sink.example",
					"https",
					"test-transmitted-metadata.sink.example",
					0,
				),
			},
		},
		{
			name: "Wget cleared no-clobber restores first-wire proof",
			argv: []string{
				"wget", "--no-config", "--no-clobber", "--no-no-clobber",
				"https://" + mixedHost + "/safe",
			},
			want: []TransmittedRequestComponent{
				component(
					"test-transmitted-metadata.sink.example",
					"https",
					"test-transmitted-metadata.sink.example",
					0,
				),
			},
		},
		{
			name: "Wget directory and TLS controls preserve first-wire proof",
			argv: []string{
				"wget", "--no-config", "--directory-prefix", "/missing/directory",
				"--no-check-certificate",
				"https://" + mixedHost + "/safe",
			},
			want: []TransmittedRequestComponent{
				component(
					"test-transmitted-metadata.sink.example",
					"https",
					"test-transmitted-metadata.sink.example",
					0,
				),
			},
		},
		{
			name: "Wget continue preserves first-wire proof",
			argv: []string{
				"wget", "--no-config", "--continue", "https://" + mixedHost + "/safe",
			},
			want: []TransmittedRequestComponent{
				component(
					"test-transmitted-metadata.sink.example",
					"https",
					"test-transmitted-metadata.sink.example",
					0,
				),
			},
		},
		{
			name: "Wget timestamping preserves first-wire proof",
			argv: []string{
				"wget", "--no-config", "--timestamping", "https://" + mixedHost + "/safe",
			},
			want: []TransmittedRequestComponent{
				component(
					"test-transmitted-metadata.sink.example",
					"https",
					"test-transmitted-metadata.sink.example",
					0,
				),
			},
		},
		{
			name: "Wget literal post data preserves first-wire proof",
			argv: []string{
				"wget", "--no-config", "--post-data", "fixture",
				"https://" + mixedHost + "/safe",
			},
			want: []TransmittedRequestComponent{
				component(
					"test-transmitted-metadata.sink.example",
					"https",
					"test-transmitted-metadata.sink.example",
					0,
				),
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
			got := StaticWgetTransmittedMetadata(facts.Commands[0]).
				HTTPDestinationHostnameComponents
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("Wget hostname components = %#v, want %#v; facts=%#v", got, test.want, facts)
			}
		})
	}
}

func TestDestinationHostnameComponentsRequireDirectShellExecution(t *testing.T) {
	t.Parallel()

	const host = "test-transmitted-metadata.sink.example"
	for _, test := range []struct {
		name    string
		tool    string
		command string
		program string
	}{
		{
			name: "POSIX curl redirect", tool: "exec",
			command: "curl https://" + host + "/safe > /missing/directory/out",
			program: "curl",
		},
		{
			name: "POSIX Wget redirect", tool: "exec",
			command: "wget --no-config https://" + host + "/safe > /missing/directory/out",
			program: "wget",
		},
		{
			name: "POSIX curl pipeline", tool: "exec",
			command: "curl https://" + host + "/safe | cat",
			program: "curl",
		},
		{
			name: "POSIX curl wrapper", tool: "exec",
			command: "env curl https://" + host + "/safe",
			program: "curl",
		},
		{
			name: "CMD curl redirect", tool: "cmd",
			command: "curl.exe https://" + host + `/safe > C:\missing\directory\out`,
			program: "curl",
		},
		{
			name: "PowerShell curl redirect", tool: "PowerShell",
			command: "curl.exe https://" + host + `/safe > C:\missing\directory\out`,
			program: "curl",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{Tool: test.tool, Command: test.command})
			found := false
			for _, command := range facts.Commands {
				if command.Program != test.program {
					continue
				}
				found = true
				var got []TransmittedRequestComponent
				if test.program == "curl" {
					got = StaticCurlTransmittedMetadata(command).
						HTTPDestinationHostnameComponents
				} else {
					got = StaticWgetTransmittedMetadata(command).
						HTTPDestinationHostnameComponents
				}
				if len(got) != 0 {
					t.Fatalf("hostname components = %#v, want none; command=%#v", got, command)
				}
			}
			if !found {
				t.Fatalf("%s command missing from facts: %#v", test.program, facts)
			}
		})
	}
}

func TestDestinationHostnameComponentsRequireExecuteEffect(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		argv []string
		wget bool
	}{
		{
			name: "curl", argv: []string{
				"curl", "https://test-transmitted-metadata.sink.example/safe",
			},
		},
		{
			name: "Wget", wget: true, argv: []string{
				"wget", "--no-config", "https://test-transmitted-metadata.sink.example/safe",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{Tool: "exec", Argv: test.argv})
			if len(facts.Commands) != 1 {
				t.Fatalf("commands = %#v", facts.Commands)
			}
			command := facts.Commands[0]
			command.Effect = EffectPreview
			var got []TransmittedRequestComponent
			if test.wget {
				got = StaticWgetTransmittedMetadata(command).
					HTTPDestinationHostnameComponents
			} else {
				got = StaticCurlTransmittedMetadata(command).
					HTTPDestinationHostnameComponents
			}
			if len(got) != 0 {
				t.Fatalf("hostname components = %#v, want none", got)
			}
		})
	}
}

func TestDestinationHostnameComponentsRequireNativeWindowsProgram(t *testing.T) {
	t.Parallel()

	const host = "test-transmitted-metadata.sink.example"
	for _, test := range []struct {
		name       string
		command    string
		program    string
		wantNative bool
	}{
		{
			name: "PowerShell curl alias", command: "curl https://" + host + "/safe",
			program: "curl",
		},
		{
			name: "PowerShell native curl", command: "curl.exe https://" + host + "/safe",
			program: "curl", wantNative: true,
		},
		{
			name:    "PowerShell Wget alias",
			command: "wget --no-config https://" + host + "/safe",
			program: "wget",
		},
		{
			name:    "PowerShell native Wget",
			command: "wget.exe --no-config https://" + host + "/safe",
			program: "wget", wantNative: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{Tool: "PowerShell", Command: test.command})
			found := false
			for _, command := range facts.Commands {
				if command.Program != test.program {
					continue
				}
				found = true
				var got []TransmittedRequestComponent
				if test.program == "curl" {
					got = StaticCurlTransmittedMetadata(command).
						HTTPDestinationHostnameComponents
				} else {
					got = StaticWgetTransmittedMetadata(command).
						HTTPDestinationHostnameComponents
				}
				if gotNative := len(got) == 1 && got[0].Value == host; gotNative != test.wantNative {
					t.Fatalf(
						"native hostname component = %t, want %t; components=%#v command=%#v",
						gotNative,
						test.wantNative,
						got,
						command,
					)
				}
			}
			if !found {
				t.Fatalf("%s command missing from facts: %#v", test.program, facts)
			}
		})
	}
}

func TestWgetDestinationHostnameWindowsExecutableIdentity(t *testing.T) {
	t.Parallel()

	const host = "test-transmitted-metadata.sink.example"
	for _, test := range []struct {
		name string
		tool string
		argv string
		want bool
	}{
		{
			name: "PowerShell uppercase native executable", tool: "PowerShell",
			argv: "WGET.EXE --no-config -O - https://" + host + "/safe", want: true,
		},
		{
			name: "PowerShell mixed-case native executable", tool: "PowerShell",
			argv: "WgEt.ExE --no-config -O - https://" + host + "/safe", want: true,
		},
		{
			name: "CMD uppercase native executable", tool: "cmd",
			argv: "WGET.EXE --no-config -O - https://" + host + "/safe", want: true,
		},
		{
			name: "trusted Windows system path", tool: "PowerShell",
			argv: "& 'C:\\Windows\\System32\\WGET.EXE' --no-config -O - https://" +
				host + "/safe", want: true,
		},
		{
			name: "untrusted executable path", tool: "PowerShell",
			argv: "& 'C:\\Temp\\WGET.EXE' --no-config -O - https://" + host + "/safe",
		},
		{
			name: "lookalike executable suffix", tool: "PowerShell",
			argv: "WGET.EXE.bak --no-config -O - https://" + host + "/safe",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{Tool: test.tool, Command: test.argv})
			got := false
			for _, command := range facts.Commands {
				for _, component := range StaticWgetTransmittedMetadata(command).
					HTTPDestinationHostnameComponents {
					got = got || component.Value == host
				}
			}
			if got != test.want {
				t.Fatalf("hostname projection = %t, want %t; facts=%#v", got, test.want, facts)
			}
		})
	}
}

func TestWgetUploadPayloadWindowsExecutableIdentity(t *testing.T) {
	t.Parallel()

	const payload = "test-wget-windows-payload"
	for _, test := range []struct {
		name    string
		tool    string
		command string
		want    bool
	}{
		{
			name: "PowerShell uppercase native payload", tool: "PowerShell",
			command: "WGET.EXE --no-config -O - --post-data " + payload +
				" https://sink.example/upload", want: true,
		},
		{
			name: "CMD mixed-case native payload", tool: "cmd",
			command: "WgEt.ExE --no-config -O - --post-data " + payload +
				" https://sink.example/upload", want: true,
		},
		{
			name: "PowerShell default output payload", tool: "PowerShell",
			command: "WGET.EXE --no-config --post-data " + payload +
				" https://sink.example/upload", want: true,
		},
		{
			name: "PowerShell redirect can preempt payload", tool: "PowerShell",
			command: "WGET.EXE --no-config -O - --post-data " + payload +
				" https://sink.example/upload > C:\\missing\\out",
		},
		{
			name: "CMD redirect can preempt payload", tool: "cmd",
			command: "WGET.EXE --no-config -O - --post-data " + payload +
				" https://sink.example/upload > C:\\missing\\out",
		},
		{
			name: "output file can preempt payload", tool: "PowerShell",
			command: "WGET.EXE --no-config -O C:\\missing\\out --post-data " + payload +
				" https://sink.example/upload",
		},
		{
			name: "log file can preempt payload", tool: "cmd",
			command: "WGET.EXE --no-config -o C:\\missing\\log --post-data " + payload +
				" https://sink.example/upload",
		},
		{
			name: "append log can preempt payload", tool: "PowerShell",
			command: "WGET.EXE --no-config -a C:\\missing\\log --post-data " + payload +
				" https://sink.example/upload",
		},
		{
			name: "no clobber can skip payload", tool: "cmd",
			command: "WGET.EXE --no-config --no-clobber --post-data " + payload +
				" https://sink.example/upload",
		},
		{
			name: "bind failure can preempt payload", tool: "PowerShell",
			command: "WGET.EXE --no-config --bind-address 127.0.0.1 --post-data " +
				payload + " https://sink.example/upload",
		},
		{
			name: "background mode is not exact", tool: "PowerShell",
			command: "WGET.EXE --no-config --background --post-data " + payload +
				" https://sink.example/upload",
		},
		{
			name: "spider mode still transmits the body", tool: "cmd",
			command: "WGET.EXE --no-config --spider --post-data " + payload +
				" https://sink.example/upload", want: true,
		},
		{
			name: "input file route is indirect", tool: "PowerShell",
			command: "WGET.EXE --no-config --input-file C:\\missing\\urls " +
				"--post-data " + payload,
		},
		{
			name: "config route is indirect", tool: "cmd",
			command: "WGET.EXE --config C:\\missing\\wgetrc --post-data " + payload +
				" https://sink.example/upload",
		},
		{
			name: "final stdout overrides restore payload", tool: "PowerShell",
			command: "WGET.EXE --no-config -O C:\\missing\\out -O - " +
				"-o C:\\missing\\log -o - --no-clobber --no-no-clobber " +
				"--post-data " + payload + " https://sink.example/upload",
			want: true,
		},
		{
			name: "PowerShell alias payload", tool: "PowerShell",
			command: "wget --no-config -O - --post-data " + payload +
				" https://sink.example/upload",
		},
		{
			name: "untrusted path payload", tool: "PowerShell",
			command: "& 'C:\\Temp\\WGET.EXE' --no-config -O - --post-data " +
				payload + " https://sink.example/upload",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{Tool: test.tool, Command: test.command})
			got := false
			for _, command := range facts.Commands {
				for _, candidate := range StaticWgetUploadPayloads(command) {
					got = got || candidate == payload
				}
			}
			if got != test.want {
				t.Fatalf("payload projection = %t, want %t; facts=%#v", got, test.want, facts)
			}
		})
	}
}

func TestWgetMetadataWindowsFirstWireSetup(t *testing.T) {
	t.Parallel()

	const header = "X-Key: test-wget-windows-first-wire"
	for _, test := range []struct {
		name    string
		tool    string
		command string
		want    bool
	}{
		{
			name: "PowerShell literal header", tool: "PowerShell",
			command: "WGET.EXE --no-config -O - --header '" + header +
				"' https://sink.example/upload", want: true,
		},
		{
			name: "CMD literal header", tool: "cmd",
			command: "WGET.EXE --no-config -O - --header \"" + header +
				"\" https://sink.example/upload", want: true,
		},
		{
			name: "PowerShell redirect", tool: "PowerShell",
			command: "WGET.EXE --no-config -O - --header '" + header +
				"' https://sink.example/upload > C:\\missing\\out",
		},
		{
			name: "CMD redirect", tool: "cmd",
			command: "WGET.EXE --no-config -O - --header \"" + header +
				"\" https://sink.example/upload > C:\\missing\\out",
		},
		{
			name: "output file", tool: "PowerShell",
			command: "WGET.EXE --no-config -O C:\\missing\\out --header '" +
				header + "' https://sink.example/upload",
		},
		{
			name: "log file", tool: "cmd",
			command: "WGET.EXE --no-config -o C:\\missing\\log --header \"" +
				header + "\" https://sink.example/upload",
		},
		{
			name: "append log", tool: "PowerShell",
			command: "WGET.EXE --no-config -a C:\\missing\\log --header '" +
				header + "' https://sink.example/upload",
		},
		{
			name: "post file", tool: "cmd",
			command: "WGET.EXE --no-config -O - --post-file C:\\missing\\body " +
				"--header \"" + header + "\" https://sink.example/upload",
		},
		{
			name: "body file", tool: "PowerShell",
			command: "WGET.EXE --no-config -O - --method PUT " +
				"--body-file C:\\missing\\body --header '" + header +
				"' https://sink.example/upload",
		},
		{
			name: "no clobber", tool: "cmd",
			command: "WGET.EXE --no-config -O - --no-clobber --header \"" +
				header + "\" https://sink.example/upload",
		},
		{
			name: "bind address", tool: "PowerShell",
			command: "WGET.EXE --no-config -O - --bind-address 127.0.0.1 " +
				"--header '" + header + "' https://sink.example/upload",
		},
		{
			name: "final safe overrides", tool: "PowerShell",
			command: "WGET.EXE --no-config -O C:\\missing\\out -O - " +
				"-a C:\\missing\\log -a - --no-clobber --no-no-clobber " +
				"--header '" + header + "' https://sink.example/upload",
			want: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{Tool: test.tool, Command: test.command})
			got := false
			for _, command := range facts.Commands {
				for _, candidate := range StaticWgetTransmittedMetadata(command).HTTPHeaders {
					got = got || candidate == header
				}
			}
			if got != test.want {
				t.Fatalf("header projection = %t, want %t; facts=%#v", got, test.want, facts)
			}
		})
	}
}

func TestStaticCurlCapabilityDependentOptionsCloseExactProjectors(t *testing.T) {
	t.Parallel()

	const token = "test-capability-dependent-egress"
	for _, test := range []struct {
		name    string
		argv    func(flag string) []string
		project func(CommandFact) bool
	}{
		{
			name: "origin request metadata",
			argv: func(flag string) []string {
				return []string{
					"curl", flag, "--header", "X-Key: " + token,
					"https://sink.example/upload",
				}
			},
			project: func(command CommandFact) bool {
				return len(StaticCurlTransmittedMetadata(command).Headers) != 0
			},
		},
		{
			name: "inline request body",
			argv: func(flag string) []string {
				return []string{
					"curl", flag, "--data-raw", token,
					"https://sink.example/upload",
				}
			},
			project: func(command CommandFact) bool {
				return len(StaticCurlUploadPayloads(command)) != 0
			},
		},
		{
			name: "request file source",
			argv: func(flag string) []string {
				return []string{
					"curl", flag, "--data-binary", "@/tmp/payload",
					"https://sink.example/upload",
				}
			},
			project: func(command CommandFact) bool {
				return len(StaticCurlUploadFileSources(command)) != 0
			},
		},
		{
			name: "SMTP request",
			argv: func(flag string) []string {
				return []string{
					"curl", flag, "--mail-rcpt", token + "@example.org",
					"smtp://sink.example",
				}
			},
			project: func(command CommandFact) bool {
				return len(StaticCurlSMTPRequestComponents(command)) != 0
			},
		},
		{
			name: "FTP control request",
			argv: func(flag string) []string {
				return []string{
					"curl", flag, "--ftp-account", token,
					"ftp://sink.example/",
				}
			},
			project: func(command CommandFact) bool {
				return len(StaticCurlFTPControlRequestComponents(command)) != 0
			},
		},
		{
			name: "HTTP proxy request",
			argv: func(flag string) []string {
				return []string{
					"curl", flag, "--proxy", "http://proxy.example",
					"--proxy-header", "X-Key: " + token,
					"http://origin.example/upload",
				}
			},
			project: func(command CommandFact) bool {
				return len(StaticCurlProxyTransmittedMetadata(command).
					ProxyRequestComponents) != 0
			},
		},
		{
			name: "SOCKS plaintext request body",
			argv: func(flag string) []string {
				return []string{
					"curl", flag, "--socks5", "proxy.example",
					"--data-raw", token, "http://origin.localhost/upload",
				}
			},
			project: func(command CommandFact) bool {
				return len(StaticCurlProxyUploadPayloads(command)) != 0
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			for _, flag := range []struct {
				value string
				want  bool
			}{
				{value: "--socks5-gssapi-nec"},
				{value: "--no-socks5-gssapi-nec", want: true},
			} {
				facts := Analyze(Input{Tool: "exec", Argv: test.argv(flag.value)})
				if len(facts.Commands) != 1 {
					t.Fatalf("%s commands = %#v", flag.value, facts.Commands)
				}
				if got := test.project(facts.Commands[0]); got != flag.want {
					t.Fatalf(
						"%s exact projection = %t, want %t; facts=%#v",
						flag.value,
						got,
						flag.want,
						facts,
					)
				}
			}
		})
	}
}

func TestStaticCurlFinalSOCKSGSSAPINECState(t *testing.T) {
	t.Parallel()

	const header = "X-Key: test-final-nec-state"
	for _, test := range []struct {
		name  string
		flags []string
		want  bool
	}{
		{
			name: "later disable restores portable setup",
			flags: []string{
				"--socks5-gssapi-nec", "--no-socks5-gssapi-nec",
			},
			want: true,
		},
		{
			name: "later enable keeps setup capability dependent",
			flags: []string{
				"--no-socks5-gssapi-nec", "--socks5-gssapi-nec",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			argv := []string{"curl"}
			argv = append(argv, test.flags...)
			argv = append(
				argv,
				"--header",
				header,
				"https://sink.example/upload",
			)
			facts := Analyze(Input{Tool: "exec", Argv: argv})
			if len(facts.Commands) != 1 {
				t.Fatalf("commands = %#v", facts.Commands)
			}
			got := len(StaticCurlTransmittedMetadata(facts.Commands[0]).Headers) != 0
			if got != test.want {
				t.Fatalf("exact projection = %t, want %t; facts=%#v", got, test.want, facts)
			}
		})
	}
}

func TestStaticCurlSOCKSGSSAPINECStateIsTransferGroupBound(t *testing.T) {
	t.Parallel()

	for _, flags := range [][]string{
		{"--socks5-gssapi-nec", "--no-socks5-gssapi-nec"},
		{"--no-socks5-gssapi-nec", "--socks5-gssapi-nec"},
	} {
		facts := Analyze(Input{Tool: "exec", Argv: []string{
			"curl", flags[0], "--ftp-account", "first",
			"ftp://first.example/", "--next", flags[1],
			"--ftp-account", "second", "ftp://second.example/",
		}})
		if len(facts.Commands) != 1 {
			t.Fatalf("%q commands = %#v", flags, facts.Commands)
		}
		if got := StaticCurlFTPControlRequestComponents(facts.Commands[0]); len(got) != 0 {
			t.Fatalf("%q FTP components = %#v, want none; facts=%#v", flags, got, facts)
		}
	}
}
