// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"testing"
)

func TestStaticCurlHTTPProxyChainRoute(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name              string
		argv              []string
		wantOK            bool
		wantPreproxyHost  string
		wantMainHost      string
		wantMainScheme    string
		wantPlaintext     bool
		wantAuthoritative bool
	}{
		{
			name: "SOCKS5h preproxy plus HTTP main proxy",
			argv: []string{
				"curl", "--preproxy", "socks5h://preproxy.example",
				"--proxy", "http://proxy.example", "http://origin.example/",
			},
			wantOK:            true,
			wantPreproxyHost:  "preproxy.example",
			wantMainHost:      "proxy.example",
			wantMainScheme:    "http",
			wantPlaintext:     true,
			wantAuthoritative: true,
		},
		{
			name: "SOCKS4a preproxy plus HTTPS main proxy",
			argv: []string{
				"curl", "--preproxy", "socks4a://preproxy.example",
				"--proxy", "https://proxy.example", "https://origin.example/",
			},
			wantOK:            true,
			wantPreproxyHost:  "preproxy.example",
			wantMainHost:      "proxy.example",
			wantMainScheme:    "https",
			wantAuthoritative: true,
		},
		{
			name: "locally resolving SOCKS5 plus HTTP main proxy",
			argv: []string{
				"curl", "--preproxy", "socks5://preproxy.example",
				"--proxy", "http://proxy.example", "http://origin.example/",
			},
			wantOK:            true,
			wantPreproxyHost:  "preproxy.example",
			wantMainHost:      "proxy.example",
			wantMainScheme:    "http",
			wantPlaintext:     true,
			wantAuthoritative: true,
		},
		{
			name: "matching noproxy bypasses the chain",
			argv: []string{
				"curl", "--preproxy", "socks5h://preproxy.example",
				"--proxy", "http://proxy.example", "--noproxy", "origin.example",
				"http://origin.example/",
			},
		},
		{
			name: "local preproxy remains a proved chain",
			argv: []string{
				"curl", "--preproxy", "socks5h://127.0.0.1",
				"--proxy", "http://proxy.example", "http://origin.example/",
			},
			wantOK:            true,
			wantPreproxyHost:  "127.0.0.1",
			wantMainHost:      "proxy.example",
			wantMainScheme:    "http",
			wantPlaintext:     true,
			wantAuthoritative: true,
		},
		{
			name: "mixed later transfer group closes the chain",
			argv: []string{
				"curl", "--preproxy", "socks5h://preproxy.example",
				"--proxy", "http://proxy.example", "http://origin.example/",
				"--next", "https://two.example/",
			},
		},
		{
			name: "config-derived route stays outside the exact lane",
			argv: []string{
				"curl", "--config", "curlrc", "--preproxy",
				"socks5h://preproxy.example", "--proxy", "http://proxy.example",
				"http://origin.example/",
			},
		},
		{
			name: "HTTP preproxy is not a SOCKS first hop",
			argv: []string{
				"curl", "--preproxy", "http://preproxy.example",
				"--proxy", "http://proxy.example", "http://origin.example/",
			},
		},
		{
			name: "SOCKS4 plus IPv4 main proxy",
			argv: []string{
				"curl", "--preproxy", "socks4://preproxy.example",
				"--proxy", "http://192.0.2.10", "http://origin.example/",
			},
			wantOK:            true,
			wantPreproxyHost:  "preproxy.example",
			wantMainHost:      "192.0.2.10",
			wantMainScheme:    "http",
			wantPlaintext:     true,
			wantAuthoritative: true,
		},
		{
			name: "SOCKS4 plus IPv6 main proxy is not exact",
			argv: []string{
				"curl", "--preproxy", "socks4://preproxy.example",
				"--proxy", "http://[2001:db8::10]", "http://origin.example/",
			},
		},
		{
			name: "header file is a pre-connect failure",
			argv: []string{
				"curl", "--preproxy", "socks5h://preproxy.example",
				"--proxy", "http://proxy.example", "--header", "@/missing",
				"http://origin.example/",
			},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{Tool: "exec", Argv: test.argv})
			if facts.Authoritative() != test.wantAuthoritative {
				t.Fatalf("Authoritative() = %t, want %t status=%s issues=%v",
					facts.Authoritative(), test.wantAuthoritative,
					facts.Parse.Status, facts.Parse.Issues)
			}
			if len(facts.Commands) != 1 {
				t.Fatalf("commands = %#v", facts.Commands)
			}
			chain, _, ok := staticCurlHTTPProxyChainRoute(facts.Commands[0])
			if ok != test.wantOK {
				t.Fatalf("chain ok = %t, want %t chain=%#v", ok, test.wantOK, chain)
			}
			if !test.wantOK {
				return
			}
			if chain.Preproxy.Scheme != "tcp" ||
				chain.Preproxy.Host != test.wantPreproxyHost ||
				chain.MainProxy.Scheme != test.wantMainScheme ||
				chain.MainProxy.Host != test.wantMainHost ||
				chain.DownstreamPlaintext != test.wantPlaintext {
				t.Fatalf("chain = %#v", chain)
			}
		})
	}
}

func TestStaticCurlPreproxyObserverComponents(t *testing.T) {
	t.Parallel()

	const token = "AKIA7Q2M9X4B6C8D3F5H"
	for _, test := range []struct {
		name         string
		argv         []string
		wantHost     string
		rejectHost   string
		wantRequest  string
		wantObserver string
	}{
		{
			name: "SOCKS5h observes HTTP main-proxy hostname",
			argv: []string{
				"curl", "--preproxy", "socks5h://preproxy.example",
				"--proxy", "http://proxy.example", "http://origin.example/",
			},
			wantHost:     "proxy.example",
			wantObserver: "preproxy.example",
		},
		{
			name: "plaintext HTTP origin header is visible to SOCKS5h",
			argv: []string{
				"curl", "--preproxy", "socks5h://preproxy.example",
				"--proxy", "http://proxy.example", "--header",
				"X-Key: " + token, "http://origin.example/",
			},
			wantHost:     "proxy.example",
			wantRequest:  "X-Key: " + token,
			wantObserver: "preproxy.example",
		},
		{
			name: "HTTPS main proxy hides origin header from SOCKS",
			argv: []string{
				"curl", "--preproxy", "socks5h://preproxy.example",
				"--proxy", "https://proxy.example", "--header",
				"X-Key: " + token, "http://origin.example/",
			},
			wantHost:     "proxy.example",
			wantObserver: "preproxy.example",
		},
		{
			name: "Host override does not copy origin hostname onto SOCKS5",
			argv: []string{
				"curl", "--preproxy", "socks5://preproxy.example",
				"--proxy", "http://proxy.example", "--header",
				"Host: other.example", "http://origin.example/",
			},
			rejectHost:   "origin.example",
			wantRequest:  "Host: other.example",
			wantObserver: "preproxy.example",
		},
		{
			name: "HTTPS main proxy hides origin SNI from SOCKS",
			argv: []string{
				"curl", "--preproxy", "socks5h://preproxy.example",
				"--proxy", "https://proxy.example", "https://origin.example/",
			},
			wantHost:     "proxy.example",
			rejectHost:   "origin.example",
			wantObserver: "preproxy.example",
		},
		{
			name: "HTTPS origin SNI is visible to SOCKS when main is HTTP",
			argv: []string{
				"curl", "--preproxy", "socks5://preproxy.example",
				"--proxy", "http://proxy.example", "https://origin.example/",
			},
			wantHost:     "origin.example",
			wantObserver: "preproxy.example",
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{Tool: "exec", Argv: test.argv})
			if len(facts.Commands) != 1 {
				t.Fatalf("commands = %#v", facts.Commands)
			}
			hosts := staticCurlPreproxyDestinationHostnameComponents(facts.Commands[0])
			requests := staticCurlPreproxyPlaintextHTTPRequestComponents(facts.Commands[0])
			if test.wantHost == "" && test.wantRequest == "" {
				if len(hosts) != 0 || len(requests) != 0 {
					t.Fatalf("hosts=%#v requests=%#v", hosts, requests)
				}
				return
			}
			if test.wantHost != "" {
				found := false
				for _, host := range hosts {
					if host.Value == test.wantHost &&
						host.Host == test.wantObserver && host.Scheme == "tcp" {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("hosts = %#v, want %q on %q", hosts, test.wantHost, test.wantObserver)
				}
			}
			if test.wantRequest != "" {
				found := false
				for _, request := range requests {
					if request.Value == test.wantRequest &&
						request.Host == test.wantObserver && request.Scheme == "tcp" {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("requests = %#v, want %q on %q", requests, test.wantRequest, test.wantObserver)
				}
			}
			if test.wantRequest == "" {
				for _, request := range requests {
					if request.Value == "X-Key: "+token {
						t.Fatalf("origin header leaked onto SOCKS: %#v", requests)
					}
				}
			}
			if test.rejectHost != "" {
				for _, host := range hosts {
					if host.Value == test.rejectHost {
						t.Fatalf("hostname %q leaked onto SOCKS: %#v", test.rejectHost, hosts)
					}
				}
			}
		})
	}
}

func TestStaticCurlHTTPProxyChainNetworks(t *testing.T) {
	t.Parallel()

	facts := Analyze(Input{
		Tool: "exec",
		Argv: []string{
			"curl", "--preproxy", "socks5h://preproxy.example",
			"--proxy", "http://proxy.example", "http://origin.example/",
		},
	})
	if !facts.Authoritative() || len(facts.Commands) != 1 {
		t.Fatalf("facts = %#v", facts)
	}
	if !hasNetworkHost(facts, NetworkConnect, "preproxy.example") ||
		!hasNetworkHost(facts, NetworkConnect, "proxy.example") ||
		!hasNetworkHost(facts, NetworkDownload, "origin.example") {
		t.Fatalf("chain networks = %#v", facts.Network)
	}
}

func TestStaticCurlPreproxyObservesPlaintextHTTPBody(t *testing.T) {
	t.Parallel()

	const token = "AKIA7Q2M9X4B6C8D3F5H"
	facts := Analyze(Input{
		Tool: "exec",
		Argv: []string{
			"curl", "--preproxy", "socks5h://preproxy.example",
			"--proxy", "http://proxy.example", "--data-raw", token,
			"http://origin.example/upload",
		},
	})
	if !facts.Authoritative() || len(facts.Commands) != 1 {
		t.Fatalf("facts = %#v", facts)
	}
	foundSOCKS := false
	foundMain := false
	for _, component := range StaticCurlProxyUploadPayloads(facts.Commands[0]) {
		if component.Value != token {
			continue
		}
		if component.Host == "preproxy.example" && component.Scheme == "tcp" {
			foundSOCKS = true
		}
		if component.Host == "proxy.example" && component.Scheme == "http" {
			foundMain = true
		}
	}
	if !foundSOCKS || !foundMain {
		t.Fatalf("plaintext body observers = %#v",
			StaticCurlProxyUploadPayloads(facts.Commands[0]))
	}

	encrypted := Analyze(Input{
		Tool: "exec",
		Argv: []string{
			"curl", "--preproxy", "socks5h://preproxy.example",
			"--proxy", "https://proxy.example", "--data-raw", token,
			"http://origin.example/upload",
		},
	})
	if !encrypted.Authoritative() || len(encrypted.Commands) != 1 {
		t.Fatalf("encrypted facts = %#v", encrypted)
	}
	foundMain = false
	for _, component := range StaticCurlProxyUploadPayloads(encrypted.Commands[0]) {
		if component.Value != token {
			continue
		}
		if component.Host == "preproxy.example" && component.Scheme == "tcp" {
			t.Fatalf("origin body leaked onto SOCKS through HTTPS main: %#v",
				component)
		}
		if component.Host == "proxy.example" && component.Scheme == "https" {
			foundMain = true
		}
	}
	if !foundMain {
		t.Fatalf("HTTPS main missing body: %#v",
			StaticCurlProxyUploadPayloads(encrypted.Commands[0]))
	}
}
