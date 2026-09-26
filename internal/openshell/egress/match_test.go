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

package egress

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		in     string
		want   string
		isAddr bool
		bad    bool
	}{
		{in: "Example.COM.", want: "example.com"},
		{in: "  registry.npmjs.org ", want: "registry.npmjs.org"},
		{in: "under_score.example.com", want: "under_score.example.com"},
		{in: "xn--p1ai", want: "xn--p1ai"},
		{in: "8.8.8.8", want: "8.8.8.8", isAddr: true},
		{in: "[2001:DB8::1]", want: "2001:db8::1", isAddr: true},
		{in: "2001:db8::1", want: "2001:db8::1", isAddr: true},
		{in: "::ffff:127.0.0.1", want: "127.0.0.1", isAddr: true},
		{in: "[::ffff:10.0.0.1]", want: "10.0.0.1", isAddr: true},
		{in: "fe80::1%eth0", want: "fe80::1%eth0", isAddr: true},
		{in: "", bad: true},
		{in: ".", bad: true},
		{in: "a..b.com", bad: true},
		{in: ".example.com", bad: true},
		{in: "exa mple.com", bad: true},
		{in: "user@example.com", bad: true},
		{in: "example.com:443", bad: true},
		{in: "例え.jp", bad: true},
		{in: "127.1", bad: true},
		{in: "0x7f.1", bad: true},
		{in: "0x7f000001", bad: true},
		{in: "2130706433", bad: true},
		{in: "017700000001", bad: true},
		{in: "1.2.3.4.", bad: true},
		{in: "example.123", bad: true},
		{in: strings.Repeat("a", 64) + ".com", bad: true},
		{in: strings.Repeat("abcdefghi.", 26) + "com", bad: true},
	}
	for _, tt := range tests {
		got, addr, err := normalizeHost(tt.in)
		if tt.bad {
			if !errors.Is(err, ErrInvalidHost) {
				t.Errorf("normalizeHost(%q) = %q, %v; want ErrInvalidHost", tt.in, got, err)
			}
			continue
		}
		if err != nil || got != tt.want || addr.IsValid() != tt.isAddr {
			t.Errorf("normalizeHost(%q) = %q, addr=%v, %v; want %q addr=%v", tt.in, got, addr, err, tt.want, tt.isAddr)
		}
	}
}

func TestParsePattern(t *testing.T) {
	tests := []struct {
		in   string
		raw  string
		kind patternKind
		bad  bool
	}{
		{in: "Example.com", raw: "example.com", kind: patternExact},
		{in: "*.Ngrok-Free.App.", raw: "*.ngrok-free.app", kind: patternSuffix},
		{in: "8.8.8.8", raw: "8.8.8.8", kind: patternPrefix},
		{in: "[2001:db8::1]", raw: "2001:db8::1", kind: patternPrefix},
		{in: "10.1.2.3/8", raw: "10.0.0.0/8", kind: patternPrefix},
		{in: "::ffff:10.0.0.0/104", raw: "10.0.0.0/8", kind: patternPrefix},
		{in: "2001:db8::/32", raw: "2001:db8::/32", kind: patternPrefix},
		{in: "", bad: true},
		{in: "*", bad: true},
		{in: "*.", bad: true},
		{in: "**.example.com", bad: true},
		{in: "a.*.example.com", bad: true},
		{in: "example.*", bad: true},
		{in: "*.8.8.8.8", bad: true},
		{in: "10.0.0.0/33", bad: true},
		{in: "::ffff:10.0.0.0/64", bad: true},
		{in: "fe80::1%eth0", bad: true},
		{in: "bad host", bad: true},
	}
	for _, tt := range tests {
		p, err := parsePattern(tt.in)
		if tt.bad {
			if !errors.Is(err, ErrInvalidPattern) {
				t.Errorf("parsePattern(%q) = %+v, %v; want ErrInvalidPattern", tt.in, p, err)
			}
			continue
		}
		if err != nil || p.raw != tt.raw || p.kind != tt.kind {
			t.Errorf("parsePattern(%q) = %+v, %v; want raw %q kind %d", tt.in, p, err, tt.raw, tt.kind)
		}
	}
}

func TestHostSetMatch(t *testing.T) {
	set := newHostSet[string]()
	for _, raw := range []string{"*.example.com", "api.example.com", "*.eu.example.com", "8.8.0.0/16", "8.8.8.0/24", "2001:db8::/32"} {
		p, err := parsePattern(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !set.add(p, raw) {
			t.Fatalf("add(%q) reported a duplicate", raw)
		}
	}
	dup, _ := parsePattern("API.example.com")
	if set.add(dup, "dup") {
		t.Fatal("duplicate pattern was added")
	}
	if set.len() != 6 {
		t.Fatalf("len = %d, want 6", set.len())
	}

	tests := []struct {
		host string
		want string // "" = no match
	}{
		{"api.example.com", "api.example.com"},
		{"www.example.com", "*.example.com"},
		{"a.b.c.example.com", "*.example.com"},
		{"x.eu.example.com", "*.eu.example.com"},
		{"example.com", ""},
		{"notexample.com", ""},
		{"example.com.evil.net", ""},
		{"8.8.8.8", "8.8.8.0/24"},
		{"8.8.4.4", "8.8.0.0/16"},
		{"9.9.9.9", ""},
		{"2001:db8::5", "2001:db8::/32"},
		{"::ffff:8.8.8.8", "8.8.8.0/24"},
	}
	for _, tt := range tests {
		host, addr, err := normalizeHost(tt.host)
		if err != nil {
			t.Fatal(err)
		}
		item, ok := set.match(host, addr)
		if got := item.value; ok != (tt.want != "") || got != tt.want {
			t.Errorf("match(%q) = %q, %v; want %q", tt.host, got, ok, tt.want)
		}
	}
}

func TestPatternMatches(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "www.example.com", false},
		{"*.example.com", "www.example.com", true},
		{"*.example.com", "example.com", false},
		{"8.8.8.0/24", "8.8.8.8", true},
		{"8.8.8.0/24", "example.com", false},
		{"example.com", "8.8.8.8", false},
	}
	for _, c := range cases {
		p, err := parsePattern(c.pattern)
		if err != nil {
			t.Fatal(err)
		}
		host, addr, _ := normalizeHost(c.host)
		if got := p.matches(host, addr); got != c.want {
			t.Errorf("%q.matches(%q) = %v, want %v", c.pattern, c.host, got, c.want)
		}
	}
	zoned := netip.MustParseAddr("fe80::1%eth0")
	p, _ := parsePattern("fe80::/10")
	if p.matches(zoned.String(), zoned) {
		t.Error("zoned address matched a prefix")
	}
}
