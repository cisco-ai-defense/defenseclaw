// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package egressspec

import (
	"reflect"
	"testing"
)

// GAP-0405: a secret bound to a host that echoes requests is found, so the
// gateway can warn that the real value reaches the agent.
func TestEchoHostsCoveredGAP0405(t *testing.T) {
	for raw, want := range map[string][]string{
		"httpbin.org":     {"httpbin.org"},
		"HTTPBIN.org.":    {"httpbin.org"},
		"eu.httpbin.org":  {"httpbin.org", "*.httpbin.org"},
		"*.httpbin.org":   {"httpbin.org", "*.httpbin.org"},
		"a.b.httpbin.org": {"httpbin.org", "*.httpbin.org"}, // an echo entry covers every depth
		"x.pipedream.net": {"*.pipedream.net"},
		"pipedream.net":   nil, // "*.N" covers the names below N only
		// Request bins two labels under a listed entry (RV3 P2-1).
		"eo123.m.pipedream.net":   {"*.pipedream.net"},
		"*.m.pipedream.net":       {"*.pipedream.net"},
		"name.free.beeceptor.com": {"*.beeceptor.com"},
		"*.free.beeceptor.com":    {"*.beeceptor.com"},
		"a.echo.hoppscotch.io":    {"echo.hoppscotch.io"},
		"*.echo.hoppscotch.io":    {"echo.hoppscotch.io"},
		"*.hoppscotch.io":         {"echo.hoppscotch.io"},
		"*":                       EchoHosts,
		"api.github.com":          nil,
		"*.github.com":            nil,
		"notpostman-echo.com":     nil,
		"bedrock.amazonaws.com":   nil,
		"http://httpbin.org":      nil, // not a pattern: refused elsewhere
	} {
		if got := EchoHostsCoveredWith(raw, nil); !reflect.DeepEqual(got, want) {
			t.Errorf("EchoHostsCoveredWith(%q) = %v, want %v", raw, got, want)
		}
	}
	for _, e := range EchoHosts {
		if _, ok := ParsePattern(e); !ok {
			t.Errorf("echo host %q is not a pattern", e)
		}
	}
}
