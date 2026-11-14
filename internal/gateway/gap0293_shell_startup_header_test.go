// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// F6: a per-user gateway judges whether the agent's shell startup can change
// the proved statement from the startup the hook client reports, not from its
// own service environment. The row is the entry-only touch of the fixture's
// symlink to the keys file: it allows while the entry proof holds and blocks
// when the startup can replace touch.
func TestGAP0293PerUserGatewayJudgesTheAgentsStartup(t *testing.T) {
	const command = "touch -h keylink"
	clean := hookpaths.ShellStartup{}.Encode()
	shadowed := hookpaths.ShellStartup{Functions: []string{"touch"}}.Encode()
	for _, tc := range []struct {
		id, header string
		gatewayEnv bool // the gateway's own environment exports a touch function
		want       string
	}{
		{"client-clean-gateway-clean", clean, false, "allow"},
		{"client-shadowed-gateway-clean", shadowed, false, "block"},
		{"client-clean-gateway-shadowed", clean, true, "allow"},
		{"older-client-gateway-clean", "", false, "allow"},
		{"older-client-gateway-shadowed", "", true, "block"},
		{"unreadable-header", "f=maybe", false, "block"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			f := newB36ManagedHookFixture(t)
			if tc.gatewayEnv {
				t.Setenv("BASH_FUNC_touch%%", "() {  :\n}")
			}
			payload := f.payload(t, command)
			var calls []*hookCall
			for _, call := range everyMode(tc.id, payload, f.clientHeader(t, payload)) {
				if !call.managed {
					call.startup = tc.header
					calls = append(calls, call)
				}
			}
			f.answerAll(t, calls)
			for _, call := range calls {
				if call.verdict != tc.want {
					t.Errorf("%s: got %s, want %s", call.name, call.verdict, tc.want)
				}
			}
		})
	}
}

func TestShellStartupHeaderRoundTrip(t *testing.T) {
	for _, s := range []hookpaths.ShellStartup{
		{}, {File: true}, {Other: true}, {Functions: []string{"mv", "touch"}}, {File: true, Other: true, Functions: []string{"command_not_found_handle"}},
	} {
		got, ok := hookpaths.DecodeShellStartup(s.Encode())
		if !ok || got.File != s.File || got.Other != s.Other || len(got.Functions) != len(s.Functions) {
			t.Errorf("%q: decoded %+v ok=%t", s.Encode(), got, ok)
		}
	}
	for _, bad := range []string{"", "f=1", "f=2;o=0;fn=", "f=0;o=0;fn=rm", "f=0;o=0;fn=touch;x=1"} {
		if _, ok := hookpaths.DecodeShellStartup(bad); ok {
			t.Errorf("%q decoded", bad)
		}
	}
}
