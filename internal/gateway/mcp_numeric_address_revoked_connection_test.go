// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
)

// A loopback address written as a shorthand the resolvers read (127.1, 0,
// 2130706433, 0x7f000001, 0177.0.0.1) is the address the scanner refuses, so a
// managed gateway holds it like the plain spelling: after the allow of A is
// withdrawn and only a replacement is allowed, the live connection of A stays
// refused in its session and a new session uses the replacement.
func TestManagedNumericAddressRevokedConnectionStaysHeldInTheSession(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed Windows uses enumerator records")
	}
	for _, host := range []string{"127.0.0.1", "127.1", "0", "2130706433", "0x7f000001", "0177.0.0.1"} {
		t.Run(host, func(t *testing.T) {
			h := newReportedMCPHarness()
			h.watcherLikeStatus()
			a := assetfacts.MCPServer{Name: "vgr", URL: "http://" + host + ":18795/mcp"}
			b := assetfacts.MCPServer{Name: "vgr", URL: "http://127.0.0.1:18796/mcp"}
			h.allowOnly(a)
			wantMCPAllow(t, "allow A, the first call", h.callInSession(t, "s1", a))
			h.allowOnly()
			wantMCPBlock(t, "withdraw allow A", h.callInSession(t, "s1", b))
			h.allowOnly(b)
			wantMCPBlock(t, "allow B does not admit live A", h.callInSession(t, "s1", b))
			wantMCPAllow(t, "new session uses B", h.callInSession(t, "s2", b))
		})
	}
}
