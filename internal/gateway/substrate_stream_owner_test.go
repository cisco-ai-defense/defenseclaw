// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"net/http"
	"testing"
)

// TestSubstrateAttachStreamNotYourAgent (B3 §3, S2B-5): a port forward or
// MCP bridge is its actor's own person's only. An administrator on another
// person's actor is refused 403 not_your_agent (the GAP-0435 attach rule)
// before any stream check; the owner gets past it to the stream checks.
func TestSubstrateAttachStreamNotYourAgent(t *testing.T) {
	f := newSubstrateFixture(t)
	f.api.substrateState().cfg.Relays = &dialRelay{addr: "127.0.0.1:1"} // never dialled
	for _, rest := range []string{"port/3000", "mcp/docs"} {
		path := "/api/v1/substrate/actors/eng-web/alice-1/attach/" + rest
		up := []string{"Upgrade", "websocket", "Connection", "Upgrade"}
		if rec := f.do(t, f.admin, http.MethodGet, path, "p-admin", "", up...); rec.Code != http.StatusForbidden || reasonOf(t, rec) != "not_your_agent" {
			t.Fatalf("admin %s on alice's actor: %d %s", rest, rec.Code, rec.Body)
		}
		// The fixture's template predates streams: the owner reaches the
		// stream checks and gets relay_too_old, not not_your_agent.
		if rec := f.do(t, f.admin, http.MethodGet, path, "p-alice", "", up...); rec.Code != http.StatusConflict || reasonOf(t, rec) != "relay_too_old" {
			t.Fatalf("alice %s on her own actor: %d %s", rest, rec.Code, rec.Body)
		}
	}
}
