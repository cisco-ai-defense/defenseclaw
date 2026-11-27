// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"
)

// An MCP server the running watcher has not listed yet is not sent as a
// complete collection with no tools: the advertised collection is partial
// until its first listing, for a bounded window, so a server that is never
// scanned cannot hold back the Secure Client daily bundle. With no listing
// source (gateway.watcher.enabled off) the collection is sent as before
// (rel-1-0-10:GAP-1857).
func TestGAP1857UnlistedServerIsPartialWhileItsFirstListingIsDue(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	m := &mcpToolInventory{now: func() time.Time { return now }}
	docs := endpointInventoryComponent{id: "mcp-docs", agentConnector: "claudecode", itemName: "docs"}
	servers := []endpointInventoryComponent{docs}
	m.refreshParents(servers)
	partial := func() bool {
		t.Helper()
		_, p := m.components(servers, false, "advertised")
		return p
	}
	if partial() {
		t.Fatal("watcher off: an unlisted server made the collection partial; want the rel behaviour (complete)")
	}
	m.setListingSource(true)
	if !partial() {
		t.Fatal("watcher running: a server with no listing yet was sent as a complete collection with no tools")
	}
	if _, p := m.components(servers, false, "observed"); p {
		t.Fatal("the observed collection must not wait for a listing")
	}
	m.recordAdvertised("claudecode", "docs", []string{}, now)
	if partial() {
		t.Fatal("an authoritative empty listing must make the collection complete")
	}
	// A server added later gets its own window from when it appeared.
	now = now.Add(10 * time.Minute)
	search := endpointInventoryComponent{id: "mcp-search", agentConnector: "claudecode", itemName: "search"}
	servers = append(servers, search)
	m.refreshParents(servers)
	if !partial() {
		t.Fatal("a newly added unlisted server must make the collection partial")
	}
	now = now.Add(mcpToolFirstListingWindow)
	if partial() {
		t.Fatal("a server never listed must not keep the collection partial past the window (Secure Client daily bundle)")
	}
	now = now.Add(-time.Minute)
	m.setListingSource(false)
	if partial() {
		t.Fatal("with the watcher stopped nothing lists the server; the collection is sent as before")
	}
}
