// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestMCPBridgeAllowedCallLeavesARowGAP1104: an allowed judged call (a
// benign resources/read or tools/call) writes one substrate.mcp.allowed row
// naming its method and tool; a pass-through method (ping) writes none.
func TestMCPBridgeAllowedCallLeavesARowGAP1104(t *testing.T) {
	b := newTixgBridge(t, false)
	laptop, agent, resp := b.open(t)
	if laptop == nil {
		t.Fatalf("bridge refused: %+v", resp)
	}
	for _, msg := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///notes/a.txt"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_note","arguments":{"id":"a"}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"ping"}`,
	} {
		if err := agent.WriteMessage(websocket.BinaryMessage, []byte(msg)); err != nil {
			t.Fatal(err)
		}
		if m := tixgRead(t, laptop); m["id"] == nil {
			t.Fatalf("laptop got %v", m)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		b.mu.Lock()
		var allowed []string
		for _, a := range b.audits {
			if a["event"] == "substrate.mcp.allowed" {
				allowed = append(allowed, fmt.Sprint(a["method"], " ", a["tool"]))
			}
		}
		b.mu.Unlock()
		if len(allowed) == 2 && allowed[0] == "resources/read resources_read" && allowed[1] == "tools/call read_note" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("allowed rows %q, want resources/read and tools/call (none for ping)", allowed)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
