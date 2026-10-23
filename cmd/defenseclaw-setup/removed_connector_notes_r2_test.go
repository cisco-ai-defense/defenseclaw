// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// until 1.1: an OpenHands teardown's leftovers are shown under the
// connector's name, in the form the Python handoff reads (review fixes,
// G-deadcode loop round 2).
func TestRemovedConnectorNotesNameOpenHands(t *testing.T) {
	resetRemovedConnectorNotes(t)
	recordRemovedConnectorLeftovers("openhands", []byte(
		`{"connector":"openhands","action":"teardown","ok":true,"leftovers":[{"path":"C:\\Users\\u\\.openhands\\hooks.json","what":"w","step":"s"}]}`+"\n"))
	got := removedConnectorNotesText()
	want := "OpenHands support was removed in DefenseClaw 1.0.4. Left for you to remove by hand:\r\n" +
		`  - C:\Users\u\.openhands\hooks.json: w. To remove: s.` + "\r\n"
	if got != want {
		t.Fatalf("notes = %q, want %q", got, want)
	}
	if strings.Contains(got, "openhands support") {
		t.Fatalf("notes use the connector ID as its name: %q", got)
	}
}
