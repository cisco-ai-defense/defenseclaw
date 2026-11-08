// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"strings"
	"testing"
)

func TestRemovedConnectorsRoundTripAndStrictness(t *testing.T) {
	entries := []RemovedConnector{
		{Connector: "Cursor", SID: "S-1-5-21-1-2-3-1002", User: "bob", RemovedAt: "2026-11-08T18:00:00Z"},
		{Connector: "codex", SID: "S-1-5-21-1-2-3-1001", RemovedAt: "2026-11-08T18:00:00Z"},
	}
	data, err := MarshalRemovedConnectors(entries, "2026-11-08T18:00:01Z")
	if err != nil {
		t.Fatal(err)
	}
	if i, j := strings.Index(string(data), "S-1-5-21-1-2-3-1001"), strings.Index(string(data), "S-1-5-21-1-2-3-1002"); i < 0 || j < 0 || i > j {
		t.Fatalf("entries are not sorted by connector then SID:\n%s", data)
	}
	got, err := ParseRemovedConnectors(data)
	if err != nil || len(got) != 2 {
		t.Fatalf("round trip = %+v, %v", got, err)
	}
	for name, bad := range map[string]string{
		"unknown field": `{"version":1,"updated_at":"x","removed":[],"extra":1}`,
		"trailing":      `{"version":1,"updated_at":"x","removed":[]} {}`,
		"version":       `{"version":2,"updated_at":"x","removed":[]}`,
		"incomplete":    `{"version":1,"updated_at":"x","removed":[{"connector":"cursor","sid":"","removed_at":"t"}]}`,
		"not json":      `nope`,
	} {
		if _, err := ParseRemovedConnectors([]byte(bad)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := ParseRemovedConnectors([]byte(strings.Repeat(" ", RemovedConnectorsMaxBytes+1))); err == nil {
		t.Error("an oversized record was accepted")
	}
}

func TestRemovedConnectorsForSIDSkipsWhatIsBackOnTheRoster(t *testing.T) {
	entries := []RemovedConnector{
		{Connector: "cursor", SID: "s-1-5-21-1-2-3-1001", RemovedAt: "t"},
		{Connector: "CODEX", SID: "S-1-5-21-1-2-3-1001", RemovedAt: "t"},
		{Connector: "cursor", SID: "S-1-5-21-1-2-3-1002", RemovedAt: "t"},
		{Connector: "cursor", SID: "S-1-5-21-1-2-3-1001", RemovedAt: "t"},
	}
	got := RemovedConnectorsForSID(entries, "S-1-5-21-1-2-3-1001", nil)
	if strings.Join(got, ",") != "codex,cursor" {
		t.Fatalf("removed = %v, want codex,cursor", got)
	}
	got = RemovedConnectorsForSID(entries, "S-1-5-21-1-2-3-1001", func(name string) bool { return name == "cursor" })
	if strings.Join(got, ",") != "codex" {
		t.Fatalf("removed with cursor back on the roster = %v, want codex", got)
	}
	if got := RemovedConnectorsForSID(entries, "S-1-5-21-1-2-3-9999", nil); len(got) != 0 {
		t.Fatalf("another account's removed = %v", got)
	}
}
