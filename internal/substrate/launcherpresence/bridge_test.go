// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package launcherpresence

import (
	"os"
	"testing"
)

// One record per bridged MCP server process: kind mcp-bridge, the server's
// name and the child's PID, removed when the child ends.
func TestWriteBridgeRecord(t *testing.T) {
	dir := t.TempDir()
	remove, err := WriteBridge(dir, Record{Command: "run", Connector: "claudecode"}, 4242, "files")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(Path(dir, 4242))
	if err != nil {
		t.Fatal(err)
	}
	r, ok := Parse(b, 4242)
	if !ok || r.Kind != KindMCPBridge || r.Name != "files" || r.PID != 4242 || r.Command != "run" {
		t.Fatalf("record %+v ok=%v from %s", r, ok, b)
	}
	if _, ok := Parse(b, 4243); ok {
		t.Error("a record parsed for another PID")
	}
	remove()
	if _, err := os.Stat(Path(dir, 4242)); !os.IsNotExist(err) {
		t.Errorf("record left after remove: %v", err)
	}
}

func TestBridgeRecordValidity(t *testing.T) {
	base := Record{PID: 1, Command: "connect", Started: Record{}.Started.AddDate(2026, 0, 0)}
	good := base
	good.Kind, good.Name = KindMCPBridge, "my-srv_2"
	if !good.Valid() {
		t.Error("a good bridge record is invalid")
	}
	for name, mut := range map[string]func(*Record){
		"no name":            func(r *Record) { r.Name = "" },
		"bad name":           func(r *Record) { r.Name = "Bad Name" },
		"unknown kind":       func(r *Record) { r.Kind = "other" },
		"name on a launcher": func(r *Record) { r.Kind = "" },
	} {
		r := good
		mut(&r)
		if r.Valid() {
			t.Errorf("%s: record accepted: %+v", name, r)
		}
	}
	l := base
	if !l.Valid() {
		t.Error("a launcher record is invalid")
	}
}
