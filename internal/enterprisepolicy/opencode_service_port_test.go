// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// gas-ux-r1 GAP-0053: ports derive from the account id (the class invariant
// over every sequence is TestOpenCodePortInvariantOverRandomSequences).
func TestPlanOpenCodeServicePortsDerivesFromTheUID(t *testing.T) {
	plan := PlanOpenCodeServicePorts([]int{1001, 1002, 9001}, nil, nil, true)
	if plan.Ports[1001] != 25001 || plan.Ports[1002] != 25002 || plan.Ports[9001] != 25003 {
		t.Fatalf("ports %v", plan.Ports)
	}
}

func TestEnsureOpenCodeServicePortKeepsAndWrites(t *testing.T) {
	home := t.TempDir()
	path := OpenCodeServiceConfigPath(home)
	// No file: created at 0600 with the port.
	result, err := EnsureOpenCodeServicePort(home, 25001)
	if err != nil || !result.Changed || result.Port != 25001 {
		t.Fatalf("first write: %+v %v", result, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("service.json mode: %v %v", info, err)
	}
	// Second pass: kept, nothing written.
	if result, err = EnsureOpenCodeServicePort(home, 26000); err != nil || result.Changed || result.Port != 25001 {
		t.Fatalf("second pass: %+v %v", result, err)
	}
	// OpenCode's password is kept when the port is added.
	if err := os.WriteFile(path, []byte(`{"password":"p"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if result, err = EnsureOpenCodeServicePort(home, 25002); err != nil || !result.Changed {
		t.Fatalf("add to existing: %+v %v", result, err)
	}
	var doc map[string]any
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &doc); err != nil || doc["password"] != "p" || doc["port"] != float64(25002) {
		t.Fatalf("merged service.json: %s %v", data, err)
	}
	// A port the user set is theirs.
	if err := os.WriteFile(path, []byte(`{"port":49375,"password":"p"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if result, err = EnsureOpenCodeServicePort(home, 25003); err != nil || result.Changed || result.Port != 49375 {
		t.Fatalf("user port: %+v %v", result, err)
	}
	// A link or a file that is not a JSON object is left alone.
	for name, setup := range map[string]func(){
		"not json": func() { _ = os.WriteFile(path, []byte("[1]"), 0o600) },
		"link": func() {
			_ = os.Remove(path)
			target := filepath.Join(home, "elsewhere.json")
			_ = os.WriteFile(target, []byte("{}"), 0o600)
			_ = os.Symlink(target, path)
		},
	} {
		setup()
		if result, err = EnsureOpenCodeServicePort(home, 25004); err == nil || result.Changed {
			t.Fatalf("%s: %+v %v", name, result, err)
		}
	}
}

func TestManagedWindowsOpenCodePortsKeepFullSIDReservations(t *testing.T) {
	const (
		first  = "S-1-5-21-100-200-300-1001"
		second = "S-1-5-21-400-500-600-1001"
		third  = "S-1-5-21-700-800-900-1002"
	)
	ids := map[string]uint64{first: 1001, second: 1001}
	ports := AssignOpenCodeServicePortsByAccountWithClaims(ids, nil, nil)
	if ports[first] != 25001 || ports[second] != 25002 {
		t.Fatalf("same-RID accounts share or move a port: %v", ports)
	}
	// The first account becomes ineligible, possibly with its SID unresolved.
	// Its record remains in ids and keeps its port reserved for a newcomer.
	ids[third] = 1002
	next := AssignOpenCodeServicePortsByAccountWithClaims(ids, ports, nil)
	if next[first] != ports[first] || next[second] != ports[second] || next[third] == ports[first] || next[third] == ports[second] {
		t.Fatalf("returning account lost its reservation: before=%v after=%v", ports, next)
	}
	if again := AssignOpenCodeServicePortsByAccountWithClaims(ids, next, nil); again[first] != next[first] || again[second] != next[second] || again[third] != next[third] {
		t.Fatalf("repeated ensure moved a port: %v -> %v", next, again)
	}
	// A user-chosen port is kept and excluded from automatic assignments.
	chosen := AssignOpenCodeServicePortsByAccountWithClaims(ids, map[string]int{first: 49375}, nil)
	if chosen[first] != 49375 || chosen[second] == 49375 || chosen[third] == 49375 {
		t.Fatalf("user-chosen port was not preserved: %v", chosen)
	}
	claimed := AssignOpenCodeServicePortsByAccountWithClaims(ids, nil, map[int]string{25001: "S-1-5-21-10-20-30-1001"})
	if claimed[first] == 25001 || claimed[second] == 25001 || claimed[first] == claimed[second] {
		t.Fatalf("per-user claim was reused by another SID: %v", claimed)
	}
	reserved := AssignOpenCodeServicePortsByAccountWithClaims(ids, ports, map[int]string{ports[first]: "!"})
	if reserved[first] != ports[first] || reserved[second] != ports[second] {
		t.Fatalf("an untrusted claim moved a recorded account: %v -> %v", ports, reserved)
	}
}
