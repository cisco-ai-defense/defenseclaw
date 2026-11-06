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
	ids := map[string]uint64{first: 1001, second: 1001, third: 1002}
	plan := PlanOpenCodeServicePortsByAccountWithClaims(ids, []string{first, second}, nil, nil, nil, true)
	if plan.Ports[first] != 25001 || plan.Ports[second] != 25002 {
		t.Fatalf("same-RID accounts share or move a port: %+v", plan)
	}
	// A temporarily ineligible or unresolved SID keeps its record reservation.
	next := PlanOpenCodeServicePortsByAccountWithClaims(ids, []string{second, third}, nil, plan.Record, nil, true)
	if next.Record[first] != 25001 || next.Ports[second] != 25002 || next.Ports[third] != 25003 {
		t.Fatalf("recorded account lost its reservation: %+v", next)
	}
	returned := PlanOpenCodeServicePortsByAccountWithClaims(ids, []string{first, second, third}, nil, next.Record, nil, true)
	if returned.Ports[first] != 25001 || returned.Ports[second] != 25002 || returned.Ports[third] != 25003 {
		t.Fatalf("returning account moved ports: %+v", returned)
	}
	chosen := PlanOpenCodeServicePortsByAccountWithClaims(ids, []string{first, second}, map[string]int{first: 49375}, plan.Record, nil, true)
	if chosen.Ports[first] != 49375 || chosen.Ports[second] == 49375 {
		t.Fatalf("user port was not preserved: %+v", chosen)
	}
	claimed := PlanOpenCodeServicePortsByAccountWithClaims(ids, []string{first, second}, nil, nil, map[int]string{25001: third}, true)
	if claimed.Ports[first] == 25001 || claimed.Ports[second] == 25001 || claimed.Ports[first] == claimed.Ports[second] {
		t.Fatalf("per-user claim was reused: %+v", claimed)
	}
}

func TestManagedWindowsOpenCodePlanResolvesFileAndRecordConflicts(t *testing.T) {
	const (
		first  = "S-1-5-21-100-200-300-1001"
		second = "S-1-5-21-400-500-600-1002"
	)
	ids := map[string]uint64{first: 1001, second: 1002}
	eligible := []string{first, second}
	files := map[string]int{second: 25001}
	plan := PlanOpenCodeServicePortsByAccountWithClaims(ids, eligible, files, map[string]int{first: 25001}, nil, true)
	if plan.Ports[first] != 25001 || plan.Ports[second] != 25002 || plan.Replace[second] != 25001 ||
		len(plan.Conflicts) != 1 || plan.Conflicts[0].Holder != first || plan.Record[first] == plan.Record[second] {
		t.Fatalf("record/file conflict: %+v", plan)
	}
	files[second] = plan.Ports[second]
	again := PlanOpenCodeServicePortsByAccountWithClaims(ids, eligible, files, plan.Record, nil, true)
	if again.Ports[first] != 25001 || again.Ports[second] != 25002 || len(again.Conflicts) != 0 || len(again.Replace) != 0 {
		t.Fatalf("second pass moved or conflicted: %+v", again)
	}
	// Two files with the same port choose one holder and move the other.
	plan = PlanOpenCodeServicePortsByAccountWithClaims(ids, eligible, map[string]int{first: 26000, second: 26000}, nil, nil, true)
	if plan.Ports[first] != 26000 || plan.Ports[second] == 26000 || plan.Replace[second] != 26000 {
		t.Fatalf("file/file conflict: %+v", plan)
	}
	// A record read failure cannot allocate or move a port.
	plan = PlanOpenCodeServicePortsByAccountWithClaims(ids, eligible, map[string]int{first: 26000, second: 26000}, nil, nil, false)
	if len(plan.Replace) != 0 || plan.Ports[second] != 0 || len(plan.NoPort) != 1 {
		t.Fatalf("unreadable record made a new assignment: %+v", plan)
	}
}
