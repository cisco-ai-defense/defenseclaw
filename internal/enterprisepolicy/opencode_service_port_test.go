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

func TestOpenCodeServicePortReadDistinguishesContentFromUnavailableFile(t *testing.T) {
	home := t.TempDir()
	path := OpenCodeServiceConfigPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"port":"invalid"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if port, err := ReadOpenCodeServicePortAsUser(home); port != 0 || err == nil {
		t.Fatalf("invalid content classification: port=%d err=%v", port, err)
	}
	if err := os.WriteFile(path, []byte(`{"port":25001}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if port, err := ReadOpenCodeServicePortAsUser(home); port != 25001 || err != nil {
		t.Fatalf("valid account file: port=%d err=%v", port, err)
	}
}

// gas-ux-r1 GAP-0053: ports derive from the account id (the class invariant
// over every sequence is TestOpenCodePortInvariantOverRandomSequences).
func TestPlanOpenCodeServicePortsDerivesFromTheUID(t *testing.T) {
	plan := PlanOpenCodeServicePorts([]int{1001, 1002, 9001}, nil, nil, true, nil, true, nil)
	if plan.Ports[1001] != 25001 || plan.Ports[1002] != 25002 || plan.Ports[9001] != 25003 {
		t.Fatalf("ports %v", plan.Ports)
	}
}

// The record wins: a port the file names is rewritten to the recorded one;
// OpenCode's other keys are kept; a link or a non-object file is left alone.
func TestSetOpenCodeServicePort(t *testing.T) {
	home := t.TempDir()
	path := OpenCodeServiceConfigPath(home)
	result, err := SetOpenCodeServicePort(home, 25001)
	if err != nil || !result.Changed || result.Port != 25001 {
		t.Fatalf("first write: %+v %v", result, err)
	}
	requireOpenCodeServiceFilePrivate(t, path)
	if result, err = SetOpenCodeServicePort(home, 25001); err != nil || result.Changed {
		t.Fatalf("second pass: %+v %v", result, err)
	}
	if err := os.WriteFile(path, []byte(`{"port":49375,"password":"p"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if result, err = SetOpenCodeServicePort(home, 25001); err != nil || !result.Changed || result.Previous != 49375 {
		t.Fatalf("a disagreeing file: %+v %v", result, err)
	}
	var doc map[string]any
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &doc); err != nil || doc["password"] != "p" || doc["port"] != float64(25001) {
		t.Fatalf("rewritten service.json: %s %v", data, err)
	}
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
		if result, err = SetOpenCodeServicePort(home, 25004); err == nil || result.Changed {
			t.Fatalf("%s: %+v %v", name, result, err)
		}
	}
}

func TestManagedWindowsOpenCodePortsKeepFullSIDReservations(t *testing.T) {
	const first, second, third = "S-1-5-21-100-200-300-1001", "S-1-5-21-400-500-600-1001", "S-1-5-21-700-800-900-1002"
	ids := map[string]uint64{first: 1001, second: 1001, third: 1002}
	plan := PlanOpenCodeServicePortsByAccountWithClaims(ids, []string{first, second}, nil, nil, nil, true, nil, true, nil)
	if plan.Ports[first] != 25001 || plan.Ports[second] != 25002 {
		t.Fatalf("same-RID accounts shared a port: %+v", plan)
	}
	next := PlanOpenCodeServicePortsByAccountWithClaims(ids, []string{second, third}, nil, plan.Record, nil, true, nil, true, nil)
	if next.Record[first] != 25001 || next.Ports[second] != 25002 || next.Ports[third] != 25003 {
		t.Fatalf("absent SID lost its reservation: %+v", next)
	}
	returned := PlanOpenCodeServicePortsByAccountWithClaims(ids, []string{first, second, third}, map[string]int{first: 49375}, next.Record, map[int]string{25001: third}, true, nil, true, nil)
	if returned.Ports[first] != 25001 || returned.Ports[second] != 25002 || returned.Ports[third] != 25003 {
		t.Fatalf("file or claim changed a recorded binding: %+v", returned)
	}
}

func TestManagedWindowsOpenCodePlanResolvesFileAndRecordConflicts(t *testing.T) {
	const first, second = "S-1-5-21-100-200-300-1001", "S-1-5-21-400-500-600-1002"
	ids := map[string]uint64{first: 1001, second: 1002}
	plan := PlanOpenCodeServicePortsByAccountWithClaims(ids, []string{first, second}, map[string]int{second: 25001}, map[string]int{first: 25001}, nil, true, nil, true, nil)
	if plan.Ports[first] != 25001 || plan.Ports[second] != 25002 || plan.Record[first] != 25001 || len(plan.Conflicts) != 1 || plan.Conflicts[0].Holder != first {
		t.Fatalf("record did not decide the file conflict: %+v", plan)
	}
	stable := PlanOpenCodeServicePortsByAccountWithClaims(ids, []string{first, second}, map[string]int{first: 26000, second: 25001}, plan.Record, nil, true, nil, true, nil)
	if stable.Ports[first] != 25001 || stable.Ports[second] != 25002 || stable.Record[first] != 25001 || stable.Record[second] != 25002 {
		t.Fatalf("manual edits moved a binding: %+v", stable)
	}
	contest := PlanOpenCodeServicePortsByAccountWithClaims(ids, []string{first, second}, map[string]int{first: 26000, second: 26000}, nil, nil, true, nil, true, nil)
	if contest.Ports[first] == 26000 || contest.Ports[second] == 26000 || len(contest.Contested[26000]) != 2 || contest.Ports[first] == contest.Ports[second] {
		t.Fatalf("contested port was granted: %+v", contest)
	}
	noRecord := PlanOpenCodeServicePortsByAccountWithClaims(ids, []string{first, second}, map[string]int{first: 26000}, nil, nil, false, nil, true, nil)
	if len(noRecord.Ports) != 0 || len(noRecord.Record) != 0 || len(noRecord.NoPort) != 2 {
		t.Fatalf("unreadable record made a binding: %+v", noRecord)
	}
}

func TestManagedWindowsOpenCodeRecordWinsAnOlderClaim(t *testing.T) {
	const first, second = "S-1-5-21-100-200-300-1001", "S-1-5-21-400-500-600-1002"
	ids := map[string]uint64{first: 1001, second: 1002}
	plan := PlanOpenCodeServicePortsByAccountWithClaims(ids, []string{first, second}, map[string]int{second: 25001}, map[string]int{first: 25001}, map[int]string{25001: second}, true, nil, true, nil)
	if plan.Record[first] != 25001 || plan.Ports[first] != 25001 || plan.Ports[second] != 25002 {
		t.Fatalf("claim displaced protected record: %+v", plan)
	}
	fresh := PlanOpenCodeServicePortsByAccountWithClaims(ids, []string{first, second}, nil, nil, map[int]string{25001: "other"}, true, nil, true, nil)
	if fresh.Ports[first] == 25001 || fresh.Ports[first] == fresh.Ports[second] {
		t.Fatalf("fresh allocation reused another account's claim: %+v", fresh)
	}
}

func TestReviewUnwritableFileCannotTakeDepartedAccountReservation(t *testing.T) {
	const current, departed = "S-1-5-21-100-200-300-1001", "S-1-5-21-400-500-600-1002"
	ids := map[string]uint64{current: 1001, departed: 1002}
	plan := PlanOpenCodeServicePortsByAccountWithClaims(ids, []string{current}, map[string]int{current: 25002}, map[string]int{departed: 25002}, nil, true, nil, true, nil)
	if plan.Record[departed] != 25002 || plan.Ports[current] != 25001 || plan.Record[current] != 25001 {
		t.Fatalf("departed account reservation moved: %+v", plan)
	}
}

func TestReadOpenCodeServicePortAsUserFollowsFinalLink(t *testing.T) {
	home := t.TempDir()
	path := OpenCodeServiceConfigPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, "linked-service.json")
	if err := os.WriteFile(target, []byte(`{"port":25002}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("service link unavailable: %v", err)
	}
	if port, err := ReadOpenCodeServicePortAsUser(home); err != nil || port != 25002 {
		t.Fatalf("account port through final link: %d %v", port, err)
	}
	if _, err := SetOpenCodeServicePort(home, 25001); err == nil {
		t.Fatal("account writer followed final link")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"port":25002}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if port, err := ReadOpenCodeServicePortAsUser(home); err != nil || port != 25002 {
		t.Fatalf("regular account file: %d %v", port, err)
	}
}

func TestManagedWindowsOpenCodeClaimCanRetryAfterFileRefusal(t *testing.T) {
	const first, second, third = "S-1-5-21-100-200-300-1001", "S-1-5-21-400-500-600-1002", "S-1-5-21-700-800-900-9001"
	ids := map[string]uint64{first: 1001, second: 1002, third: 9001}
	recorded := map[string]int{second: 25002}
	imports := map[string]int{first: 25002}
	claims := map[int]string{25001: first}
	for pass := 0; pass < 3; pass++ {
		plan := PlanOpenCodeServicePortsByAccountWithClaims(ids, []string{first, second}, imports, recorded, claims, true, nil, true, nil)
		if plan.Ports[first] != 25001 || plan.Ports[second] != 25002 || plan.Record[second] != 25002 {
			t.Fatalf("pass %d could not retry its own reserved port: %+v", pass, plan)
		}
	}
	plan := PlanOpenCodeServicePortsByAccountWithClaims(ids, []string{second, third}, nil, recorded, claims, true, nil, true, nil)
	if plan.Ports[third] == 25001 || plan.Record[second] != 25002 {
		t.Fatalf("another account reused the pending claim: %+v", plan)
	}
}

func TestManagedWindowsOpenCodeImportWindowKeepsContestedPortMarked(t *testing.T) {
	const first, second = "S-1-5-21-100-200-300-1001", "S-1-5-21-400-500-600-1002"
	ids := map[string]uint64{first: 1001, second: 1002}
	imports := map[string]int{first: 25002, second: 25002}
	initial := PlanOpenCodeServicePortsByAccountWithClaims(ids, []string{first, second}, imports, nil, nil, true, nil, true, nil)
	if len(initial.Contested[25002]) != 2 || initial.Ports[first] == 25002 || initial.Ports[second] == 25002 {
		t.Fatalf("contested import assigned: %+v", initial)
	}
	// The first account's file refused replacement, so its new binding was
	// not published. It may retry only a fresh port on the next pass.
	delete(initial.Record, first)
	next := PlanOpenCodeServicePortsByAccountWithClaims(ids, []string{first, second}, map[string]int{first: 25002}, initial.Record, nil, true, nil, false, map[int]bool{25002: true})
	if next.Ports[first] == 25002 || next.Record[first] == 25002 || next.Ports[second] != initial.Ports[second] {
		t.Fatalf("later pass reused a contested import: %+v", next)
	}
	// An ordinary unique import in the first window is still honored.
	ordinary := PlanOpenCodeServicePortsByAccountWithClaims(ids, []string{first}, map[string]int{first: 26600}, nil, nil, true, nil, true, nil)
	if ordinary.Ports[first] != 26600 {
		t.Fatalf("ordinary import was lost: %+v", ordinary)
	}
}
