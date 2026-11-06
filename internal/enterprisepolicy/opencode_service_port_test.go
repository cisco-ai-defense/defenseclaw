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
	plan := PlanOpenCodeServicePorts([]int{1001, 1002, 9001}, nil, nil, true, nil)
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
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode: %v %v", info, err)
	}
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
