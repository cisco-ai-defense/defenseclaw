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
