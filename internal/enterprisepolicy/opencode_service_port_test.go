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

// gas-ux-r1 GAP-0053: every account on one computer gets its own OpenCode
// service port, and keeps it.
func TestAssignOpenCodeServicePortsNeverShares(t *testing.T) {
	for _, tc := range []struct {
		name string
		ids  []int
		kept map[int]int
	}{
		{name: "two accounts", ids: []int{1001, 1002}},
		{name: "same id mod span", ids: []int{1001, 9001, 17001}},
		{name: "kept port another id would take", ids: []int{1001, 1002}, kept: map[int]int{1002: OpenCodeAccountPort(1001)}},
		{name: "kept ports collide", ids: []int{1001, 1002}, kept: map[int]int{1001: 25500, 1002: 25500}},
		{name: "kept user port 49374", ids: []int{1001, 1002, 1003}, kept: map[int]int{1003: OpenCodeDefaultServicePort}},
		{name: "many", ids: func() []int {
			ids := []int{}
			for i := 0; i < 300; i++ {
				ids = append(ids, 1000+i*8000/7)
			}
			return ids
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := AssignOpenCodeServicePorts(tc.ids, tc.kept)
			seen := map[int]int{}
			for _, id := range tc.ids {
				port, ok := got[id]
				if !ok || port <= 0 {
					t.Fatalf("id %d got no port: %v", id, got)
				}
				if other, dup := seen[port]; dup {
					t.Fatalf("ids %d and %d share port %d", other, id, port)
				}
				seen[port] = id
				if port == OpenCodeDefaultServicePort && tc.kept[id] != port {
					t.Fatalf("id %d was given the shared default", id)
				}
			}
			// Stable: a later pass with the result kept gives the same ports,
			// also with a new account added.
			again := AssignOpenCodeServicePorts(append(append([]int{}, tc.ids...), 999), got)
			for _, id := range tc.ids {
				if again[id] != got[id] {
					t.Fatalf("id %d moved from %d to %d", id, got[id], again[id])
				}
			}
		})
	}
	if got := AssignOpenCodeServicePorts([]int{1001, 1002}, nil); got[1001] != 25001 || got[1002] != 25002 {
		t.Fatalf("ports not derived from the uid: %v", got)
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
