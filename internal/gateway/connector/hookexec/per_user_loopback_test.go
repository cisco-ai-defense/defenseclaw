// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// perUserLoopbackVector is one row of the address table shared with the
// shell preflight's defenseclaw_loopback_targets test.
type perUserLoopbackVector struct {
	Addr    string   `json:"addr"`
	Targets []string `json:"targets"`
	Port    uint16   `json:"port"`
}

func TestPerUserLoopbackTargetsMatchTheSharedTable(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "per_user_loopback_addrs.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors []perUserLoopbackVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors {
		targets, err := perUserLoopbackTargets(vector.Addr)
		if len(vector.Targets) == 0 {
			if err == nil {
				t.Errorf("%q: accepted as %v, want refused", vector.Addr, targets)
			}
			continue
		}
		if err != nil || len(targets) != len(vector.Targets) {
			t.Errorf("%q: targets=%v err=%v, want %v", vector.Addr, targets, err, vector.Targets)
			continue
		}
		for index, target := range targets {
			if target.Addr().String() != vector.Targets[index] || target.Port() != vector.Port {
				t.Errorf("%q: target %d = %s, want %s port %d", vector.Addr, index, target, vector.Targets[index], vector.Port)
			}
		}
	}
}
