// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// An operator's Kiro hook file {"hooks":[]}, there before Setup and only
// reformatted since, is cleaned surgically at teardown (its bytes no longer
// match) and stays, with its empty hooks list. Nothing in the file tells it
// from one DefenseClaw wrote; the copy Setup captured does.
func TestKiroSurgicalTeardownKeepsTheOperatorsEmptyHookFile(t *testing.T) {
	home := t.TempDir()
	dataDir := t.TempDir()
	t.Cleanup(func() { KiroHomeOverride = "" })
	KiroHomeOverride = home
	path := filepath.Join(home, "hooks", kiroManagedHooksName)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{\"hooks\": []}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "tok-test", HookFailMode: "closed"}
	conn := NewKiroConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(body, &cfg); err != nil {
		t.Fatal(err)
	}
	reformatted, err := json.MarshalIndent(cfg, "", "\t") // the operator's editor, same content
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, reformatted, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean: %v", err)
	}
	after, err := readJSONObject(path)
	if err != nil {
		t.Fatalf("teardown removed the operator's hook file: %v", err)
	}
	if hooks, ok := after["hooks"].([]interface{}); !ok || len(hooks) != 0 {
		t.Fatalf("after teardown the operator's file is %v, want its empty hooks list", after)
	}
}
