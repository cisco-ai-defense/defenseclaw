// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// GAP-1140: a Cursor hooks.json the operator edited after Setup is cleaned
// surgically at teardown. The operator's empty hooks object, there before
// Setup, stays with the operator's edit.
func TestCursorSurgicalTeardownKeepsTheOperatorsEmptyHooksObject(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".cursor", "hooks.json")
	prev := CursorHooksPathOverride
	CursorHooksPathOverride = cfgPath
	t.Cleanup(func() { CursorHooksPathOverride = prev })
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte("{\n  \"version\": 1,\n  \"hooks\": {}\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conn := NewCursorConnector()
	opts := SetupOpts{DataDir: filepath.Join(dir, "dc"), APIAddr: "127.0.0.1:18970", APIToken: "tok-test", HookFailMode: "closed"}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	cfg, err := readJSONObject(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg["operator"] = true // an edit after Setup: teardown cannot restore the bytes
	if err := writeJSONObject(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	after, err := readJSONObject(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	hooks, ok := after["hooks"].(map[string]interface{})
	if !ok || len(hooks) != 0 || after["operator"] != true {
		t.Fatalf("after a surgical teardown the file is %v, want the empty hooks object and the operator's edit", after)
	}
}

// A file whose hooks key was DefenseClaw's alone (none before Setup) loses
// it at teardown, and an empty list the operator had is kept as a list.
func TestKeepPristineEmptyHooksOnlyPutsBackTheOperatorsKey(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "dc")
	cases := []struct {
		name, pristine string
		want           interface{}
	}{
		{"no hooks before setup", `{"version":1}`, nil},
		{"operator hooks before setup", `{"hooks":{"stop":[]}}`, nil},
		{"empty list before setup", `{"hooks":[]}`, []interface{}{}},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".json")
			if err := os.WriteFile(path, []byte(tc.pristine), 0o600); err != nil {
				t.Fatal(err)
			}
			logical := "case" + string(rune('a'+i))
			if err := captureManagedFileBackup(dataDir, "kiro", logical, path); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(`{"name":"agent"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := keepPristineEmptyHooks(dataDir, "kiro", logical, path); err != nil {
				t.Fatal(err)
			}
			after, err := readJSONObject(path)
			if err != nil {
				t.Fatal(err)
			}
			got, present := after["hooks"]
			if tc.want == nil && present {
				t.Fatalf("hooks %v put back, want none", got)
			}
			if list, ok := got.([]interface{}); tc.want != nil && (!ok || len(list) != 0) {
				t.Fatalf("hooks = %#v, want an empty list", got)
			}
		})
	}
}
