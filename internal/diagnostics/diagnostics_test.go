// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package diagnostics

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withRegistry(t *testing.T, names ...string) {
	t.Helper()
	registryMu.Lock()
	saved := registry
	registry = map[string]string{}
	for _, name := range names {
		registry[name] = "test"
	}
	registryMu.Unlock()
	t.Cleanup(func() {
		registryMu.Lock()
		registry = saved
		registryMu.Unlock()
	})
}

func TestRegisterRejectsInvalidNames(t *testing.T) {
	withRegistry(t)
	for _, name := range []string{"", "Upper.json", "a.txt", "../x.json", "a/b.json", "a-b.json", ".json", "x.json.tmp"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Register(%q) did not panic", name)
				}
			}()
			Register(name, "owner")
		}()
	}
}

func TestRegisterRejectsDuplicatesAndMissingOwner(t *testing.T) {
	withRegistry(t)
	Register("one.json", "owner")
	for _, call := range []func(){
		func() { Register("one.json", "other") },
		func() { Register("two.json", " ") },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("Register did not panic")
				}
			}()
			call()
		}()
	}
	if got := Registered(); len(got) != 1 || got[0] != "one.json" {
		t.Fatalf("Registered() = %v", got)
	}
}

func TestWriteJSONRefusesUnregisteredName(t *testing.T) {
	withRegistry(t)
	err := WriteJSON(t.TempDir(), "nobody.json", map[string]int{"a": 1})
	if !errors.Is(err, ErrUnregistered) {
		t.Fatalf("err = %v, want ErrUnregistered", err)
	}
}

func TestWriteJSONReplacesAtomicallyAndLeavesNoTemp(t *testing.T) {
	withRegistry(t, "state.json")
	dataDir := t.TempDir()
	for _, value := range []int{1, 2} {
		if err := WriteJSON(dataDir, "state.json", map[string]int{"value": value}); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(Path(dataDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]int
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded["value"] != 2 {
		t.Fatalf("decoded = %v, err = %v", decoded, err)
	}
	entries, err := os.ReadDir(Dir(dataDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "state.json" {
		names := []string{}
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("folder holds %v, want only state.json", names)
	}
}

func TestWriteJSONPerFileLimit(t *testing.T) {
	withRegistry(t, "big.json")
	dataDir := t.TempDir()
	if err := WriteJSON(dataDir, "big.json", map[string]string{"v": "small"}); err != nil {
		t.Fatal(err)
	}
	err := WriteJSON(dataDir, "big.json", map[string]string{"v": strings.Repeat("x", MaxFileBytes)})
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("err = %v, want ErrLimit", err)
	}
	raw, readErr := os.ReadFile(Path(dataDir, "big.json"))
	if readErr != nil || !strings.Contains(string(raw), "small") {
		t.Fatalf("existing file changed: %q, %v", raw, readErr)
	}
}

func TestWriteJSONFolderLimits(t *testing.T) {
	withRegistry(t, "new.json")
	dataDir := t.TempDir()
	if err := os.MkdirAll(Dir(dataDir), 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxFiles; i++ {
		name := filepath.Join(Dir(dataDir), "f"+string(rune('a'+i%26))+string(rune('a'+i/26))+".json")
		if err := os.WriteFile(name, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := WriteJSON(dataDir, "new.json", map[string]int{}); !errors.Is(err, ErrLimit) {
		t.Fatalf("file-count limit: err = %v, want ErrLimit", err)
	}

	dataDir = t.TempDir()
	if err := os.MkdirAll(Dir(dataDir), 0o700); err != nil {
		t.Fatal(err)
	}
	filler := make([]byte, MaxTotalBytes-16)
	if err := os.WriteFile(filepath.Join(Dir(dataDir), "filler.json"), filler, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(dataDir, "new.json", map[string]string{"v": "0123456789abcdef"}); !errors.Is(err, ErrLimit) {
		t.Fatalf("byte limit: err = %v, want ErrLimit", err)
	}
	// Files that don't match *.json don't count against the budget.
	if err := os.Remove(filepath.Join(Dir(dataDir), "filler.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(Dir(dataDir), "filler.bin"), filler, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(dataDir, "new.json", map[string]string{"v": "ok"}); err != nil {
		t.Fatalf("non-json files counted: %v", err)
	}
}

func TestWriteJSONRequiresDataDir(t *testing.T) {
	withRegistry(t, "state.json")
	if err := WriteJSON("  ", "state.json", 1); err == nil {
		t.Fatal("empty data dir accepted")
	}
}
