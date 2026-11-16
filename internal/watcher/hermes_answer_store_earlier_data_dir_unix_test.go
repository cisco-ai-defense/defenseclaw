// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package watcher

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// GAP-0945: the answer cache a gateway rewrites in a folder `config set
// data_dir` moved away from is recorded in the list in the install home in
// the step that writes it, so uninstall removes the rewrite and keeps an edit.
func TestAnAnswerStoreRewriteInAnEarlierDataFolderIsRecordedForUninstall(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	t.Setenv("HOME", root)
	home := filepath.Join(root, ".defenseclaw")
	earlier := filepath.Join(root, "earlier")
	for _, dir := range []string{home, earlier} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	list, err := json.Marshal(map[string]any{"folders": []string{earlier}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "previous-data-dirs.json"), list, 0o600); err != nil {
		t.Fatal(err)
	}

	store := newHermesAnswerStore(earlier)
	if err := store.remember("a", []string{"plugins/a/__init__.py"}); err != nil {
		t.Fatal(err)
	}

	written, err := os.ReadFile(filepath.Join(earlier, hermesStoreFileName))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(written)
	var recorded struct {
		Backups map[string]map[string]string `json:"backups"`
	}
	body, err := os.ReadFile(filepath.Join(home, "previous-data-dirs.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &recorded); err != nil {
		t.Fatal(err)
	}
	if got := recorded.Backups[earlier][hermesStoreFileName]; got != hex.EncodeToString(sum[:]) {
		t.Fatalf("recorded %q, want the digest of the file written", got)
	}
}

func TestAnAnswerStoreInTheCurrentDataFolderLeavesTheListAlone(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	t.Setenv("HOME", root)
	home := filepath.Join(root, ".defenseclaw")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	list := []byte(`{"folders":["` + filepath.Join(root, "earlier") + `"]}`)
	listPath := filepath.Join(home, "previous-data-dirs.json")
	if err := os.WriteFile(listPath, list, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := newHermesAnswerStore(home).remember("a", []string{"x"}); err != nil {
		t.Fatal(err)
	}

	if after, _ := os.ReadFile(listPath); string(after) != string(list) {
		t.Fatalf("the list changed: %s", after)
	}
}
