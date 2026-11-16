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

package connector

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// GAP-0945: a gateway that keeps running in a folder `config set data_dir`
// moved away from rewrites the records uninstall removes by digest. The
// write records its digest in the list in the install home, in the step that
// makes it, so uninstall removes the gateway own rewrite and keeps an edit.

type earlierDataDirList struct {
	Folders []string                     `json:"folders"`
	Backups map[string]map[string]string `json:"backups"`
	Other   string                       `json:"other,omitempty"`
}

func readEarlierDataDirList(t *testing.T, home string) earlierDataDirList {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(home, hermesEarlierDataDirsFile))
	if err != nil {
		t.Fatal(err)
	}
	var list earlierDataDirList
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	return list
}

func writeEarlierDataDirListWith(t *testing.T, home string, list earlierDataDirList) {
	t.Helper()
	body, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, hermesEarlierDataDirsFile), append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAWriteBelowAnEarlierDataFolderIsRecordedInTheSameStep(t *testing.T) {
	f := newMovedStoreFixture(t)
	earlier := filepath.Join(f.root, "earlier")
	other := filepath.Join(f.root, "other")
	writeEarlierDataDirListWith(t, f.home, earlierDataDirList{
		Folders: []string{earlier, other},
		Backups: map[string]map[string]string{
			earlier: {"codex_config_backup.json": sha256Hex([]byte("old"))},
			other:   {"codex_config_backup.json": sha256Hex([]byte("kept"))},
		},
		Other: "unrelated",
	})

	for name, body := range map[string][]byte{
		"codex_config_backup.json":       []byte(`{"had_hooks_key":true}`),
		"hermes-plugin-entrypoints.json": []byte(`{"answers":{}}`),
		"hooks/.hookcfg.hermes":          []byte("DEFENSECLAW_CONNECTOR=hermes\nDEFENSECLAW_FAIL_MODE=open\n"),
	} {
		if err := atomicWriteFile(filepath.Join(earlier, filepath.FromSlash(name)), body, 0o600); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}

	got := readEarlierDataDirList(t, f.home)
	if got.Other != "unrelated" || len(got.Folders) != 2 {
		t.Fatalf("the rest of the list changed: %+v", got)
	}
	want := map[string]string{
		"codex_config_backup.json":       sha256Hex([]byte(`{"had_hooks_key":true}`)),
		"hermes-plugin-entrypoints.json": sha256Hex([]byte(`{"answers":{}}`)),
		"hooks/.hookcfg.hermes":          sha256Hex([]byte("DEFENSECLAW_CONNECTOR=hermes\nDEFENSECLAW_FAIL_MODE=open\n")),
	}
	for name, digest := range want {
		if got.Backups[earlier][name] != digest {
			t.Errorf("%s: recorded %q, want %q", name, got.Backups[earlier][name], digest)
		}
	}
	if got.Backups[other]["codex_config_backup.json"] != sha256Hex([]byte("kept")) {
		t.Errorf("another folder digest changed: %v", got.Backups[other])
	}
}

func TestAWriteBelowAFolderTheListDoesNotNameIsNotRecorded(t *testing.T) {
	f := newMovedStoreFixture(t)
	earlier := filepath.Join(f.root, "earlier")
	writeEarlierDataDirListWith(t, f.home, earlierDataDirList{Folders: []string{earlier}})
	before, err := os.ReadFile(filepath.Join(f.home, hermesEarlierDataDirsFile))
	if err != nil {
		t.Fatal(err)
	}

	current := filepath.Join(f.root, "current")
	for _, path := range []string{
		filepath.Join(current, "codex_config_backup.json"),
		filepath.Join(f.home, "hermes-plugin-entrypoints.json"),
		filepath.Join(earlier, "notes.json"),
	} {
		if err := atomicWriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	after, err := os.ReadFile(filepath.Join(f.home, hermesEarlierDataDirsFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("the list changed:\n%s", after)
	}
}

func TestAListOpenToOtherAccountsIsNeverRewrittenByARecord(t *testing.T) {
	f := newMovedStoreFixture(t)
	earlier := filepath.Join(f.root, "earlier")
	writeEarlierDataDirListWith(t, f.home, earlierDataDirList{Folders: []string{earlier}})
	list := filepath.Join(f.home, hermesEarlierDataDirsFile)
	if err := os.Chmod(list, 0o644); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(list)

	if err := atomicWriteFile(filepath.Join(earlier, "codex_config_backup.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	if after, _ := os.ReadFile(list); !bytes.Equal(before, after) {
		t.Fatalf("a list other accounts can write was changed:\n%s", after)
	}
}

func TestTheLifecycleLockCreatedInAnEarlierDataFolderIsRecorded(t *testing.T) {
	f := newMovedStoreFixture(t)
	earlier := filepath.Join(f.root, "earlier")
	if err := os.MkdirAll(earlier, 0o700); err != nil {
		t.Fatal(err)
	}
	writeEarlierDataDirListWith(t, f.home, earlierDataDirList{Folders: []string{earlier}})

	if err := withOwnedFileLock(filepath.Join(earlier, hermesLifecycleLockName), func() error { return nil }); err != nil {
		t.Fatal(err)
	}

	if got := readEarlierDataDirList(t, f.home).Backups[earlier][hermesLifecycleLockName]; got != sha256Hex(nil) {
		t.Fatalf("lock recorded as %q", got)
	}
}
