// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestStandaloneManifestExcludesFleetCompiler(t *testing.T) {
	for _, name := range requiredStandalonePayloadFiles {
		if name == "policy_compiler.py" {
			t.Fatal("managed Setup inventory contains Fleet compiler")
		}
	}
	dir := t.TempDir()
	for _, name := range requiredStandalonePayloadFiles {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	opts := options{Flavor: flavorStandalone, Version: "1.4.0", SourceCommit: "0123456789abcdef0123456789abcdef01234567"}
	body, entries, err := buildManifestAndEntries(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	var manifest manifestDocument
	if err := json.Unmarshal(body, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(requiredStandalonePayloadFiles) || len(manifest.Files) != len(requiredStandalonePayloadFiles) {
		t.Fatal("standalone payload inventory changed unexpectedly")
	}
	for _, file := range manifest.Files {
		if file.Name == "policy_compiler.py" {
			t.Fatal("managed Setup manifest contains Fleet compiler")
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "policy_compiler.py"), []byte("unexpected"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyPayloadInventory(dir, requiredStandalonePayloadFiles); err == nil {
		t.Fatal("managed Setup accepted an extra Fleet compiler")
	}
}
