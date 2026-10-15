// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestStandaloneManifestBindsPolicyCompiler(t *testing.T) {
	if payloadRequiresAuthenticode(flavorStandalone, "policy_compiler.py") ||
		!payloadRequiresAuthenticode(flavorStandalone, "defenseclaw-gateway.exe") ||
		!payloadRequiresAuthenticode(flavorEnterprise, "defenseclaw-gateway.exe") {
		t.Fatal("standalone compiler signature exception widened beyond Python source")
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
	for _, file := range manifest.Files {
		if file.Name == "policy_compiler.py" {
			content := []byte("policy_compiler.py\n")
			wantSHA := fmt.Sprintf("%x", sha256.Sum256(content))
			if file.Size != int64(len(content)) || file.SHA256 != wantSHA || len(entries) != len(requiredStandalonePayloadFiles) {
				t.Fatalf("compiler not fully bound to standalone manifest: %#v", file)
			}
			return
		}
	}
	t.Fatal("standalone manifest omits policy_compiler.py")
}
