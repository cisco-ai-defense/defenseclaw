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

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A rule pack below a folder the gateway cannot traverse (0700 from a umask
// 077 mkdir -p) is named with the folder, its mode and the chmod hint, not a
// bare lstat permission error (GAP-0757).
func TestPolicyInputInspectErrorNamesTheUntraversableFolder(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root traverses every folder")
	}
	root := t.TempDir()
	guardrail := filepath.Join(root, "policies", "guardrail")
	pack := filepath.Join(guardrail, "default")
	if err := os.MkdirAll(pack, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(guardrail, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(guardrail, 0o700) })
	_, lstatErr := os.Lstat(pack)
	if lstatErr == nil {
		t.Fatal("lstat through a 0600 folder succeeded")
	}
	got := policyInputInspectError("guardrail.rule_pack_dir", pack, lstatErr).Error()
	for _, want := range []string{
		"config: inspect guardrail.rule_pack_dir " + pack,
		guardrail + " is 0600, so the gateway cannot reach the folders below it",
		"chmod o+x " + guardrail,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("error = %q, want %q", got, want)
		}
	}
	if len(got) > 300+len(root)*3 {
		t.Fatalf("error is %d bytes; the status warning keeps the first 300 of the gateway text", len(got))
	}
}
