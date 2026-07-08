// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package safefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadRegularBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte("policy"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := ReadRegular(path, 6)
	if err != nil || string(raw) != "policy" {
		t.Fatalf("ReadRegular = %q, %v", raw, err)
	}
	if _, err := ReadRegular(path, 5); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected bounded-read error, got %v", err)
	}
	raw, err = ReadRegular(path, -1)
	if err != nil || string(raw) != "policy" {
		t.Fatalf("unlimited ReadRegular = %q, %v", raw, err)
	}
}

func TestReadRegularRejectsLinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("policy"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("hard link", func(t *testing.T) {
		alias := filepath.Join(dir, "hard-link")
		if err := os.Link(target, alias); err != nil {
			t.Skipf("hard links unavailable: %v", err)
		}
		if _, err := ReadRegular(target, 64); err == nil || !strings.Contains(err.Error(), "hard links") {
			t.Fatalf("expected hard-link rejection, got %v", err)
		}
		if err := os.Remove(alias); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("symbolic link", func(t *testing.T) {
		alias := filepath.Join(dir, "symbolic-link")
		if err := os.Symlink(target, alias); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if _, err := ReadRegular(alias, 64); err == nil {
			t.Fatal("expected symbolic-link rejection")
		}
	})
}
