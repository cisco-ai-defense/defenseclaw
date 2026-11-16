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

package packs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0229: the managed gateway reads a required pack once per
// configuration generation. After the file is edited into one that does
// not load, trusted loads keep the pack the live generation loaded (the
// last good policy), while LoadGenerationPack, which builds the next
// generation, reports the edit. A pack folder this process may not look at
// is "unreadable", not a pack that does not load.
func TestGenerationPacksKeepTheLastGoodPack(t *testing.T) {
	trustAllPacks(t)
	t.Cleanup(func() { UseGenerationPacks("", nil) })
	dir := t.TempDir()
	file := filepath.Join(dir, "corp", PackFileName)
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	good := "version: 1\nname: corp\nextends: balanced\negress: {allow: [artifacts.example.com]}\n"
	if err := os.WriteFile(file, []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}
	s := Subject{UID: os.Getuid()}
	pack, err := LoadGenerationPack(s, file, dir)
	if err != nil {
		t.Fatalf("LoadGenerationPack: %v", err)
	}
	UseGenerationPacks(dir, map[string]*Pack{file: pack})

	if err := os.WriteFile(file, []byte("version: 1\nname: corp\nextends: balanced\nnetwork:\n  mode: unbuildable\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGenerationPack(s, file, dir); err == nil || !strings.Contains(err.Error(), "unbuildable") {
		t.Fatalf("LoadGenerationPack of the broken edit: %v", err)
	}
	kept, err := LoadRequired(s, file, dir, true)
	if err != nil || kept.Digest != pack.Digest {
		t.Fatalf("trusted load after the broken edit: %v, %v", kept, err)
	}
	// Another pack folder is not the live generation's.
	if _, err := LoadRequired(s, file, t.TempDir(), true); err == nil {
		t.Fatal("the generation's pack stood in for another pack folder")
	}
	UseGenerationPacks(dir, nil)
	if _, err := LoadRequired(s, file, dir, true); err == nil {
		t.Fatal("a later generation without the pack still used it")
	}

	if os.Geteuid() == 0 {
		return
	}
	if err := os.Chmod(filepath.Dir(file), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Dir(file), 0o755) })
	_, err = LoadGenerationPack(s, file, dir)
	var perr *Error
	if err == nil || !errors.As(err, &perr) || perr.Code != "unreadable" {
		t.Fatalf("a pack this process may not read: %v", err)
	}
}
