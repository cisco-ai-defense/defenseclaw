//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestAcceptInheritedCreateChildOnlyOnFolders(t *testing.T) {
	t.Setenv(TrustStrictAncestorsEnv, "")
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatalf("Users SID: %v", err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatalf("Everyone SID: %v", err)
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(file, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	const programDataUsers windows.ACCESS_MASK = 0x116
	inherited := uint8(windows.INHERITED_ACE)

	if !acceptInheritedCreateChild(dir, "test", inherited, programDataUsers, users) {
		t.Fatal("inherited Users create-child on a folder was not accepted")
	}
	for name, tc := range map[string]struct {
		path  string
		flags uint8
		mask  windows.ACCESS_MASK
		sid   *windows.SID
	}{
		"file (0x116 is write data there)": {file, inherited, programDataUsers, users},
		"explicit entry":                   {dir, 0, programDataUsers, users},
		"delete right":                     {dir, inherited, programDataUsers | windows.DELETE, users},
		"delete child":                     {dir, inherited, programDataUsers | 0x40, users},
		"Everyone":                         {dir, inherited, programDataUsers, everyone},
	} {
		if acceptInheritedCreateChild(tc.path, "test", tc.flags, tc.mask, tc.sid) {
			t.Fatalf("%s was accepted", name)
		}
	}

	t.Setenv(TrustStrictAncestorsEnv, "1")
	if acceptInheritedCreateChild(dir, "test", inherited, programDataUsers, users) {
		t.Fatal("strict mode accepted inherited create-child")
	}
}
