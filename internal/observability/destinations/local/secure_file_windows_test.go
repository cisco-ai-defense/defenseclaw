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

package local

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// This runs on Windows CI and pins the preparation seam: validation must open
// the parent directory, not the not-yet-created JSONL leaf path.
func TestWindowsJSONLPreparesNewFileInTrustedParent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new", "events.jsonl")
	adapter, err := NewJSONL(JSONLConfig{Path: path, MaxSizeMB: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("mode = %v, want regular file", info.Mode())
	}
}

// DefenseClaw's cross-runtime private-directory contract uses OWNER RIGHTS
// instead of embedding a user SID. OWNER RIGHTS resolves only to the validated
// current owner and must therefore remain a trusted JSONL parent principal.
func TestWindowsJSONLAcceptsPrivateOwnerRightsParent(t *testing.T) {
	directory := t.TempDir()
	descriptor, err := windows.SecurityDescriptorFromString(
		"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)",
	)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("extract private parent DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(
		directory,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(directory, "events.jsonl")
	adapter, err := NewJSONL(JSONLConfig{Path: path, MaxSizeMB: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsAllowedPrincipalDoesNotBroadenOwnerRights(t *testing.T) {
	ownerRights, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerRightsSid)
	if err != nil {
		t.Fatal(err)
	}
	if !windowsAllowedACEPrincipal(ownerRights) {
		t.Fatal("OWNER RIGHTS ACE was rejected")
	}
	if windowsAllowedOwner(ownerRights) {
		t.Fatal("OWNER RIGHTS was accepted as the object's concrete owner")
	}
	for name, kind := range map[string]windows.WELL_KNOWN_SID_TYPE{
		"creator-owner": windows.WinCreatorOwnerSid,
		"world":         windows.WinWorldSid,
	} {
		sid, err := windows.CreateWellKnownSid(kind)
		if err != nil {
			t.Fatal(err)
		}
		if windowsAllowedACEPrincipal(sid) {
			t.Errorf("%s ACE was accepted", name)
		}
		if windowsAllowedOwner(sid) {
			t.Errorf("%s was accepted as owner", name)
		}
	}
}
