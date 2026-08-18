//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"
	"testing"
)

func TestExpandEnterpriseHookProfileImagePathUsesTrustedSystemDrive(t *testing.T) {
	previous := enterpriseHookWindowsSystemDirectory
	t.Cleanup(func() { enterpriseHookWindowsSystemDirectory = previous })
	enterpriseHookWindowsSystemDirectory = func() (string, error) {
		return `D:\Windows\System32`, nil
	}
	t.Setenv("SystemDrive", `Z:`)

	got, err := expandEnterpriseHookProfileImagePath(`%SystemDrive%\Users\managed`)
	if err != nil {
		t.Fatalf("expand ProfileImagePath: %v", err)
	}
	want := filepath.Clean(`D:\Users\managed`)
	if filepath.Clean(got) != want {
		t.Fatalf("expanded ProfileImagePath = %q, want %q", got, want)
	}
}

func TestExpandEnterpriseHookProfileImagePathRejectsOtherVariables(t *testing.T) {
	if _, err := expandEnterpriseHookProfileImagePath(`%USERPROFILE%\managed`); err == nil {
		t.Fatal("ProfileImagePath with user-controlled expansion was accepted")
	}
}
