//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
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

func TestWindowsEnterpriseDesiredEnrollmentsResolvesLocalUser(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatalf("resolve current user: %v", err)
	}
	manifest := enterprisehooks.Manifest{Targets: []enterprisehooks.ManifestTarget{{
		User:      current.Username,
		Connector: "codex",
	}}}

	_, codex, err := windowsEnterpriseDesiredEnrollments(manifest)
	if err != nil {
		t.Fatalf("resolve desired enrollments: %v", err)
	}
	if len(codex) != 1 {
		t.Fatalf("Codex enrollment count = %d, want 1", len(codex))
	}
	if !strings.EqualFold(codex[0].SID, current.Uid) {
		t.Fatalf("Codex enrollment SID = %q, want %q", codex[0].SID, current.Uid)
	}
	wantDataDir := filepath.Join(filepath.Clean(current.HomeDir), ".defenseclaw")
	if !sameWindowsEnterprisePathCLI(codex[0].DataDir, wantDataDir) {
		t.Fatalf("Codex enrollment data dir = %q, want %q", codex[0].DataDir, wantDataDir)
	}
}
