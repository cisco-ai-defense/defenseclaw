// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winfolders

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestUserProgramFilesIgnoresProcessEnvironmentOverrides(t *testing.T) {
	want, err := UserProgramFiles()
	if err != nil {
		t.Fatal(err)
	}
	foreignProfile := t.TempDir()
	for name, value := range map[string]string{
		"USERPROFILE":  foreignProfile,
		"HOME":         foreignProfile,
		"LOCALAPPDATA": filepath.Join(foreignProfile, "AppData", "Local"),
		"APPDATA":      filepath.Join(foreignProfile, "AppData", "Roaming"),
	} {
		t.Setenv(name, value)
	}
	got, err := UserProgramFiles()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(filepath.Clean(got), filepath.Clean(want)) {
		t.Fatalf("token-bound UserProgramFiles changed with process environment: got %q, want %q", got, want)
	}
}

func TestUserProgramFilesDoesNotRequireMaterializedFolder(t *testing.T) {
	const local = `C:\Users\fixture\AppData\Local`
	var calls int
	got, err := userProgramFiles(func(id *windows.KNOWNFOLDERID, flags uint32) (string, error) {
		calls++
		if flags != windows.KF_FLAG_DONT_VERIFY {
			t.Fatalf("KnownFolderPath flags = %#x, want KF_FLAG_DONT_VERIFY", flags)
		}
		switch id {
		case windows.FOLDERID_UserProgramFiles:
			return "", errors.New("fixture folder is not registered")
		case windows.FOLDERID_LocalAppData:
			return local, nil
		default:
			t.Fatalf("unexpected Known Folder id: %v", id)
			return "", nil
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("KnownFolderPath calls = %d, want 2", calls)
	}
	want := filepath.Join(local, "Programs")
	if got != want {
		t.Fatalf("UserProgramFiles fallback = %q, want %q", got, want)
	}
}

func TestUserProgramFilesPrefersRedirectedKnownFolder(t *testing.T) {
	const redirected = `D:\Per User Programs`
	got, err := userProgramFiles(func(id *windows.KNOWNFOLDERID, flags uint32) (string, error) {
		if id != windows.FOLDERID_UserProgramFiles {
			t.Fatalf("unexpected fallback for available UserProgramFiles")
		}
		if flags != windows.KF_FLAG_DONT_VERIFY {
			t.Fatalf("KnownFolderPath flags = %#x, want KF_FLAG_DONT_VERIFY", flags)
		}
		return redirected, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != redirected {
		t.Fatalf("UserProgramFiles = %q, want redirected path %q", got, redirected)
	}
}
