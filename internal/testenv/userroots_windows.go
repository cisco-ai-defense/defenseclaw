// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package testenv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// vendorFolders are the folders below the real roaming profile that a
// connector Setup writes and the tests read back: Devin keeps its user
// config at %APPDATA%\devin\config.json.
var vendorFolders = []string{"devin"}

// realRoamingFolders returns the roaming profile folder of the account that
// runs the tests, from the known-folder API and the inherited %APPDATA%.
func realRoamingFolders() []string {
	var roots []string
	add := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		for _, have := range roots {
			if strings.EqualFold(have, path) {
				return
			}
		}
		roots = append(roots, path)
	}
	if known, err := windows.KnownFolderPath(windows.FOLDERID_RoamingAppData, windows.KF_FLAG_DONT_VERIFY); err == nil {
		add(known)
	}
	add(os.Getenv("APPDATA"))
	return roots
}

func watchedUserRoots() []string {
	var watch []string
	for _, root := range realRoamingFolders() {
		for _, name := range vendorFolders {
			watch = append(watch, filepath.Join(root, name))
		}
	}
	return watch
}

func redirectedUserRoots(runDir string) map[string]string {
	return map[string]string{"APPDATA": filepath.Join(runDir, "AppData", "Roaming")}
}

// AssertOffRealRoamingProfile fails the test when %APPDATA% still names the
// real roaming profile of the account that runs the tests, which is what a
// package TestMain (IsolateUserRoots) moves away.
func AssertOffRealRoamingProfile(t testing.TB) {
	t.Helper()
	current := os.Getenv("APPDATA")
	if strings.TrimSpace(current) == "" {
		t.Fatal("APPDATA is empty; the run should name a folder of its own")
	}
	known, err := windows.KnownFolderPath(windows.FOLDERID_RoamingAppData, windows.KF_FLAG_DONT_VERIFY)
	if err != nil {
		t.Fatalf("resolve the real roaming profile: %v", err)
	}
	if strings.EqualFold(filepath.Clean(current), filepath.Clean(known)) {
		t.Fatalf("APPDATA is the real roaming profile %s; the package TestMain must call testenv.IsolateUserRoots", known)
	}
}
