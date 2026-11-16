// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package testenv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A test that redirects the home with SetHome still needs private folders of
// its own: the redirected LocalAppData does not exist yet.
func TestPrivateTempDirWorksAfterSetHomeRedirectsLocalAppData(t *testing.T) {
	home := PrivateTempDir(t)
	SetHome(t, home)
	redirected := os.Getenv("LOCALAPPDATA")
	if _, err := os.Stat(redirected); !os.IsNotExist(err) {
		t.Fatalf("redirected LocalAppData %s should not exist yet: %v", redirected, err)
	}

	dir := PrivateTempDir(t)
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Fatalf("private temp dir %s after SetHome: %v", dir, err)
	}
	if strings.HasPrefix(strings.ToLower(dir), strings.ToLower(filepath.Clean(home))+string(filepath.Separator)) {
		t.Fatalf("private temp dir %s was made inside the redirected home %s", dir, home)
	}
	if _, err := os.Stat(redirected); !os.IsNotExist(err) {
		t.Fatalf("PrivateTempDir created the redirected LocalAppData %s: %v", redirected, err)
	}
}
