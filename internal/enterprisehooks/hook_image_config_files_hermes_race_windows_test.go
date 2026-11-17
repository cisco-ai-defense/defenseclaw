//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hermespath"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// rel-1-0-10 GAP-0905: the Hermes home was resolved twice, once to decide
// that the account is signed in and again by the connector for its list,
// which falls back to the profile default when the lookup fails. An
// account that signed out between the two lookups, with a moved
// HERMES_HOME, had the default config listed as its readable, verified
// file and the moved one never read. The list must name the home resolved
// first; otherwise the account is one unverified entry.
func TestWindowsManagedHookConfigFilesHermesSignOutBetweenLookupsIsUnverified(t *testing.T) {
	t.Setenv(managed.EnterpriseProfileEnv, "")
	t.Setenv("HERMES_HOME", "")
	home := t.TempDir()
	moved := filepath.Join(home, "hermes-moved")
	var mu sync.Mutex
	calls := 0
	t.Cleanup(hermespath.OverrideAccountHomeForTest(func(string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 {
			return moved, nil
		}
		return "", hermespath.ErrAccountSignedOut
	}))
	const sid = "S-1-5-21-1-2-3-1018"
	enabled := true
	files, problems := WindowsManagedHookConfigFiles(writeWindowsTestManifest(t,
		ManifestTarget{User: `HOST\std2`, UserHome: home, SID: sid, Connector: "hermes", AgentVersion: "1.0.0", Enabled: &enabled}))
	if len(problems) != 0 || len(files) == 0 {
		t.Fatalf("files %+v problems %v", files, problems)
	}
	if calls < 2 {
		t.Fatalf("the Hermes home was looked up %d time(s); the race needs the second lookup", calls)
	}
	for _, file := range files {
		if file.Unverified == "" {
			t.Errorf("listed as a readable, verified Hermes file after the account signed out: %+v", file)
		}
	}
	if !strings.EqualFold(files[0].Path, filepath.Join(moved, "config.yaml")) || !files[0].User || files[0].SID != sid ||
		!strings.Contains(files[0].Unverified, "Hermes home changed while its files were listed") {
		t.Errorf("first entry = %+v, want the moved config.yaml, unverified", files[0])
	}
}

// Control: a Hermes home that stays put between the lookups is listed and
// read as before.
func TestWindowsManagedHookConfigFilesHermesStableHomeIsRead(t *testing.T) {
	t.Setenv(managed.EnterpriseProfileEnv, "")
	t.Setenv("HERMES_HOME", "")
	home := t.TempDir()
	moved := filepath.Join(home, "hermes-moved")
	t.Cleanup(hermespath.OverrideAccountHomeForTest(func(string) (string, error) { return moved, nil }))
	enabled := true
	files, problems := WindowsManagedHookConfigFiles(writeWindowsTestManifest(t,
		ManifestTarget{User: `HOST\std2`, UserHome: home, SID: "S-1-5-21-1-2-3-1018", Connector: "hermes", AgentVersion: "1.0.0", Enabled: &enabled}))
	if len(problems) != 0 {
		t.Fatalf("problems %v", problems)
	}
	found := false
	for _, file := range files {
		if strings.EqualFold(file.Path, filepath.Join(moved, "config.yaml")) {
			found = file.Unverified == "" && file.User
		}
	}
	if !found {
		t.Fatalf("the stable moved Hermes config is not a readable account file: %+v", files)
	}
}
