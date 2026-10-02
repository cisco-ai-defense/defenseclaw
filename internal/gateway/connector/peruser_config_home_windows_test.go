// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"path/filepath"
	"strings"
	"testing"
)

// The managed guardian resolves per-user connector configs as LocalSystem,
// whose APPDATA and LOCALAPPDATA name the service profile. Under
// WithUserHomeDir every path must land inside the target user's profile.
func TestPerUserHookConfigPathsFollowTheUserHomeOverride(t *testing.T) {
	serviceProfile := t.TempDir()
	t.Setenv("APPDATA", filepath.Join(serviceProfile, "AppData", "Roaming"))
	t.Setenv("LOCALAPPDATA", filepath.Join(serviceProfile, "AppData", "Local"))
	t.Setenv("HERMES_HOME", filepath.Join(serviceProfile, "hermes"))
	previousDevin, previousHermes := DevinHooksPathOverride, HermesConfigPathOverride
	DevinHooksPathOverride, HermesConfigPathOverride = "", ""
	t.Cleanup(func() { DevinHooksPathOverride, HermesConfigPathOverride = previousDevin, previousHermes })

	home := filepath.Join(t.TempDir(), "Users", "target")
	for _, tc := range []struct {
		conn Connector
		want string
	}{
		{NewDevinConnector(), filepath.Join(home, "AppData", "Roaming", "devin", "config.json")},
		{NewHermesConnector(), filepath.Join(home, "AppData", "Local", "hermes", "config.yaml")},
	} {
		var paths []string
		if err := WithUserHomeDir(home, func() error {
			paths = HookConfigPathsForConnector(tc.conn, SetupOpts{})
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, path := range paths {
			if strings.HasPrefix(strings.ToLower(path), strings.ToLower(serviceProfile)) {
				t.Fatalf("%s hook config path %s resolved from the calling process profile", tc.conn.Name(), path)
			}
			if strings.EqualFold(path, tc.want) {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s hook config paths = %v, want %s", tc.conn.Name(), paths, tc.want)
		}
	}
}
