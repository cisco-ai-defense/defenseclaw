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
)

// A stray DEFENSECLAW_DEPLOYMENT_MODE in a user's shell must not turn a
// per-user install into a managed (or an invalid) one (GAP-0091).
func TestIgnoreUnmanagedPinsDropsPinsOnlyForAPerUserConfig(t *testing.T) {
	home := t.TempDir()
	perUser := filepath.Join(home, ".defenseclaw", "config.yaml")
	machine := filepath.Join(t.TempDir(), "config.yaml")
	for _, path := range []string{perUser, machine} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("config_version: 9\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	managedUser := filepath.Join(home, "managed", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(managedUser), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedUser, []byte("deployment_mode: managed_enterprise\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, config string
		dropped      bool
	}{
		{"per-user config", perUser, true},
		{"machine config", machine, false},
		{"per-user config that declares managed", managedUser, false},
	} {
		t.Setenv(DeploymentModeEnv, "oss")
		t.Setenv(EnterpriseProfileEnv, "")
		got := IgnoreUnmanagedPins(tc.config, home)
		if dropped := len(got) == 1 && got[0] == DeploymentModeEnv; dropped != tc.dropped {
			t.Errorf("%s: dropped %v, want %v", tc.name, got, tc.dropped)
		}
		if _, still := os.LookupEnv(DeploymentModeEnv); still == tc.dropped {
			t.Errorf("%s: pin still set = %v, want %v", tc.name, still, !tc.dropped)
		}
	}
}
