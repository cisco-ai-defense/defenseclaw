// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestManagedIPCEnabled(t *testing.T) {
	cases := []struct {
		name string
		cfg  *Config
		want bool
	}{
		{"nil config", nil, false},
		{"empty deployment mode", &Config{}, false},
		{"unmanaged_byod", &Config{DeploymentMode: string(DeploymentModeUnmanagedBYOD)}, false},
		{"ci_cd", &Config{DeploymentMode: string(DeploymentModeCICD)}, false},
		{"sandboxed", &Config{DeploymentMode: string(DeploymentModeSandboxed)}, false},
		{"server", &Config{DeploymentMode: string(DeploymentModeServer)}, false},
		{"saas", &Config{DeploymentMode: string(DeploymentModeSaaS)}, false},
		{"managed_enterprise", &Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.ManagedIPCEnabled(); got != tc.want {
				t.Errorf("ManagedIPCEnabled = %v, want %v", got, tc.want)
			}
		})
	}
}
