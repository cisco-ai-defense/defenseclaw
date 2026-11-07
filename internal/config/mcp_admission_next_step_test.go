// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func TestMCPAdmissionNextStep(t *testing.T) {
	managedCfg := &Config{DeploymentMode: "managed_enterprise"}
	for _, tc := range []struct {
		cfg  *Config
		name string
		want string
	}{
		{&Config{}, "notes", MCPNextStepAllow},
		{&Config{}, "acme-notes_v2.1", MCPNextStepAllow},
		{&Config{}, "my notes", MCPNextStepList},
		{&Config{}, "notes; rm", MCPNextStepList},
		{&Config{}, "-flag", MCPNextStepList},
		{&Config{}, "", MCPNextStepList},
		{managedCfg, "notes", MCPNextStepAdmin},
		{managedCfg, "my notes", MCPNextStepAdmin},
		{nil, "notes", MCPNextStepAllow},
	} {
		if got := tc.cfg.MCPAdmissionNextStep(tc.name); got != tc.want {
			t.Errorf("%+v %q: %q, want %q", tc.cfg, tc.name, got, tc.want)
		}
	}
}
