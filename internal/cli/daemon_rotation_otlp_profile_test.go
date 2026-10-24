// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestRotationRequiresNativeOTLPOnlyForProfilesThatInstallIt(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *config.Config
		want bool
	}{
		{name: "per-user", cfg: &config.Config{}, want: false},
		{name: "managed standalone", cfg: &config.Config{
			DeploymentMode: managed.DeploymentModeManagedEnterprise,
			Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
		}, want: true},
		{name: "Secure Client", cfg: &config.Config{
			DeploymentMode: managed.DeploymentModeManagedEnterprise,
			Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileSecureClient},
		}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := rotationNativeOTLPRequired(tc.cfg); got != tc.want {
				t.Fatalf("native OTLP readiness = %v, want %v", got, tc.want)
			}
		})
	}
}
