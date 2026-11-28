//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import "testing"

// TestDeploymentGatewayServiceIsProductionOrThisCertificationScope pins
// rel-1-0-10 GAP-2125: the gateway whose grants a deployment recognises is
// the production gateway or the run-scoped certification gateway of its pin
// or install root, and nothing broader.
func TestDeploymentGatewayServiceIsProductionOrThisCertificationScope(t *testing.T) {
	for _, tc := range []struct {
		name, install, pin, want string
	}{
		{"certification pin", StandaloneWindowsGatewaySvc, certificationGatewayAccountForTest, certificationGatewayServiceForTest},
		{"production pin", certificationGatewayServiceForTest, productionGatewayAccountForTest, StandaloneWindowsGatewaySvc},
		{"production pin, other case", "", `nt service\defenseclawgateway`, StandaloneWindowsGatewaySvc},
		{"certification install root, no pin", certificationGatewayServiceForTest, "", certificationGatewayServiceForTest},
		{"production install root, no pin", StandaloneWindowsGatewaySvc, "", StandaloneWindowsGatewaySvc},
		{"outside every install root, no pin", "", "", StandaloneWindowsGatewaySvc},
		// Twins: nothing but the two shapes is ever returned.
		{"another service", "", `NT SERVICE\OtherGateway`, StandaloneWindowsGatewaySvc},
		{"certification scope upper-case hex", "", `NT SERVICE\DefenseClawCertGateway_0A1B2C3D4E`, StandaloneWindowsGatewaySvc},
		{"certification scope too long", "", `NT SERVICE\DefenseClawCertGateway_0a1b2c3d4e5`, StandaloneWindowsGatewaySvc},
		{"certification guardian", "", `NT SERVICE\DefenseClawCertGuardian_0a1b2c3d4e`, StandaloneWindowsGatewaySvc},
		{"not an NT SERVICE account", "", `CORP\DefenseClawCertGateway_0a1b2c3d4e`, StandaloneWindowsGatewaySvc},
		{"bare service name", "", certificationGatewayServiceForTest, StandaloneWindowsGatewaySvc},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installServiceForTest(t, tc.install)
			t.Setenv(WindowsServiceAccountEnv, tc.pin)
			if got := DeploymentGatewayService(); got != tc.want {
				t.Fatalf("DeploymentGatewayService() = %q, want %q", got, tc.want)
			}
		})
	}
}
