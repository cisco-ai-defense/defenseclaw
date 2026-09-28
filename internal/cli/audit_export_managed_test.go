// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func withAuditExportManagedSeams(t *testing.T, managedHost, administrator bool) {
	t.Helper()
	host, admin, layout := auditExportManagedHost, auditExportCallerIsAdministrator, auditExportManagedLayout
	auditExportManagedHost = func() bool { return managedHost }
	auditExportCallerIsAdministrator = func() bool { return administrator }
	auditExportManagedLayout = func() (managed.StandaloneLayout, error) {
		return managed.StandaloneWindowsLayoutForRoots(`C:\Program Files`, `C:\ProgramData`)
	}
	t.Cleanup(func() {
		auditExportManagedHost, auditExportCallerIsAdministrator, auditExportManagedLayout = host, admin, layout
	})
	for _, key := range []string{
		"DEFENSECLAW_HOME", managed.ConfigPathEnv, managed.DeploymentModeEnv, managed.EnterpriseProfileEnv,
		managed.WindowsServiceAccountEnv, connector.WindowsGatewayServiceNameEnv,
	} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
}

// An elevated administrator's export reads the managed deployment,
// with the same identity pins the lifecycle gives gateway commands.
func TestAuditExportManagedEnvironmentPointsAnAdministratorAtTheDeployment(t *testing.T) {
	withAuditExportManagedSeams(t, true, true)
	if err := prepareManagedAuditExportEnvironment(); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	want := map[string]string{
		"DEFENSECLAW_HOME":                     `C:\ProgramData\Cisco\DefenseClaw\runtime`,
		managed.ConfigPathEnv:                  `C:\ProgramData\Cisco\DefenseClaw\etc\config.yaml`,
		managed.DeploymentModeEnv:              "managed_enterprise",
		managed.EnterpriseProfileEnv:           managed.ProfileStandalone,
		managed.WindowsServiceAccountEnv:       `NT SERVICE\DefenseClawGateway`,
		connector.WindowsGatewayServiceNameEnv: "DefenseClawGateway",
	}
	for key, value := range want {
		if got := os.Getenv(key); got != value {
			t.Fatalf("%s = %q, want %q", key, got, value)
		}
	}
}
