// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// An elevated administrator's `enterprise policy show|verify` on a
// standalone managed host reads the managed deployment's config, not the
// administrator's own profile.
func TestEnterprisePolicyPinsTheManagedDeploymentForAnAdministrator(t *testing.T) {
	withAuditExportManagedSeams(t, true, true)
	if err := pinStandaloneManagedEnv(); err != nil {
		t.Fatalf("pin: %v", err)
	}
	for key, want := range map[string]string{
		"DEFENSECLAW_HOME":           `C:\ProgramData\Cisco\DefenseClaw\runtime`,
		managed.ConfigPathEnv:        `C:\ProgramData\Cisco\DefenseClaw\etc\config.yaml`,
		managed.DeploymentModeEnv:    "managed_enterprise",
		managed.EnterpriseProfileEnv: managed.ProfileStandalone,
	} {
		if got := os.Getenv(key); got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
}

// On a managed Windows host `enterprise policy verify
// --live` is refused with its own reason before the elevation pin, for an
// administrator and for a standard account alike, instead of two refusals
// that point at each other.
func TestEnterprisePolicyLiveVerifyIsRefusedUpFrontOnAManagedWindowsHost(t *testing.T) {
	previousLive := enterprisePolicyLive
	t.Cleanup(func() { enterprisePolicyLive = previousLive })
	enterprisePolicyLive = true
	for _, administrator := range []bool{false, true} {
		withAuditExportManagedSeams(t, true, administrator)
		err := enterprisePolicyCmd.PersistentPreRunE(enterprisePolicyVerifyCmd, nil)
		if err == nil || !strings.Contains(err.Error(), "--live is not available") ||
			strings.Contains(err.Error(), "elevated Administrator prompt or by the MDM agent") {
			t.Fatalf("administrator=%v: verify --live error = %v, want the up-front live refusal", administrator, err)
		}
		if got := os.Getenv(managed.ConfigPathEnv); got != "" {
			t.Fatalf("administrator=%v: a refused live check set %s=%q", administrator, managed.ConfigPathEnv, got)
		}
	}
	withAuditExportManagedSeams(t, false, false)
	if err := enterprisePolicyLiveAvailable(); err != nil {
		t.Fatalf("an unmanaged Windows host refuses the live check: %v", err)
	}
}
