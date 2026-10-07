// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
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

// An elevated administrator's `enterprise policy show --user <account>` (the
// command the standard-account refusal names) reads the account's settings
// with its own rights instead of failing on the LocalSystem-only
// impersonation (GAP-2465). Other impersonation errors still fail.
func TestEnterprisePolicyUserScanRunsAsAnAdministratorWithoutLocalSystem(t *testing.T) {
	previous := enterprisePolicyRunAsTarget
	t.Cleanup(func() { enterprisePolicyRunAsTarget = previous })
	target := enterprisehooks.TargetCredentials{UserHome: `C:\Users\dcw-std1`, SID: "S-1-5-21-1-2-3-1001"}

	enterprisePolicyRunAsTarget = func(enterprisehooks.TargetCredentials, func() error) error {
		return enterprisehooks.ErrWindowsEnterpriseNotLocalSystem
	}
	ran := 0
	if err := runAsEnterprisePolicyTarget(target, func() error { ran++; return nil }); err != nil || ran != 1 {
		t.Fatalf("administrator scan: err=%v ran=%d, want nil and 1", err, ran)
	}

	other := errors.New("enterprise hooks: resolve guardian process SID: access denied")
	enterprisePolicyRunAsTarget = func(enterprisehooks.TargetCredentials, func() error) error { return other }
	ran = 0
	if err := runAsEnterprisePolicyTarget(target, func() error { ran++; return nil }); !errors.Is(err, other) || ran != 0 {
		t.Fatalf("identity failure: err=%v ran=%d, want the error and no scan", err, ran)
	}
}

// GAP-0242: an Entra ID account resolves through the LSA and ProfileList, as
// profile explain does; os/user failed for every one ("No mapping between
// account names and security IDs was done").
func TestEnterprisePolicyTargetResolvesAnEntraIDAccount(t *testing.T) {
	const sid = "S-1-12-1-1111111111-2222222222-3333333333-4444444444"
	previousAccount, previousHome := enterprisePolicyAccount, enterprisePolicyProfileHome
	t.Cleanup(func() { enterprisePolicyAccount, enterprisePolicyProfileHome = previousAccount, previousHome })
	enterprisePolicyAccount = func(name string) (string, string, error) {
		if name != `AzureAD\EntraAlice` {
			return "", "", errors.New("No mapping between account names and security IDs was done")
		}
		return sid, "EntraAlice", nil
	}
	homes := map[string]string{sid: `C:\Users\EntraAlice`}
	enterprisePolicyProfileHome = func(id string) string { return homes[id] }
	target, err := enterprisePolicyTarget(`AzureAD\EntraAlice`)
	if err != nil || target.SID != sid || target.UserHome != `C:\Users\EntraAlice` || target.UID != -1 {
		t.Fatalf("target = %+v, %v", target, err)
	}
	delete(homes, sid)
	if _, err := enterprisePolicyTarget(`AzureAD\EntraAlice`); err == nil || !strings.Contains(err.Error(), "no profile on this computer") {
		t.Fatalf("an account without a profile = %v", err)
	}
}
