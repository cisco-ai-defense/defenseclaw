//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/spf13/cobra"
)

func TestManagedWindowsHermesVerifierDefaults(t *testing.T) {
	want := reflect.ValueOf(enterpriseHookGuardianVerify).Pointer()
	if got := reflect.ValueOf(enterpriseHookReconcileVerifier).Pointer(); got != want {
		t.Errorf("guardian default verifier = %x, want physical registration verifier %x", got, want)
	}
	if got := reflect.ValueOf(enterpriseHookLiveRegistrationVerifier).Pointer(); got != want {
		t.Errorf("live readiness default verifier = %x, want physical registration verifier %x", got, want)
	}
}

// The guardian needs proof of the hooks it installed, while Verify still
// refuses to certify a Hermes home that only a later user shell can select.
func TestManagedWindowsHermesGuardianKeepsSessionHomeOutOfMachineReadiness(t *testing.T) {
	previousVerifier := enterpriseHookReconcileVerifier
	previousSession := enterpriseHookReconcileSessionAvailable
	previousRegistration := enterpriseHookWindowsRegistrationVerifier
	previousConfig := cfg
	t.Cleanup(func() {
		enterpriseHookReconcileVerifier = previousVerifier
		enterpriseHookReconcileSessionAvailable = previousSession
		enterpriseHookWindowsRegistrationVerifier = previousRegistration
		cfg = previousConfig
	})
	cfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	enterpriseHookReconcileVerifier = enterpriseHookGuardianVerify
	want := enterprisehooks.InstallResult{Connector: "hermes", UserHome: `C:\Users\operator`}
	var registrationErr error
	calls := 0
	enterpriseHookWindowsRegistrationVerifier = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		calls++
		return want, registrationErr
	}
	enterpriseHookReconcileSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) { return false, nil }
	target := enterprisehooks.ManifestTarget{Connector: "hermes"}
	got, repaired, err := enterpriseHookVerifyOrRepairTarget(context.Background(), target, enterprisehooks.InstallOptions{ConnectorName: "hermes"}, true)
	if err != nil || repaired || got.Connector != want.Connector || calls != 1 {
		t.Fatalf("guardian registration proof = (%+v, repaired=%t, err=%v, calls=%d)", got, repaired, err, calls)
	}
	if err := enterprisehooks.ManagedHermesSessionHomeAttestation("windows", "hermes", true, false); err == nil || !strings.Contains(err.Error(), "session-only HERMES_HOME") {
		t.Fatalf("public coverage attestation changed: %v", err)
	}
	registrationErr = errors.New("owned hook command not present")
	_, _, err = enterpriseHookVerifyOrRepairTarget(context.Background(), target, enterprisehooks.InstallOptions{ConnectorName: "hermes"}, true)
	if err == nil || !strings.Contains(err.Error(), "owned hook command not present") {
		t.Fatalf("guardian accepted an absent physical Hermes hook: %v", err)
	}
	cfg.Enterprise.Profile = managed.ProfileSecureClient
	_, err = enterpriseHookGuardianVerify(context.Background(), enterprisehooks.InstallOptions{ConnectorName: "hermes"})
	if err == nil || calls != 2 {
		t.Fatalf("Secure Client used standalone registration proof: err=%v calls=%d", err, calls)
	}
}

func TestManagedWindowsHermesLiveReadinessKeepsPublicVerifyStrict(t *testing.T) {
	previousPublic := enterpriseHookLivePublicVerifier
	previousRegistration := enterpriseHookLiveRegistrationVerifier
	previousConfig := cfg
	t.Cleanup(func() {
		enterpriseHookLivePublicVerifier = previousPublic
		enterpriseHookLiveRegistrationVerifier = previousRegistration
		cfg = previousConfig
	})
	cfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	publicCalls, registrationCalls := 0, 0
	publicErr := errors.New("Hermes NOT COVERED: session-only HERMES_HOME cannot be observed")
	enterpriseHookLivePublicVerifier = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		publicCalls++
		return enterprisehooks.InstallResult{}, publicErr
	}
	registrationErr := error(nil)
	enterpriseHookLiveRegistrationVerifier = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		registrationCalls++
		if !strings.EqualFold(opts.ConnectorName, "hermes") {
			t.Fatalf("registration verifier used for %q", opts.ConnectorName)
		}
		return enterprisehooks.InstallResult{Connector: "hermes"}, registrationErr
	}

	ctx := context.Background()
	hermes := enterprisehooks.InstallOptions{ConnectorName: "hermes"}
	if _, err := enterpriseHookLiveTargetVerifier(ctx, hermes, false); !errors.Is(err, publicErr) {
		t.Fatalf("public Verify accepted a session-only Hermes home: %v", err)
	}
	if result, err := enterpriseHookLiveTargetVerifier(ctx, hermes, true); err != nil || result.Connector != "hermes" {
		t.Fatalf("Setup registration of physically hooked Hermes = (%+v, %v)", result, err)
	}
	registrationErr = errors.New("owned hook command not present")
	if _, err := enterpriseHookLiveTargetVerifier(ctx, hermes, true); !errors.Is(err, registrationErr) {
		t.Fatalf("Setup accepted an absent owned Hermes hook: %v", err)
	}
	if _, err := enterpriseHookLiveTargetVerifier(ctx, enterprisehooks.InstallOptions{ConnectorName: "codex"}, true); !errors.Is(err, publicErr) {
		t.Fatalf("Setup weakened a non-Hermes verification: %v", err)
	}
	if publicCalls != 2 || registrationCalls != 2 {
		t.Fatalf("verifier calls: public=%d registration=%d, want 2 each", publicCalls, registrationCalls)
	}
	cfg.Enterprise.Profile = managed.ProfileSecureClient
	if err := runEnterpriseHooksReadiness(&cobra.Command{}, nil); err == nil ||
		!strings.Contains(err.Error(), "only for managed standalone Windows Setup") {
		t.Fatalf("Secure Client entered standalone readiness: %v", err)
	}
}
