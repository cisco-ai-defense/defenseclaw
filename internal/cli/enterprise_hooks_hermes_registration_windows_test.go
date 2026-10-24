//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

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
