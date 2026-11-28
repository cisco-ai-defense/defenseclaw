// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-1537: the earlier-matrix sign-in wait reads the account's own Hermes
// config, which the account can write. A signed-out account owner after a
// 1.0.9 -> 1.0.10 upgrade (lock 1.0.9) who strips only fail_closed got the
// pending wait (verify passes) instead of a failure, while Hermes hooks
// failed open on a gateway outage. The wait now also needs the other release
// (enterpriseHookReconcileTargetRelease: the lock's release, counted only when
// the administrator-only machine release history names it) to be one that
// registered no fail_closed (before 1.0.4). The account can edit its lock too:
// enterprisehooks TestGAP1537AccountEditedLockReleaseNeedsTheMachineReleaseHistory.
// Fails on d36e4f852b: lock 1.0.9 was pending.
func TestGAP1537EarlierMatrixWaitNeedsALockFromBeforeFailClosed(t *testing.T) {
	stubSecureClientSignInReconcile(t)
	previousEarlier := enterpriseHookReconcileTargetEarlierMatrix
	previousClosed := enterpriseHookReconcileClosedMachineRegistration
	t.Cleanup(func() {
		enterpriseHookReconcileTargetEarlierMatrix = previousEarlier
		enterpriseHookReconcileClosedMachineRegistration = previousClosed
	})
	enterpriseHookReconcileVerifier = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		return enterprisehooks.InstallResult{}, errors.New("enterprise hooks: connector hermes hook verification failed: canonical hook matrix is absent: owned hook command not present")
	}
	enterpriseHookReconcileSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) { return false, nil }
	enterpriseHookReconcileSecureClient = func() bool { return false }
	enterpriseHookReconcileClosedMachineRegistration = func(enterprisehooks.InstallOptions) (bool, error) { return false, nil }
	installs := 0
	enterpriseHookReconcileInstaller = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		installs++
		return enterprisehooks.InstallResult{}, nil
	}
	// The account's config holds this release's matrix minus fail_closed.
	enterpriseHookReconcileTargetEarlierMatrix = func(enterprisehooks.InstallOptions) (bool, error) { return true, nil }
	opts := enterprisehooks.InstallOptions{ConnectorName: "hermes"}
	target := enterprisehooks.ManifestTarget{Connector: "hermes", SID: "S-1-5-21-1-2-3-1017", UserHome: `C:\Users\dcw-std1`, Deferred: true}

	for _, tc := range []struct {
		lock    string
		pending bool
	}{
		{"1.0.2", true},
		{"1.0.3", true},
		{"1.0.4", false},
		{"1.0.4-rc1", false},
		{"1.0.9", false},
		{"1.0.10", false},
		{"dev", false},
	} {
		lock := tc.lock
		enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) { return lock, true, nil }
		_, repaired, err := enterpriseHookVerifyOrRepairTarget(context.Background(), target, opts, true)
		if repaired || installs != 0 {
			t.Fatalf("lock %s: repaired=%t installs=%d, want no install as SYSTEM", lock, repaired, installs)
		}
		if got := errors.Is(err, errEnterpriseHookAwaitingSignIn); got != tc.pending {
			t.Fatalf("GAP-1537: lock %s: awaiting sign-in = %t (err %v), want %t", lock, got, err, tc.pending)
		}
		if !tc.pending && err == nil {
			t.Fatalf("GAP-1537: lock %s: no error, want the signed-out refusal", lock)
		}
	}
}
