// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-1096 (review RV-LENT P2-1): after hook-image retire, Setup 1.0.9
// /upgrade and this release's Setup /ensure, an account's lock names this
// release while its protected runtime selection names the earlier image. That
// retire render admits only the read-only proof that accepts the earlier
// release's render. It must not open the GAP-2463 earlier-matrix wait, which
// trusts the account's own Hermes config: an account owner who strips only
// fail_closed from this release's matrix before disconnecting stays failed,
// as at rel. A lock a release before fail_closed wrote keeps the GAP-2463
// wait; one from 1.0.4 on does not (GAP-1537).
func TestEnterpriseHookRetireRenderAdmitsOnlyThePriorRenderProof(t *testing.T) {
	f := newUpgradeWaitFixture(t)
	previousRetire, previousMatrix := enterpriseHookReconcileTargetRetireRender, enterpriseHookReconcileTargetEarlierMatrix
	t.Cleanup(func() {
		enterpriseHookReconcileTargetRetireRender, enterpriseHookReconcileTargetEarlierMatrix = previousRetire, previousMatrix
	})
	const this = "1.0.10"
	f.verifyErr = errors.New("enterprise hooks: connector hermes hook verification failed: canonical hook matrix is absent")
	retireRender := func(on bool) {
		// Lock = this release: the release check says no, as at rel.
		enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) { return "", false, nil }
		enterpriseHookReconcileTargetRetireRender = func(enterprisehooks.InstallOptions) (string, bool, error) {
			if on {
				return this, true, nil
			}
			return "", false, nil
		}
	}
	// The account's Hermes config holds this release's matrix with only
	// fail_closed removed.
	enterpriseHookReconcileTargetEarlierMatrix = func(enterprisehooks.InstallOptions) (bool, error) { return true, nil }
	opts := enterprisehooks.InstallOptions{ConnectorName: "hermes"}
	deferred := enterprisehooks.ManifestTarget{Connector: "hermes", SID: "S-1-5-21-1-2-3-1096", Deferred: true}
	run := func() error {
		t.Helper()
		f.installs = 0
		_, repaired, err := enterpriseHookVerifyOrRepairTarget(context.Background(), deferred, opts, true)
		if repaired || f.installs != 0 {
			t.Fatalf("repaired=%t installs=%d, want no repair without a session", repaired, f.installs)
		}
		return err
	}
	wantFailed := func(label string, err error) {
		t.Helper()
		if err == nil || errors.Is(err, errEnterpriseHookAwaitingSignIn) || !strings.HasPrefix(err.Error(), upgradeWaitSignedOutRepair) {
			t.Fatalf("%s: err=%v, want the signed-out repair failure", label, err)
		}
	}

	// 1. Tampered config, the prior-render proof fails: failed, as at rel.
	retireRender(true)
	f.staleRender = false
	wantFailed("retire render with a tampered Hermes config", run())

	// 1b. Same, with hook fail mode open and the machine registration proven:
	// the open-mode wait needs a lock an earlier release wrote.
	opts.HookFailMode = "open"
	enterpriseHookReconcileMachineRegistration = func(enterprisehooks.InstallOptions) (bool, error) { return true, nil }
	wantFailed("retire render in open mode", run())
	opts.HookFailMode = ""
	enterpriseHookReconcileMachineRegistration = func(enterprisehooks.InstallOptions) (bool, error) { return false, nil }

	// 2. The prior-render proof passes: pending, naming this release.
	f.staleRender = true
	err := run()
	if !errors.Is(err, errEnterpriseHookAwaitingSignIn) ||
		!strings.Contains(err.Error(), enterpriseHookAwaitingSignInPriorRender) ||
		strings.Contains(err.Error(), enterpriseHookAwaitingSignInEarlierMatrix) ||
		!strings.Contains(err.Error(), "DefenseClaw "+this+" protected it") {
		t.Fatalf("retire render, prior render proven: err=%v, want the prior-render sign-in wait", err)
	}

	// 2b. No retire render and a lock this release wrote: failed, as at rel.
	retireRender(false)
	wantFailed("this release lock without a retire render", run())

	// 3. A lock 1.0.3 wrote with the earlier matrix: the GAP-2463 wait.
	f.staleRender = false
	enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) { return "1.0.3", true, nil }
	err = run()
	if !errors.Is(err, errEnterpriseHookAwaitingSignIn) ||
		!strings.Contains(err.Error(), enterpriseHookAwaitingSignInEarlierMatrix) ||
		!strings.Contains(err.Error(), "DefenseClaw 1.0.3 registered them without fail_closed") {
		t.Fatalf("lock 1.0.3 with the earlier matrix: err=%v, want the GAP-2463 wait", err)
	}

	// 3b. A lock 1.0.9 wrote: 1.0.9 rendered fail_closed, so a matrix
	// without it was changed after the render (GAP-1537).
	enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) { return "1.0.9", true, nil }
	if err := run(); errors.Is(err, errEnterpriseHookAwaitingSignIn) {
		t.Fatalf("lock 1.0.9 with the earlier matrix: err=%v, want no GAP-2463 wait", err)
	}

	// 4. Secure Client never takes a retire render (no prior-render branch).
	enterpriseHookReconcileSecureClient = func() bool { return true }
	retireRender(true)
	f.staleRender = true
	wantFailed("Secure Client retire render", run())
}
