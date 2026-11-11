// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// degradedGuardianFixture is a Guardian reconcile with one active, one
// pending (deferred) and one failed target, written the way
// writeEnterpriseHookGuardianState writes it: all three records share counts
// and timestamp, OK is false because a target failed, and the failed target
// stays in ProtectedTargets with its last successful row when it was
// protected before.
type degradedGuardianFixture struct {
	ctx            windowsManagedHooksLifecycleContext
	manifestSHA256 string
	activation     enterpriseHookGuardianActivation
	authorization  enterpriseHookGuardianAuthorization
	state          enterpriseHookGuardianState
	activeRow      enterpriseHookReconcileRow
	pendingRow     enterpriseHookReconcileRow
	failedRow      enterpriseHookReconcileRow
}

func newDegradedGuardianFixture(failedWasProtected bool) degradedGuardianFixture {
	f := degradedGuardianFixture{manifestSHA256: strings.Repeat("a", 64)}
	f.ctx = windowsManagedHooksLifecycleContext{
		manifestPath: `C:\ProgramData\DefenseClaw\hook-guardian\targets.yaml`,
		targets: []windowsManagedHooksTeardownTarget{
			{Connector: "claudecode", SID: "S-1-5-21-111-222-333-1003", DataDir: `C:\Users\carol\.defenseclaw`},
			{Connector: "codex", SID: "S-1-5-21-111-222-333-1001", DataDir: `C:\Users\alice\.defenseclaw`},
			{Connector: "cursor", SID: "S-1-5-21-111-222-333-1002", DataDir: `C:\Users\bob\.defenseclaw`, Deferred: true},
		},
	}
	f.failedRow = enterpriseHookReconcileRow{
		Connector: "claudecode", SID: f.ctx.targets[0].SID, UserHome: `C:\Users\carol`,
		Error: "enterprise hooks: open managed runtime selector: Access is denied.",
	}
	f.activeRow = enterpriseHookReconcileRow{
		Connector: "codex", SID: f.ctx.targets[1].SID, UserHome: `C:\Users\alice`, OK: true,
	}
	f.pendingRow = enterpriseHookReconcileRow{
		Connector: "cursor", SID: f.ctx.targets[2].SID, UserHome: `C:\Users\bob`, Pending: true,
	}
	protected := []enterpriseHookReconcileRow{f.activeRow}
	if failedWasProtected {
		protected = append(protected, enterpriseHookReconcileRow{
			Connector: f.failedRow.Connector, SID: f.failedRow.SID, UserHome: f.failedRow.UserHome, OK: true,
		})
	}
	const updatedAt = "2026-10-29T00:00:00Z"
	f.activation = enterpriseHookGuardianActivation{
		Version: enterpriseHookGuardianActivationVersion, UpdatedAt: updatedAt,
		ReconcileID: strings.Repeat("f", 32), Manifest: f.ctx.manifestPath, ManifestSHA256: f.manifestSHA256,
		OK: false, TargetCount: 3, SuccessCount: 1, FailureCount: 1, PendingCount: 1,
		ProtectedTargets: protected,
	}
	f.authorization = enterpriseHookGuardianAuthorization{
		Version: 1, UpdatedAt: updatedAt,
		OK: false, TargetCount: 3, SuccessCount: 1, FailureCount: 1, PendingCount: 1,
		ProtectedTargets: protected,
	}
	f.state = enterpriseHookGuardianState{
		Version: 1, UpdatedAt: updatedAt, Manifest: f.ctx.manifestPath,
		OK: false, TargetCount: 3, SuccessCount: 1, FailureCount: 1, PendingCount: 1,
		Results: []enterpriseHookReconcileRow{f.failedRow, f.activeRow, f.pendingRow},
	}
	return f
}

func (f degradedGuardianFixture) validate() ([]windowsManagedHooksTeardownTarget, []windowsManagedHooksTeardownTarget, error) {
	return validateWindowsManagedHooksGuardianActivation(f.activation, f.authorization, f.state, f.ctx, f.manifestSHA256)
}

func TestWindowsManagedHooksGuardianAcceptsFailedTargets(t *testing.T) {
	for _, wasProtected := range []bool{true, false} {
		f := newDegradedGuardianFixture(wasProtected)
		pending, failed, err := f.validate()
		if err != nil {
			t.Fatalf("failed target (previously protected=%t) rejected: %v", wasProtected, err)
		}
		if len(pending) != 1 || pending[0] != f.ctx.targets[2] {
			t.Fatalf("pending targets = %+v, want the deferred cursor target", pending)
		}
		if len(failed) != 1 || failed[0] != f.ctx.targets[0] {
			t.Fatalf("failed targets = %+v, want the claudecode target", failed)
		}
		if err := validateLegacyWindowsManagedHooksGuardianActivation(
			f.activation, f.authorization, f.state, f.ctx, f.manifestSHA256,
		); err != nil {
			t.Fatalf("legacy classification rejected a degraded Guardian: %v", err)
		}
	}
}

func TestWindowsManagedHooksGuardianStillRejectsAmbiguousRows(t *testing.T) {
	both := newDegradedGuardianFixture(true)
	both.state.Results[0].OK = true
	both.state.Results[0].Pending = true
	if _, _, err := both.validate(); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("row marked both active and pending: error = %v, want ambiguous", err)
	}

	noError := newDegradedGuardianFixture(true)
	noError.state.Results[0].Error = "  "
	if _, _, err := noError.validate(); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("failed row without an error: error = %v, want ambiguous", err)
	}
}

func TestWindowsManagedHooksGuardianKeepsBindingWithFailures(t *testing.T) {
	for name, mutate := range map[string]func(*degradedGuardianFixture){
		"failed row outside the manifest": func(f *degradedGuardianFixture) {
			f.state.Results[0].SID = "S-1-5-21-111-222-333-9999"
		},
		"duplicate failed row": func(f *degradedGuardianFixture) {
			f.state.Results = append(f.state.Results, f.failedRow)
		},
		"failed row home mismatch": func(f *degradedGuardianFixture) {
			f.state.Results[0].UserHome = `C:\Users\mallory`
		},
		"failure count does not match failed rows": func(f *degradedGuardianFixture) {
			f.state.FailureCount = 0
			f.state.SuccessCount = 2
		},
		"OK while a target failed": func(f *degradedGuardianFixture) {
			f.activation.OK = true
		},
		"authorization failure count differs": func(f *degradedGuardianFixture) {
			f.authorization.FailureCount = 0
			f.authorization.SuccessCount = 2
		},
		"protected set drops an active target": func(f *degradedGuardianFixture) {
			f.activation.ProtectedTargets = f.activation.ProtectedTargets[1:]
		},
		"protected set holds the pending target": func(f *degradedGuardianFixture) {
			f.authorization.ProtectedTargets = append(f.authorization.ProtectedTargets, enterpriseHookReconcileRow{
				Connector: f.pendingRow.Connector, SID: f.pendingRow.SID, OK: true,
			})
		},
		"malformed manifest digest": func(f *degradedGuardianFixture) {
			f.activation.ManifestSHA256 = "not-a-digest"
		},
		"records from different reconciles": func(f *degradedGuardianFixture) {
			f.state.UpdatedAt = "2026-10-29T00:00:01Z"
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newDegradedGuardianFixture(true)
			f.activation.ProtectedTargets = append([]enterpriseHookReconcileRow(nil), f.activation.ProtectedTargets...)
			f.authorization.ProtectedTargets = append([]enterpriseHookReconcileRow(nil), f.authorization.ProtectedTargets...)
			f.state.Results = append([]enterpriseHookReconcileRow(nil), f.state.Results...)
			mutate(&f)
			if _, _, err := f.validate(); err == nil {
				t.Fatal("tampered degraded Guardian evidence was accepted")
			}
		})
	}
}

func TestWindowsManagedHooksTeardownBindsFailedTargets(t *testing.T) {
	f := newDegradedGuardianFixture(true)
	targets := f.ctx.targets
	failed := []windowsManagedHooksTeardownTarget{targets[0]}
	pending := []windowsManagedHooksTeardownTarget{targets[2]}
	if err := validateWindowsManagedHooksFailedTargetSubset(targets, pending, failed, windowsManagedHooksActivated); err != nil {
		t.Fatalf("failed target subset: %v", err)
	}
	for name, bad := range map[string][]windowsManagedHooksTeardownTarget{
		"outside the manifest": {{Connector: "codex", SID: "S-1-5-21-1-2-3-9", DataDir: `C:\Users\x\.defenseclaw`}},
		"changed data dir":     {{Connector: targets[0].Connector, SID: targets[0].SID, DataDir: `C:\Elsewhere`}},
		"duplicate":            {targets[0], targets[0]},
		"also pending":         {targets[2]},
	} {
		if err := validateWindowsManagedHooksFailedTargetSubset(targets, pending, bad, windowsManagedHooksActivated); err == nil {
			t.Fatalf("%s: failed target subset accepted", name)
		}
	}
	if err := validateWindowsManagedHooksFailedTargetSubset(targets, nil, failed, windowsManagedHooksNeverActivated); err == nil {
		t.Fatal("never-activated deployment accepted failed target evidence")
	}
	if !windowsManagedHooksTeardownTargetIn(targets[0], failed) || windowsManagedHooksTeardownTargetIn(targets[1], failed) {
		t.Fatal("failed target membership is wrong")
	}
}

// The enumerator republishes the manifest (an agent version bump, a new user)
// between Guardian reconciles. The stale digest is logged and accepted, and a
// row the Guardian has not reported yet is treated as possibly wired.
func TestWindowsManagedHooksGuardianAcceptsRepublishedManifest(t *testing.T) {
	events := captureResilienceEvents(t)
	f := newDegradedGuardianFixture(true)
	f.activation.ManifestSHA256 = strings.Repeat("b", 64)
	added := windowsManagedHooksTeardownTarget{
		Connector: "codex",
		SID:       "S-1-5-21-111-222-333-1777",
		DataDir:   `C:\Users\newcomer\.defenseclaw`,
	}
	f.ctx.targets = append(append([]windowsManagedHooksTeardownTarget(nil), f.ctx.targets...), added)

	pending, failed, err := f.validate()
	if err != nil {
		t.Fatalf("republished manifest rejected: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending = %+v", pending)
	}
	found := false
	for _, target := range failed {
		if target == added {
			found = true
		}
	}
	if !found {
		t.Fatalf("failed = %+v, want the unreported row treated as possibly wired", failed)
	}
	if len(*events) != 2 {
		t.Fatalf("events = %v, want the digest drift and the unreported row", *events)
	}
	for _, event := range *events {
		if !strings.HasPrefix(event, managed.MarkerAccept+" ") {
			t.Fatalf("event = %q", event)
		}
	}
}

// A never-protected, non-deferred user who is signed out is recorded as a
// failed row whose error says it is waiting. The coverage wait accepts it,
// teardown treats it as possibly wired, and a non-deferred pending row is
// still rejected, so earlier releases read the same state after a rollback.
func TestWindowsManagedHooksGuardianAcceptsWaitingTargetAsFailed(t *testing.T) {
	f := newDegradedGuardianFixture(false)
	f.state.Results = append([]enterpriseHookReconcileRow(nil), f.state.Results...)
	f.state.Results[0].Error = "pending: no active session for the target user"

	pending, failed, err := f.validate()
	if err != nil {
		t.Fatalf("waiting target rejected: %v", err)
	}
	if len(pending) != 1 || pending[0] != f.ctx.targets[2] {
		t.Fatalf("pending = %+v, want only the deferred target", pending)
	}
	if len(failed) != 1 || failed[0] != f.ctx.targets[0] {
		t.Fatalf("failed = %+v, want the waiting target treated as possibly wired", failed)
	}

	f.state.Results[0] = enterpriseHookReconcileRow{
		Connector: f.failedRow.Connector, SID: f.failedRow.SID, UserHome: f.failedRow.UserHome, Pending: true,
	}
	if _, _, err := f.validate(); err == nil {
		t.Fatal("non-deferred pending target was accepted")
	}
}

// rel-1-0-6:GAP-0994: the Guardian publishes its authorization, state and
// activation records one after the other, and publishes OK=false with no failed
// row when the exact enrollment set could not be published. A classification
// that meets either refuses with the one sentence the lifecycle module
// recognizes, and now names the input that disagreed.
func TestWindowsManagedHooksGuardianBindingRefusalNamesTheDisagreement(t *testing.T) {
	healthy := func() degradedGuardianFixture {
		f := newDegradedGuardianFixture(true)
		protected := []enterpriseHookReconcileRow{f.activeRow}
		f.activation.OK, f.activation.TargetCount, f.activation.SuccessCount = true, 1, 1
		f.activation.FailureCount, f.activation.PendingCount, f.activation.ProtectedTargets = 0, 0, protected
		f.authorization.OK, f.authorization.TargetCount, f.authorization.SuccessCount = true, 1, 1
		f.authorization.FailureCount, f.authorization.PendingCount, f.authorization.ProtectedTargets = 0, 0, protected
		f.state.OK, f.state.TargetCount, f.state.SuccessCount = true, 1, 1
		f.state.FailureCount, f.state.PendingCount, f.state.Results = 0, 0, []enterpriseHookReconcileRow{f.activeRow}
		return f
	}
	const older = "2026-10-29T00:00:00Z"
	const newer = "2026-10-29T00:02:40Z"
	if _, _, err := healthy().validate(); err != nil {
		t.Fatalf("one publication was refused: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*degradedGuardianFixture)
		want   string
	}{
		{"stopped after the authorization and the state were published", func(f *degradedGuardianFixture) {
			f.authorization.UpdatedAt, f.state.UpdatedAt = newer, newer
			f.activation.UpdatedAt = older
		}, "different publications (activation \"" + older + "\", authorization \"" + newer + "\", state \"" + newer + "\")"},
		{"stopped after the authorization was published", func(f *degradedGuardianFixture) {
			f.authorization.UpdatedAt = newer
		}, "different publications (activation \"" + older + "\", authorization \"" + newer + "\", state \"" + older + "\")"},
		{"published as incomplete with no failed row", func(f *degradedGuardianFixture) {
			f.activation.OK, f.authorization.OK, f.state.OK = false, false, false
		}, "activation ok=false, its rows say ok=true"},
		{"another manifest path", func(f *degradedGuardianFixture) {
			f.state.Manifest = `C:\elsewhere\targets.yaml`
		}, "manifest path"},
	} {
		f := healthy()
		tc.mutate(&f)
		for name, call := range map[string]func() error{
			"classification": func() error {
				return validateLegacyWindowsManagedHooksGuardianActivation(f.activation, f.authorization, f.state, f.ctx, f.manifestSHA256)
			},
			"teardown": func() error { _, _, err := f.validate(); return err },
		} {
			err := call()
			if !errors.Is(err, errWindowsManagedHooksGuardianNotBound) {
				t.Fatalf("%s (%s): err = %v, want the binding refusal", tc.name, name, err)
			}
			if !strings.Contains(err.Error(), "does not exactly bind the legacy deployment manifest and authorization") ||
				!strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%s (%s): err = %q, want the recognized sentence and %q", tc.name, name, err, tc.want)
			}
		}
	}
}
