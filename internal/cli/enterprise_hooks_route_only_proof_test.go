// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-1975: Setup readiness runs as an elevated administrator, which cannot
// read the account-only route-only files (route_config_unverified). It
// counts such a target as verified only when the guardian, as LocalSystem,
// recorded it protected with the proof of exactly the render expected now,
// in the pass of the state readiness compares. Verify still fails the row;
// a render for another credential epoch, a proof record of another pass and
// a target the guardian recorded failed are not covered. The proofs never
// enter the state or authorization a prior binary reads strictly.
func TestReadinessCountsARouteOnlyRenderOnlyWhenTheGuardianProvedIt(t *testing.T) {
	f := newVerifyRecordedProtectionFixture(t)
	bob := f.bob
	route := &connector.RouteOnlySetup{BaseURL: "http://127.0.0.1:18970/r/codex", Token: "dcr1-bob-epoch-1", Custody: true}
	expected := route
	previousExpected := enterpriseHookVerifyExpectedRouteOnly
	t.Cleanup(func() { enterpriseHookVerifyExpectedRouteOnly = previousExpected })
	enterpriseHookVerifyExpectedRouteOnly = func(_, _, sid, _ string, _ bool) *connector.RouteOnlySetup {
		if sid == bob {
			return expected
		}
		return nil
	}
	var guardianErr error
	guardian := func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		result := enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}
		if opts.OwnerSID == bob {
			if guardianErr != nil {
				return enterprisehooks.InstallResult{}, guardianErr
			}
			result.RouteOnly = enterprisehooks.RouteOnlyProof(route)
		}
		return result, nil
	}
	enterpriseHookReconcileInstaller, enterpriseHookReconcileVerifier = guardian, guardian
	f.reconcile(0)

	for _, dir := range []string{cfg.DataDir, os.Getenv(hookGuardianAuthorizationDirEnv)} {
		_ = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() || filepath.Base(path) == hookGuardianRouteOnlyProofFile {
				return nil
			}
			if data, readErr := os.ReadFile(path); readErr == nil && strings.Contains(string(data), "route_only") {
				t.Fatalf("%s carries route_only, which a prior binary refuses", filepath.Base(path))
			}
			return nil
		})
	}

	f.routeOnlyUnverified = true
	readiness := func(name string) enterpriseHookVerifyRun {
		t.Helper()
		run, err := runEnterpriseHookVerifyAttemptWithScope(context.Background(), true)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return run
	}
	bobFailed := func(name string, run enterpriseHookVerifyRun) {
		t.Helper()
		for _, row := range run.Rows {
			if row.SID == bob && !row.OK && strings.Contains(row.Error, enterprisehooks.RouteConfigUnverifiedCode) && run.Failures-len(run.Excused) == 1 {
				return
			}
		}
		t.Fatalf("%s: failures=%d excused=%d rows=%+v, want Bob's row failed with %s", name, run.Failures, len(run.Excused), run.Rows, enterprisehooks.RouteConfigUnverifiedCode)
	}

	run := readiness("guardian proved the render")
	if run.Failures != 0 || run.AuthorizationErr != nil {
		t.Fatalf("guardian proved the render: failures=%d authorization=%v rows=%+v, want ready", run.Failures, run.AuthorizationErr, run.Rows)
	}
	for _, row := range run.Rows {
		if row.SID == bob && (!row.OK || row.Result == nil || row.Result.RouteOnly != enterprisehooks.RouteOnlyGuardianVerified) {
			t.Fatalf("guardian proved the render: Bob's row %+v, want ok with route_only %s", row, enterprisehooks.RouteOnlyGuardianVerified)
		}
	}

	bobFailed("verify", f.verify("verify"))

	expected = &connector.RouteOnlySetup{BaseURL: route.BaseURL, Token: "dcr1-bob-epoch-2", Custody: true}
	bobFailed("another render expected", readiness("another render expected"))
	expected = route

	_, proofs := takeEnterpriseHookRouteOnlyProofs([]enterpriseHookReconcileRow{{OK: true, SID: bob, Connector: "codex", Result: &enterprisehooks.InstallResult{RouteOnly: enterprisehooks.RouteOnlyProof(route)}}})
	if err := writeEnterpriseHookRouteOnlyProofs(cfg.DataDir, "2026-01-01T00:00:00Z", proofs); err != nil {
		t.Fatal(err)
	}
	bobFailed("proof record of another pass", readiness("proof record of another pass"))

	guardianErr = errors.New("enterprise hooks: connector codex hook installation failed")
	f.reconcile(1)
	if _, err := os.Stat(filepath.Join(cfg.DataDir, hookGuardianRouteOnlyProofFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a pass with no proof left the record: %v", err)
	}
	run = readiness("guardian recorded the target failed")
	if run.Failures-len(run.Excused) == 0 && run.AuthorizationErr == nil {
		t.Fatalf("guardian recorded the target failed: readiness passed: rows=%+v", run.Rows)
	}
}

// The comparison itself: only an unread render of a protected, not pending
// record with the proof of the render expected now.
func TestEnterpriseHookRouteOnlyGuardianVerified(t *testing.T) {
	route := &connector.RouteOnlySetup{BaseURL: "http://127.0.0.1:18970/r/claudecode", Token: "dcr1-a", Custody: true}
	proof := enterprisehooks.RouteOnlyProof(route)
	unread := enterprisehooks.InstallResult{RouteOnly: enterprisehooks.RouteOnlyUnverified}
	ok := enterpriseHookReconcileRow{OK: true}
	cases := []struct {
		name     string
		result   enterprisehooks.InstallResult
		recorded enterpriseHookReconcileRow
		proof    string
		expected *connector.RouteOnlySetup
		want     bool
	}{
		{"proved", unread, ok, proof, route, true},
		{"read and verified here", enterprisehooks.InstallResult{}, ok, proof, route, false},
		{"recorded failed", unread, enterpriseHookReconcileRow{}, proof, route, false},
		{"recorded pending", unread, enterpriseHookReconcileRow{OK: true, Pending: true}, proof, route, false},
		{"no proof recorded", unread, ok, "", route, false},
		{"proof of another render", unread, ok, enterprisehooks.RouteOnlyProof(&connector.RouteOnlySetup{BaseURL: route.BaseURL, Token: "dcr1-b", Custody: true}), route, false},
		{"no render expected", unread, ok, proof, nil, false},
		{"credential unavailable", unread, ok, proof, &connector.RouteOnlySetup{Unavailable: "no epoch"}, false},
	}
	for _, tc := range cases {
		if got := enterpriseHookRouteOnlyGuardianVerified(tc.result, tc.recorded, tc.proof, tc.expected); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
