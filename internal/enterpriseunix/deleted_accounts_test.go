// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// revokeGoneRunner answers `enterprise hooks revoke-gone` and records
// whether the guardian or the enumerator was running at the time.
type revokeGoneRunner struct {
	*fakeRunner
	services     *fakeServices
	units        []string
	answer       string
	fail         error
	calls        int
	whileRunning []string
}

func (r *revokeGoneRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if strings.Contains(strings.Join(args, " "), "enterprise hooks revoke-gone --manifest ") {
		r.calls++
		for _, unit := range r.units {
			if r.services.isActive(unit) {
				r.whileRunning = append(r.whileRunning, unit)
			}
		}
		if r.fail != nil {
			return CommandResult{ExitCode: 1}, r.fail
		}
		return CommandResult{Stdout: []byte(r.answer)}, nil
	}
	return r.fakeRunner.Run(ctx, name, args...)
}

// `enterprise macos repair` said done but kept the target of a
// deleted account, so verify and reconcile kept failing for the whole host
// until the enumerator's third miss. Repair now removes such targets while
// the guardian and the enumerator are stopped, and reports what it did.
func TestRepairRemovesTheTargetsOfDeletedAccounts(t *testing.T) {
	for goos, units := range map[string][]string{
		"linux":  {unitGuardian, unitEnumerator},
		"darwin": {labelGuardian, labelEnumerator},
	} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			runner := &revokeGoneRunner{fakeRunner: h.runner, services: h.services, units: units,
				answer: `{"rows":1,"revoked":["carol/amp"],"kept":["bob: account not found, but the directory could not be confirmed reachable, so its targets stay"],"manifest":"x","changed":true}` + "\n"}
			h.env.Runner = runner
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			requireOK(t, h.run(Options{Action: ActionEnsure}))
			if runner.calls != 0 {
				t.Fatalf("install or ensure ran the deleted-account check %d times; only repair does", runner.calls)
			}
			repair := h.run(Options{Action: ActionRepair})
			requireOK(t, repair)
			if runner.calls != 1 {
				t.Fatalf("repair ran the deleted-account check %d times, want 1", runner.calls)
			}
			if len(runner.whileRunning) != 0 {
				t.Fatalf("the check ran while %v could rewrite or read the manifest", runner.whileRunning)
			}
			removed, kept := "", ""
			for _, w := range repair.Warnings {
				switch w.Code {
				case codeDeletedAccountsRevoked:
					removed += w.Message
				case codeDeletedAccountsKept:
					kept += w.Message
				}
			}
			if !strings.Contains(removed, "no longer exist: carol/amp") || !strings.HasPrefix(kept, "bob: account not found") {
				t.Fatalf("repair warnings = %+v", repair.Warnings)
			}
			// It is one of the changes, so the repair does not also say
			// there was nothing to repair.
			if !strings.Contains(strings.Join(repair.Changes, "\n"), "deleted accounts: carol/amp") {
				t.Fatalf("repair changes = %q", repair.Changes)
			}
			for _, unit := range units {
				if !h.services.isActive(unit) {
					t.Fatalf("%s was not started again after repair", unit)
				}
			}

			// A failed check does not fail the repair.
			runner.fail = errors.New("exit 1: dscl timed out")
			repair = h.run(Options{Action: ActionRepair})
			requireOK(t, repair)
			if !hasWarning(repair, codeDeletedAccountsCheck) || hasWarning(repair, codeDeletedAccountsRevoked) {
				t.Fatalf("failed check warnings = %+v", repair.Warnings)
			}
		})
	}
}
