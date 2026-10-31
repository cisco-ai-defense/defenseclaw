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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/contracttest"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// Rapid config pushes: status while another run applied a change read ok
// false with a lifecycle_busy error and no pending-apply state (rel-1-0-3
// GAP-0129). It is ok with pending_apply, names the run in a lifecycle_busy
// warning and still exits 75; verify still fails busy, and a real failure
// still fails status.
func TestStatusDuringAnApplyIsPendingNotUnhealthy(t *testing.T) {
	schemas := contracttest.Compile(t)
	requirePending := func(t *testing.T, label string, status *enterprisestatus.Result, message string) {
		t.Helper()
		if !status.OK || !status.PendingApply || len(status.Errors) != 0 || status.ExitCode != enterprisestatus.UnixExitBusy ||
			!status.Installed || status.InstalledVersion != "1.0.0" || status.CoverageComplete || status.SecurityComplete ||
			!strings.Contains(messagesOf(status.Warnings, codeBusy), message) {
			t.Fatalf("%s: ok=%v pending_apply=%v exit=%d installed=%v version=%q coverage=%v security=%v errors=%+v warnings=%+v",
				label, status.OK, status.PendingApply, status.ExitCode, status.Installed, status.InstalledVersion,
				status.CoverageComplete, status.SecurityComplete, status.Errors, status.Warnings)
		}
		schemas.ValidateValue(t, "lifecycle-result.schema.json", status)
	}
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			// An ensure --config holds the lifecycle lock past the 5 s wait.
			held, err := h.env.acquireLock(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			requirePending(t, "status while another run holds the lock", h.run(Options{Action: ActionStatus}),
				"another DefenseClaw enterprise lifecycle run is in progress")
			verify := h.run(Options{Action: ActionVerify})
			requireError(t, verify, codeBusy)
			if verify.PendingApply || verify.ExitCode != enterprisestatus.UnixExitBusy {
				t.Fatalf("busy verify: pending_apply=%v exit=%d", verify.PendingApply, verify.ExitCode)
			}
			// The intent record of the run names it and its phase.
			if err := h.env.savePending(&Pending{Action: ActionEnsure, Phase: "activate"}); err != nil {
				t.Fatal(err)
			}
			requirePending(t, "status during an ensure", h.run(Options{Action: ActionStatus}), "in progress (ensure, phase activate); waited ")
			if err := h.env.clearPending(); err != nil {
				t.Fatal(err)
			}
			held.release()
			// Once the run ended, status is the plain healthy result again.
			healthy := h.run(Options{Action: ActionStatus})
			requireOK(t, healthy)
			if healthy.PendingApply {
				t.Fatal("a healthy status reports pending_apply")
			}
			// A real failure is still unhealthy, not pending.
			h.healthy = false
			failed := h.run(Options{Action: ActionStatus})
			if failed.OK || failed.PendingApply || failed.ExitCode != enterprisestatus.UnixExitFailure {
				t.Fatalf("status of a gateway that does not answer: ok=%v pending_apply=%v exit=%d", failed.OK, failed.PendingApply, failed.ExitCode)
			}
		})
	}
	// The apply trigger applying a pushed config.yaml (systemd reports it
	// activating) is a pending apply too.
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	h.services.activating = map[string]bool{unitApplyService: true}
	requirePending(t, "status while the apply trigger runs", h.run(Options{Action: ActionStatus}), "configuration change is being applied")
	requireError(t, h.run(Options{Action: ActionVerify}), codeBusy)
}
