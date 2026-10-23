// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxcli

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// GAP-0528: a temporarily unavailable setup still refuses run. Doctor must
// make the same readiness decision in its text and JSON verdicts.
func TestManagedSetupChangingDoctorIsNotReady(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.status.Managed = managedStatusFixture()
	ta.daemon.status.Managed.Unavailable = sandboxrelay.UnavailableSetupChanging
	ta.daemon.status.Available = false
	ta.daemon.status.Reason = sandboxrelay.UnavailableSetupChanging
	rep := ta.runDoctor(bg)
	row := rep.Get(CheckIDManagedRuntime)
	if row == nil || row.Status != openshell.StatusFail || rep.OK() {
		t.Fatalf("doctor runtime row = %+v, ready = %v", row, rep.OK())
	}
	ta.printDoctor(rep)
	has(t, ta.output(), "not ready for sandboxes")
	lacks(t, ta.output(), "ready for sandboxes\n")
	wantExit(t, ta.fresh().RunDoctor(bg, DoctorOptions{Output: OutputJSON}), 1)
	var verdict struct{ OK, Ready bool }
	if err := json.Unmarshal(ta.out.Bytes(), &verdict); err != nil || verdict.OK || verdict.Ready {
		t.Fatalf("doctor json ok/ready = %+v, %v", verdict, err)
	}
}
