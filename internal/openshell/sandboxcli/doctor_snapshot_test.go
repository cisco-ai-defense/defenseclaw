// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxcli

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

func TestDoctorReadsCurrentStatusAndReusesSandboxList(t *testing.T) {
	ta := newTestApp(t, "", sampleSandbox("running"))
	ta.HostDoctor = func(context.Context, *openshell.Doctor) *openshell.DoctorReport {
		return &openshell.DoctorReport{}
	}
	report := ta.runDoctor(bg)
	if got := len(ta.daemon.callsTo("GET", sandboxapi.PathStatus)); got != 4 {
		t.Fatalf("daemon status reads = %d, want 4 (early, hooks, contained, unknown)", got)
	}
	if got := len(ta.daemon.callsTo("GET", sandboxapi.PathSandboxes)); got != 1 {
		t.Fatalf("sandbox list reads = %d, want 1", got)
	}
	var daemon, hooks int = -1, -1
	for i, check := range report.Checks {
		if check.ID == CheckIDDaemon {
			daemon = i
		}
		if check.ID == CheckIDHooks {
			hooks = i
		}
	}
	if daemon < 0 || hooks <= daemon {
		t.Fatalf("doctor row order changed: daemon=%d hooks=%d", daemon, hooks)
	}
}

func TestDoctorSeesContainmentChangedDuringHostChecks(t *testing.T) {
	ta := newTestApp(t, "")
	ta.HostDoctor = func(context.Context, *openshell.Doctor) *openshell.DoctorReport {
		ta.daemon.mu.Lock()
		ta.daemon.status.Unprotected = []sandboxapi.UnprotectedSandbox{{
			Name: "newly-contained", Phase: "starting", Stop: "defenseclaw sandbox stop newly-contained",
			Reason: sandboxapi.UnprotectedContained,
		}}
		ta.daemon.mu.Unlock()
		return &openshell.DoctorReport{}
	}
	report := ta.runDoctor(bg)
	if row := report.Get(CheckIDContainedSandbox); row == nil || row.Status != openshell.StatusFail || report.OK() {
		t.Fatalf("contained state arising during host checks omitted: row=%+v ok=%v", row, report.OK())
	}
}

func TestDoctorSeesUnknownSandboxAtItsOwnCheck(t *testing.T) {
	ta := newTestApp(t, "")
	ta.HostDoctor = func(context.Context, *openshell.Doctor) *openshell.DoctorReport {
		return &openshell.DoctorReport{}
	}
	reads := 0
	ta.daemon.onStatus = func(st *sandboxapi.Status) {
		reads++
		if reads == 4 {
			st.Unprotected = []sandboxapi.UnprotectedSandbox{{
				Name: "unseen", Phase: "unknown", Reason: sandboxapi.UnprotectedUnknown,
				Detail: "gateway status changed",
			}}
		}
	}
	report := ta.runDoctor(bg)
	if row := report.Get(CheckIDUnknownSandbox); row == nil || row.Status != openshell.StatusFail || report.OK() {
		t.Fatalf("unknown state at its check omitted: row=%+v ok=%v", row, report.OK())
	}
}
