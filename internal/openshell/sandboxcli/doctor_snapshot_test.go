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

func TestDoctorReusesDaemonStatusAndSandboxList(t *testing.T) {
	ta := newTestApp(t, "", sampleSandbox("running"))
	ta.HostDoctor = func(context.Context, *openshell.Doctor) *openshell.DoctorReport {
		return &openshell.DoctorReport{}
	}
	report := ta.runDoctor(bg)
	if got := len(ta.daemon.callsTo("GET", sandboxapi.PathStatus)); got != 1 {
		t.Fatalf("daemon status reads = %d, want 1", got)
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
