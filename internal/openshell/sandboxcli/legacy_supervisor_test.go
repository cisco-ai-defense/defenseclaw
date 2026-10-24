// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxcli

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// TestNoCommandStopsOrRunsInALegacySandbox (GAP-0415): a ready sandbox the
// daemon names as running the supervisor of an OpenShell older than
// SupportedMin gets no exec and no connect, on docker and on a MicroVM, and
// neither stops it: DefenseClaw stops it for nobody. Both name it
// unprotected and the user's own stop, which on a MicroVM syncs first.
func TestNoCommandStopsOrRunsInALegacySandbox(t *testing.T) {
	for _, driver := range []string{"docker", "vm"} {
		t.Run(driver, func(t *testing.T) {
			ta := newTestApp(t, "y\n")
			sb := sampleSandbox("m1-b")
			sb.Phase, sb.OldSupervisor, sb.Driver = "ready", true, driver
			ta.daemon.add(sb)
			for _, run := range []func() error{
				func() error { return ta.Exec(bg, ExecOptions{Name: "m1-b", Command: []string{"ls"}}) },
				func() error { return ta.Connect(bg, ConnectOptions{Name: "m1-b"}) },
			} {
				err := run()
				if err == nil || !strings.Contains(err.Error(), "m1-b: legacy sandbox running, not protected by the 1.0.4 egress policy") ||
					!strings.Contains(err.Error(), "does not stop it for you: save the work you need, then run `defenseclaw sandbox stop m1-b`") {
					t.Fatalf("refusal = %v", err)
				}
				if driver == "vm" != strings.Contains(err.Error(), "syncs the VM's disk first") {
					t.Fatalf("the MicroVM note (%s): %v", driver, err)
				}
			}
			if ta.calls("POST", "m1-b/stop") != 0 || ta.calls("POST", "m1-b/start") != 0 || len(ta.stream.runs) != 0 {
				t.Fatalf("a command stopped, started or ran in the legacy sandbox: stops %d, starts %d, runs %v",
					ta.calls("POST", "m1-b/stop"), ta.calls("POST", "m1-b/start"), ta.stream.runs)
			}
		})
	}
}

// TestDoctorIsNotReadyWhileALegacySandboxRuns: the daemon creates and
// starts no sandbox while one runs the supervisor of an OpenShell older
// than SupportedMin, so the doctor fails a row that names it unprotected
// with the command that ends it: the stop of a ready one, the delete of a
// MicroVM whose workload ended. No such sandbox, no row.
func TestDoctorIsNotReadyWhileALegacySandboxRuns(t *testing.T) {
	row := func(ta *testApp) *openshell.Check {
		t.Helper()
		ta.HostDoctor = func(context.Context, *openshell.Doctor) *openshell.DoctorReport { return &openshell.DoctorReport{} }
		return ta.runDoctor(bg).Get(CheckIDLegacySandbox)
	}
	ta := newTestApp(t, "")
	ta.daemon.add(sampleSandbox("plain"))
	if c := row(ta); c != nil {
		t.Fatalf("a row with no legacy sandbox: %+v", c)
	}
	ready := sampleSandbox("old-ready")
	ready.Phase, ready.OldSupervisor, ready.Driver = "ready", true, "vm"
	ended := sampleSandbox("old-ended")
	ended.Phase, ended.OldSupervisor, ended.Driver = "completed", true, "vm"
	ta.daemon.add(ready)
	ta.daemon.add(ended)
	c := row(ta)
	if c == nil || c.Status != openshell.StatusFail || c.Fix == nil ||
		// The fake daemon lists its sandboxes in map order.
		!(strings.Contains(c.Detail, "old-ready, old-ended: legacy sandbox running, not protected by the 1.0.4 egress policy") ||
			strings.Contains(c.Detail, "old-ended, old-ready: legacy sandbox running, not protected by the 1.0.4 egress policy")) ||
		!strings.Contains(c.Detail, "creates and starts no sandbox until they are gone") ||
		!strings.Contains(c.Fix.Summary, "save the work you need in old-ready, then run `defenseclaw sandbox stop old-ready`, which syncs the VM's disk first") ||
		!strings.Contains(c.Fix.Summary, "`defenseclaw sandbox delete old-ended` deletes old-ended and its work") {
		t.Fatalf("legacy row = %+v", c)
	}
}

// TestAStopAnOlderDaemonCouldNotMakeSaysTheWayOn (GAP-0871): a sandbox
// daemon of DefenseClaw 1.0.2 or 1.0.3 that a package upgrade left running
// answers the stop of a MicroVM in OpenShell's error state with
// OpenShell's words alone. The stop now names the sandbox, why OpenShell
// holds it and the way on for the gateway's release (on 0.1.3, its delete).
// An error that already says its way on (the 1.0.4 daemon's), or one about
// a sandbox that holds nothing (docker), goes on as it was.
func TestAStopAnOlderDaemonCouldNotMakeSaysTheWayOn(t *testing.T) {
	generic := &sandboxapi.Error{Code: sandboxapi.CodeUpstream, Message: `OpenShell: wait for sandbox t8 to stop failed: openshell: wait for sandbox "t8" to stop: Internal: sandbox "t8" is in error state`}
	for _, tc := range []struct {
		name, driver string
		err          *sandboxapi.Error
		want, not    string
	}{
		{name: "older daemon, MicroVM", driver: "vm", err: generic,
			want: "is in error state; t8 is in OpenShell's error state (MainProcessFailed: Canonical main process exited with status 137): OpenShell does not stop it, " +
				"so its MicroVM may still run, and DefenseClaw stops, restarts and upgrades no OpenShell gateway under it, nor moves this account to another OpenShell setup, " +
				"until OpenShell reports it stopped: save or sync any accessible guest work outside the guest first; " +
				"OpenShell 0.1.3 cannot stop or start a completed or error-state MicroVM: " +
				"`defenseclaw sandbox delete t8` (DefenseClaw sandbox) or `openshell sandbox delete t8` (raw OpenShell sandbox), which deletes it and its work"},
		{name: "older daemon, docker", driver: "docker", err: generic, not: "OpenShell does not stop it"},
		{name: "current daemon", driver: "vm", err: &sandboxapi.Error{Code: sandboxapi.CodeConflict, Message: "t8 is in OpenShell's error state", Detail: "its own way on"},
			want: "t8 is in OpenShell's error state: its own way on", not: "OpenShell does not stop it"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sb := sampleSandbox("t8")
			sb.Phase, sb.Driver, sb.PhaseReason = "error", tc.driver, "MainProcessFailed: Canonical main process exited with status 137"
			ta := newTestApp(t, "", sb)
			ta.daemon.status.Gateway.Version = "0.1.3"
			ta.daemon.errors["POST "+sandboxapi.PathSandboxes+"/t8/stop"] = tc.err
			err := ta.Stop(bg, StopOptions{Name: "t8", Yes: true})
			if err == nil || tc.want != "" && !strings.Contains(err.Error(), tc.want) || tc.not != "" && strings.Contains(err.Error(), tc.not) {
				t.Fatalf("stop = %v", err)
			}
		})
	}
}
