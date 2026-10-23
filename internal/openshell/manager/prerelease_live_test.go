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

package manager

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
)

// connectAtFakeRelease has the manager's gateway report the release the
// fake gateway's health says, as a real gateway does after an upgrade.
func connectAtFakeRelease(e *harnessEnv) {
	e.m.opts.Connect = func(ctx context.Context) (*Gateway, error) {
		h, err := e.client.Health(ctx)
		if err != nil {
			return nil, err
		}
		gw := *e.gw
		gw.Version = h.RawVersion
		return &gw, nil
	}
}

// TestAPrereleaseOfSandboxMinRunsNoSandbox: NVIDIA/OpenShell#4494, the
// broker fix SupportedMin stands for, landed in 0.1.5-pre.4, so a gateway
// that reports a prerelease of 0.1.5 (pre.1 to pre.3 have the hole) runs no
// sandbox: a create and a start are refused with the upgrade, and a
// session it started is named, as for 0.1.4. A prerelease of a later
// release (0.1.6-pre.1) comes after 0.1.5 and runs them.
func TestAPrereleaseOfSandboxMinRunsNoSandbox(t *testing.T) {
	e := newEnv(t, nil)
	connectAtFakeRelease(e)
	e.create(sandboxapi.CreateRequest{Name: "kept"})
	e.stopBox("kept")
	for _, release := range []string{"0.1.5-pre.1", "0.1.5-pre.3", "0.1.5-pre.7"} {
		e.fake.SetRelease(release)
		_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "fresh", Project: e.otherProject("other")})
		apiErr := wantCode(t, err, sandboxapi.CodeUnavailable)
		if !strings.Contains(apiErr.Message, "OpenShell "+release+" is a prerelease, which runs no DefenseClaw sandbox") ||
			!strings.Contains(apiErr.Message, "NVIDIA/OpenShell#4494") ||
			apiErr.Detail != "upgrade OpenShell "+release+" to "+openshell.InstallerVersion+" in place with `defenseclaw sandbox setup --install-openshell`" {
			t.Fatalf("create on %s = %+v", release, apiErr)
		}
		if e.boxOf("fresh") != nil {
			t.Fatalf("the refused create on %s left a sandbox behind", release)
		}
		_, err = e.m.Start(t.Context(), "kept", sandboxapi.StartRequest{})
		if apiErr := wantCode(t, err, sandboxapi.CodeUnavailable); !strings.Contains(apiErr.Message, "OpenShell "+release+" is a prerelease") {
			t.Fatalf("start on %s = %+v", release, apiErr)
		}
	}
	// A session that starts on a prerelease (outside DefenseClaw) runs its
	// supervisor, is named and kept until its user's stop (the gateway the manager last reached
	// runs 0.1.5-pre.7, which has the broker fix but is still a prerelease).
	must(t, e.fake.SetPhase(openshell.DefaultWorkspace, "kept", types.SandboxReady))
	e.m.statusEvent(t.Context(), e.boxOf("kept"), &stream.Status{Phase: openshell.PhaseProvisioning})
	e.m.statusEvent(t.Context(), e.boxOf("kept"), &stream.Status{Phase: openshell.PhaseReady})
	e.m.tamperStops.Wait()
	if found := e.events("kept", sandboxapi.ActivityFinding, sandboxapi.ReasonOldSupervisor); len(found) == 0 ||
		!strings.Contains(found[len(found)-1].Message, "its session started on OpenShell 0.1.5-pre.7") {
		t.Fatalf("old-supervisor findings on a prerelease = %+v", found)
	}
	if got := e.get("kept").Phase; got != "ready" {
		t.Fatalf("a session on the 0.1.5-pre.7 supervisor is %s, want ready", got)
	}
	e.fake.SetRelease("0.1.6-pre.1")
	e.stopBox("kept")
	e.startBox("kept", sandboxapi.StartRequest{})
	if got := e.boxOf("kept").rec.SessionRelease; got != "0.1.6-pre.1" || !openshell.RunsSandboxes(got) {
		t.Fatalf("session release on 0.1.6-pre.1 = %q", got)
	}
}

// TestOldGatewayTimeoutWayOnStartsWithoutAStop: a sandbox whose
// provisioning timed out on a gateway older than SupportedMin is told to
// upgrade and then start it with no stop, which is the way on of the
// upgraded gateway too: OpenShell 0.1.5 refuses to stop it
// (NVIDIA/OpenShell#4231). The feed's line, and the refusals of a stop or
// a start, all say so; any other error state keeps upgrade, stop, start.
func TestOldGatewayTimeoutWayOnStartsWithoutAStop(t *testing.T) {
	upgrade := "upgrade OpenShell 0.1.3 to " + openshell.InstallerVersion + " in place with `defenseclaw sandbox setup --install-openshell`"
	deleteFirst := "this OpenShell can neither stop nor start a sandbox in its error state, and DefenseClaw stops no OpenShell gateway, so upgrades none, " +
		"while OpenShell has not reported a MicroVM on it stopped: `defenseclaw sandbox delete box` deletes it and its work, after which " + upgrade
	timedOut := func(got string) bool {
		return strings.Contains(got, "this OpenShell can neither stop nor start a sandbox in its error state: "+upgrade+", then wait a minute") &&
			strings.Contains(got, "`defenseclaw sandbox start box` (no stop: OpenShell "+openshell.SupportedMin+" refuses to stop a sandbox whose provisioning timed out)") &&
			!strings.Contains(got, "`defenseclaw sandbox stop box`")
	}
	for _, reason := range []string{
		errorPhaseReason(&audit.SandboxCondition{Type: "Ready", Status: "False", Reason: "ProvisioningTimedOut", Message: "Provisioning repair window expired after 300 seconds"}),
		errorPhaseReason(&audit.SandboxCondition{Type: "Ready", Status: "False", Reason: "ImagePreparationTimedOut", Message: "exceeded its absolute deadline"}),
	} {
		if got := errorPhaseWayOn("box", reason, upgrade, false); !timedOut(got) {
			t.Errorf("%q on an old gateway: %q", reason, got)
		}
		// A MicroVM OpenShell does not report stopped holds the upgrade,
		// and this OpenShell neither stops nor starts it: its delete.
		if got := errorPhaseWayOn("box", reason, upgrade, true); got != deleteFirst {
			t.Errorf("%q on an old gateway, a MicroVM: %q", reason, got)
		}
	}
	if got := errorPhaseWayOn("box", "Unavailable: the container stopped", upgrade, false); !strings.Contains(got, upgrade+", then `defenseclaw sandbox stop box` and `defenseclaw sandbox start box`") ||
		strings.Contains(got, "first `defenseclaw sandbox stop box`") {
		t.Errorf("another error state on an old gateway: %q", got)
	}
	// A MicroVM in any other error state holds the upgrade too: the old
	// gateway neither stops nor starts it, and only OpenShell's own state
	// (stopped, deleted, its VM gone) releases it. The way on is its
	// delete, then the upgrade; it promises no flush and no let-go. One
	// whose VM is gone has the plain way on.
	for _, reason := range []string{"MainProcessFailed: Canonical main process exited with status 1", "ProcessPollFailed: Bad file descriptor", ""} {
		if got := errorPhaseWayOn("box", reason, upgrade, true); got != deleteFirst {
			t.Errorf("a MicroVM in the error state (%q) on an old gateway: %q", reason, got)
		}
	}
	if got := errorPhaseWayOn("box", "ProcessExited: VM process exited with status 1", upgrade, true); got !=
		"this OpenShell can neither stop nor start a sandbox in its error state: "+upgrade+", then `defenseclaw sandbox stop box` and `defenseclaw sandbox start box`, which keep the sandbox and its work" {
		t.Errorf("a MicroVM whose VM is gone on an old gateway: %q", got)
	}

	e := newEnv(t, nil)
	connectAtFakeRelease(e)
	e.create(sandboxapi.CreateRequest{Name: "box"})
	e.fake.SetRelease("0.1.3")
	if _, err := e.tryCreate(sandboxapi.CreateRequest{Name: "fresh", Project: e.otherProject("other")}); err == nil {
		t.Fatal("a create on 0.1.3 succeeded")
	}
	if got := e.m.gatewayRelease(); got != "0.1.3" {
		t.Fatalf("gateway release = %q", got)
	}
	e.m.statusEvent(t.Context(), e.boxOf("box"), &stream.Status{Phase: openshell.PhaseError,
		Conditions: []stream.Condition{{Type: "Ready", Status: "False", Reason: "ProvisioningTimedOut", Message: "Provisioning repair window expired after 300 seconds"}}})
	var line string
	for _, ev := range e.events("box", sandboxapi.ActivityLifecycle, "") {
		if ev.Phase == string(audit.SandboxPhaseError) {
			line = ev.Message
		}
	}
	if !timedOut(line) {
		t.Fatalf("the feed's line on 0.1.3: %q", line)
	}
	refusal := e.m.errorPhaseRefusal("box", e.boxOf("box").rec.PhaseReason, "",
		&types.StatusError{Code: types.ErrorConflict, Message: "sandbox must be Stopped, Completed, or a failed main-process Error to start (current phase: Error)"})
	var apiErr *sandboxapi.Error
	if !errors.As(refusal, &apiErr) || !timedOut(apiErr.Detail) {
		t.Fatalf("the refusal on 0.1.3 = %v", refusal)
	}
}

// TestHoldsCompute: what stops the gateway on its own (a managed setup
// switch, the daemon's idle stop, its exit for a pending restart) waits
// for every sandbox that OpenShell does not report stopped, not only the
// running ones: one starting or stopping, in an unknown phase, or a
// MicroVM whose workload ended (completed, or in any error state but a VM
// that is gone), whose VM still runs (GAP-0012), however long it has been
// so; the rounds before let one go after two minutes, or on its user's
// stop, which OpenShell does not make for it. A docker sandbox in those
// phases is an exited container, whose writes the stop of docker kept,
// and a missing one is gone.
func TestHoldsCompute(t *testing.T) {
	vm, docker := string(openshell.DriverVM), string(openshell.DriverDocker)
	timedOut := "ProvisioningTimedOut: Provisioning repair window expired after 300 seconds"
	unpolled := "ProcessPollFailed: Bad file descriptor"
	failed := "MainProcessFailed: Canonical main process exited with status 1"
	gone := "ProcessExited: VM process exited with status 1"
	cases := []struct {
		phase          audit.SandboxPhase
		driver, reason string
		live           int
	}{
		{audit.SandboxPhaseReady, docker, "", 1},
		{audit.SandboxPhaseReady, vm, "", 1},
		{audit.SandboxPhaseCreating, vm, "", 1},
		{audit.SandboxPhaseProvisioning, vm, "", 1},
		{audit.SandboxPhaseStarting, docker, "", 1},
		{audit.SandboxPhaseStopping, vm, "", 1},
		{audit.SandboxPhaseUnknown, vm, "", 1},
		{"", docker, "", 1},
		{audit.SandboxPhaseError, vm, "", 1},
		{audit.SandboxPhaseError, "podman", "", 1},
		{audit.SandboxPhaseError, docker, "", 0},
		{audit.SandboxPhaseError, "", "", 0},
		{audit.SandboxPhaseError, vm, failed, 1},
		{audit.SandboxPhaseError, vm, unpolled, 1},
		{audit.SandboxPhaseError, vm, timedOut, 1},
		{audit.SandboxPhaseError, vm, gone, 0},
		{audit.SandboxPhaseError, docker, failed, 0},
		{audit.SandboxPhaseCompleted, vm, "", 1},
		{audit.SandboxPhaseCompleted, "podman", "", 1},
		{audit.SandboxPhaseCompleted, vm, timedOut, 1},
		{audit.SandboxPhaseCompleted, docker, "", 0},
		{audit.SandboxPhaseCompleted, "", "", 0},
		{audit.SandboxPhaseStopped, vm, "", 0},
		{audit.SandboxPhaseDeleting, vm, "", 0},
		{audit.SandboxPhaseDeleted, vm, "", 0},
		{phaseMissing, vm, "", 0},
	}
	for _, tc := range cases {
		v := sandboxapi.Sandbox{Phase: string(tc.phase), Driver: tc.driver, PhaseReason: tc.reason}
		if got := HoldsCompute(v); got != (tc.live == 1) {
			t.Errorf("HoldsCompute(%+v) = %v", v, got)
		}
	}

	// The status counts them (Live), apart from the running ones.
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "box"})
	status := func() *sandboxapi.Status {
		t.Helper()
		st, err := e.m.Status(t.Context())
		if err != nil || st.Live == nil {
			t.Fatalf("status = %+v, %v", st, err)
		}
		return st
	}
	if st := status(); st.Running != 1 || *st.Live != 1 || st.Busy() != 1 {
		t.Fatalf("a running sandbox: running %d, live %d", st.Running, *st.Live)
	}
	b := e.boxOf("box")
	for _, tc := range cases {
		if tc.phase == phaseMissing || tc.phase == audit.SandboxPhaseDeleted {
			continue
		}
		e.m.mu.Lock()
		b.phase, b.rec.Driver, b.rec.PhaseReason = tc.phase, tc.driver, tc.reason
		e.m.mu.Unlock()
		if st := status(); st.Running != boolInt(tc.phase == audit.SandboxPhaseReady) || *st.Live != tc.live || st.Busy() != tc.live {
			t.Errorf("%s on %s (reason %q): running %d, live %d, busy %d", tc.phase, tc.driver, tc.reason, st.Running, *st.Live, st.Busy())
		}
	}
	// A box OpenShell no longer has holds nothing.
	e.m.mu.Lock()
	b.phase, b.rec.Driver, b.rec.PhaseReason, b.missing = audit.SandboxPhaseError, vm, "", true
	e.m.mu.Unlock()
	if st := status(); *st.Live != 0 {
		t.Errorf("a missing MicroVM: live %d", *st.Live)
	}
	e.m.mu.Lock()
	b.missing = false
	e.m.mu.Unlock()
	// A daemon before Live does not say which phases its sandboxes are in:
	// every one counts.
	if got := (&sandboxapi.Status{Sandboxes: 2, Running: 0}).Busy(); got != 2 {
		t.Errorf("busy without live = %d", got)
	}
}

// boolInt is 1 for true, 0 for false.
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
