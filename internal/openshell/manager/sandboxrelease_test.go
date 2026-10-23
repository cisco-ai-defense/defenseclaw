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
	"strings"
	"testing"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
)

// A sandbox retained across a 0.1.3 to 0.1.5 upgrade, or an older record
// with no release, stays running until its user explicitly stops it. No
// reconcile may retry an automatic stop, and no new run starts beside it.
func TestLegacySupervisorRequiresTheUsersStop(t *testing.T) {
	for _, release := range []string{"0.1.3", ""} {
		for _, vm := range []bool{false, true} {
			name := release
			if name == "" {
				name = "unversioned"
			}
			if vm {
				name += "-vm"
			}
			t.Run(name, func(t *testing.T) {
				e := newEnv(t, nil)
				if vm {
					e = newVMEnv(t, nil)
				}
				e.create(sandboxapi.CreateRequest{Name: "kept", Copy: true})
				e.addNetworkRule("kept", "direct", "background.example.org", 443)
				b := e.boxOf("kept")
				e.m.mu.Lock()
				b.rec.SessionRelease = release
				e.m.mu.Unlock()
				stops := e.fake.Calls(openshelltest.MethodStopSandbox)
				e.m.lifecycle(t.Context(), b, audit.SandboxPhaseReady, audit.SandboxTriggerWatch, true, nil, nil)
				e.m.tamperStops.Wait()
				must(t, e.m.Reconcile(t.Context()))
				e.m.tamperStops.Wait()
				if got := e.fake.Calls(openshelltest.MethodStopSandbox); got != stops {
					t.Fatalf("legacy guest was stopped without the user's request: %d calls", got-stops)
				}
				if got := e.get("kept"); got.Phase != "ready" || !got.OldSupervisor || !strings.Contains(strings.Join(got.Warnings, " "), "legacy sandbox running, not protected by the 1.0.4 egress policy") {
					t.Fatalf("legacy guest not reported as running and unprotected: %+v", got)
				}
				if e.hasRule("kept", "direct") || e.hasRule("kept", "defenseclaw_egress") {
					t.Fatal("DefenseClaw left direct network rules on a legacy guest")
				}
				if _, why, ok := e.m.creds.Suspended(b.cred.Username, b.cred.Password); !ok || !strings.Contains(why.Reason, "legacy sandbox running, not protected") {
					t.Fatalf("legacy guest proxy is not suspended: %+v, %t", why, ok)
				}
				_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "fresh", Copy: true, Project: e.otherProject("other")})
				if apiErr := wantCode(t, err, sandboxapi.CodeConflict); !strings.Contains(apiErr.Detail, "defenseclaw sandbox stop kept") {
					t.Fatalf("create did not name the manual stop: %+v", apiErr)
				}
				e.stopBox("kept")
				if got := e.fake.Calls(openshelltest.MethodStopSandbox); got != stops+1 {
					t.Fatalf("manual stop calls = %d, want one", got-stops)
				}
				e.create(sandboxapi.CreateRequest{Name: "fresh", Copy: true, Project: e.otherProject("other")})
				e.startBox("kept", sandboxapi.StartRequest{})
				if !e.hasRule("kept", "defenseclaw_egress") || e.hasRule("kept", "direct") {
					t.Fatal("the new supervisor did not restore the create-time network without the old direct approval")
				}
			})
		}
	}
}

// A failed rule withdrawal is a HIGH finding, not a reason to stop a guest
// and risk its unsynced writes. Reconciliation retries only the withdrawal.
func TestLegacySupervisorWithdrawalFailureNeverStopsTheGuest(t *testing.T) {
	e := newVMEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "kept", Copy: true})
	e.addNetworkRule("kept", "direct", "background.example.org", 443)
	b := e.boxOf("kept")
	e.m.mu.Lock()
	b.rec.SessionRelease = "0.1.3"
	e.m.mu.Unlock()
	e.fake.SetGlobalPolicy(&openshell.SandboxPolicy{Version: 1})
	stops := e.fake.Calls(openshelltest.MethodStopSandbox)
	e.m.lifecycle(t.Context(), b, audit.SandboxPhaseReady, audit.SandboxTriggerWatch, true, nil, nil)
	e.m.tamperStops.Wait()
	for range 2 {
		must(t, e.m.Reconcile(t.Context()))
		e.m.tamperStops.Wait()
	}
	if e.fake.Calls(openshelltest.MethodStopSandbox) != stops || e.get("kept").Phase != "ready" {
		t.Fatal("a failed withdrawal caused an automatic stop")
	}
	if warnings := strings.Join(e.get("kept").Warnings, " "); !strings.Contains(warnings, "could not withdraw the network rules") {
		t.Fatalf("failed withdrawal was hidden: %s", warnings)
	}
	e.fake.SetGlobalPolicy(nil)
	must(t, e.m.Reconcile(t.Context()))
	e.m.tamperStops.Wait()
	if e.hasRule("kept", "direct") || e.fake.Calls(openshelltest.MethodStopSandbox) != stops {
		t.Fatal("reconciliation did not withdraw the rule while preserving the guest")
	}
}

// TestAHostLeftOnAnOlderOpenShellUpgradesInPlace: DefenseClaw 1.0.0 to
// 1.0.3 left hosts on OpenShell 0.1.1 to 0.1.3, whose network broker can let
// a sandbox's connections bypass its policy (NVIDIA/OpenShell#4494). The
// daemon still connects to such a gateway and drives the sandboxes there
// (status, stop), so their work is kept, but creates and starts none,
// naming the in-place upgrade. A sandbox whose session runs that release's
// supervisor is stopped (GAP-0415) and starts again on the upgraded gateway
// only.
func TestAHostLeftOnAnOlderOpenShellUpgradesInPlace(t *testing.T) {
	e := newEnv(t, nil)
	e.m.opts.Connect = func(ctx context.Context) (*Gateway, error) {
		h, err := e.client.Health(ctx)
		if err != nil {
			return nil, err
		}
		gw := *e.gw
		gw.Version = h.RawVersion
		return &gw, nil
	}
	e.create(sandboxapi.CreateRequest{Name: "kept"})
	if got := e.boxOf("kept").rec.SessionRelease; got != openshell.SupportedMin {
		t.Fatalf("session release = %q, want %s", got, openshell.SupportedMin)
	}
	oldSupervisor := func() []sandboxapi.ActivityEvent {
		return e.events("kept", sandboxapi.ActivityFinding, sandboxapi.ReasonOldSupervisor)
	}
	if n := len(oldSupervisor()); n != 0 || e.get("kept").OldSupervisor {
		t.Fatalf("a session on %s is named: %d findings, warnings %v", openshell.SupportedMin, n, e.get("kept").Warnings)
	}

	// The host as 1.0.3 left it: its gateway runs 0.1.3.
	e.fake.SetRelease("0.1.3")
	_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "fresh", Project: e.otherProject("other")})
	apiErr := wantCode(t, err, sandboxapi.CodeUnavailable)
	if !strings.Contains(apiErr.Message, "OpenShell 0.1.3 runs no DefenseClaw sandbox") || !strings.Contains(apiErr.Message, "NVIDIA/OpenShell#4494") ||
		apiErr.Detail != "upgrade OpenShell 0.1.3 to "+openshell.InstallerVersion+" in place with `defenseclaw sandbox setup --install-openshell`" {
		t.Fatalf("create on 0.1.3 = %+v", apiErr)
	}
	if e.boxOf("fresh") != nil {
		t.Fatal("the refused create left a sandbox behind")
	}
	// A session that starts on it (outside DefenseClaw) runs its
	// supervisor: DefenseClaw reports it unprotected and waits for the user
	// to stop it; the old gateway starts it no more.
	e.m.statusEvent(t.Context(), e.boxOf("kept"), &stream.Status{Phase: openshell.PhaseProvisioning})
	e.m.statusEvent(t.Context(), e.boxOf("kept"), &stream.Status{Phase: openshell.PhaseReady})
	e.m.tamperStops.Wait()
	found := oldSupervisor()
	if len(found) != 1 || found[0].Severity != "HIGH" || !strings.Contains(found[0].Message, "its session started on OpenShell 0.1.3") ||
		!strings.Contains(found[0].Message, "legacy sandbox running, not protected by the 1.0.4 egress policy") ||
		!strings.Contains(found[0].Message, "`defenseclaw sandbox stop kept`") ||
		!strings.HasSuffix(found[0].Message, "and `defenseclaw sandbox start kept` starts it on that release's supervisor") {
		t.Fatalf("old-supervisor findings = %+v", found)
	}
	if got := e.get("kept"); got.Phase != "ready" || !got.OldSupervisor {
		t.Fatalf("a session on the 0.1.3 supervisor: phase %s, old supervisor %v, warnings %v", got.Phase, got.OldSupervisor, got.Warnings)
	}
	_, err = e.m.Start(t.Context(), "kept", sandboxapi.StartRequest{})
	if apiErr := wantCode(t, err, sandboxapi.CodeUnavailable); !strings.Contains(apiErr.Message, "OpenShell 0.1.3 runs no DefenseClaw sandbox") {
		t.Fatalf("start on 0.1.3 = %+v", apiErr)
	}

	// The in-place upgrade: the start goes on the new release's supervisor.
	e.fake.SetRelease(openshell.InstallerVersion)
	e.stopBox("kept")
	e.startBox("kept", sandboxapi.StartRequest{})
	if got := e.boxOf("kept").rec.SessionRelease; got != openshell.InstallerVersion {
		t.Fatalf("session release after the upgrade = %q", got)
	}
	if e.get("kept").OldSupervisor || len(oldSupervisor()) != 1 {
		t.Fatalf("after the upgrade: warnings %v, findings %d", e.get("kept").Warnings, len(oldSupervisor()))
	}
}

// A record from before DefenseClaw kept the session's release names no
// release, and the managed way on is the administrator's.
func TestOldSupervisorWordsForARecordWithoutARelease(t *testing.T) {
	msg := oldSupervisorMessage("box", "", audit.SandboxPhaseReady, "", "")
	if !strings.Contains(msg, "its session started before DefenseClaw kept the OpenShell release a session starts on, so it may run a supervisor older than "+openshell.SupportedMin) ||
		!strings.Contains(msg, "`defenseclaw sandbox stop box`") ||
		!strings.HasSuffix(msg, "then `defenseclaw sandbox start box` (or `connect`) starts it again on this gateway's supervisor") {
		t.Fatalf("message = %q", msg)
	}
	e := newEnv(t, nil)
	if got := e.m.upgradeWayOn(openshell.SupportedMin); got != "" {
		t.Fatalf("upgrade way on %s = %q", openshell.SupportedMin, got)
	}
	if got := e.m.upgradeWayOn("dev"); got != "" {
		t.Fatalf("upgrade way on an unreadable release = %q", got)
	}
}

// A failed manual stop keeps the old session release, and reconciliation
// never retries that stop behind the user's back. The next manual stop and
// start move it to the supported supervisor.
func TestAnOldSupervisorWaitsForTheUsersStopAfterAFailure(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "kept"})
	b := e.boxOf("kept")
	e.m.mu.Lock()
	b.rec.SessionRelease = ""
	e.m.mu.Unlock()
	stops := e.fake.Calls(openshelltest.MethodStopSandbox)
	e.m.lifecycle(t.Context(), b, audit.SandboxPhaseReady, audit.SandboxTriggerWatch, true, nil, nil)
	e.m.tamperStops.Wait()
	if got := e.get("kept"); got.Phase != "ready" || !got.OldSupervisor || e.fake.Calls(openshelltest.MethodStopSandbox) != stops {
		t.Fatalf("old unversioned session was stopped on discovery: %+v", got)
	}
	found := e.events("kept", sandboxapi.ActivityFinding, sandboxapi.ReasonOldSupervisor)
	if len(found) != 1 || !strings.Contains(found[0].Message, "its session started before DefenseClaw kept the OpenShell release") ||
		!strings.Contains(found[0].Message, "`defenseclaw sandbox stop kept`") {
		t.Fatalf("old supervisor finding = %+v", found)
	}
	e.fake.FailNext(openshelltest.MethodStopSandbox, &types.StatusError{Code: types.ErrorInternal, Message: "the gateway is busy"})
	if _, err := e.m.Stop(t.Context(), "kept"); err == nil {
		t.Fatal("the failed manual stop was reported as successful")
	}
	must(t, e.m.Reconcile(t.Context()))
	e.m.tamperStops.Wait()
	if got := e.get("kept"); got.Phase != "ready" || !got.OldSupervisor || b.rec.SessionRelease != "" || e.fake.Calls(openshelltest.MethodStopSandbox) != stops+1 {
		t.Fatalf("a failed stop was retried or counted as a new session: %+v, release %q, stop calls %d", got, b.rec.SessionRelease, e.fake.Calls(openshelltest.MethodStopSandbox)-stops)
	}
	e.stopBox("kept")
	e.startBox("kept", sandboxapi.StartRequest{})
	if got := e.get("kept"); got.Phase != "ready" || got.OldSupervisor || b.rec.SessionRelease != openshell.SupportedMin {
		t.Fatalf("manual stop and supported restart: %+v, release %q", got, b.rec.SessionRelease)
	}
}
