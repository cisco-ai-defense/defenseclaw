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
	"slices"
	"strings"
	"testing"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
)

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
	if n := len(oldSupervisor()); n != 0 || slices.Contains(e.get("kept").Warnings, oldSupervisorWarning) {
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
	// supervisor: DefenseClaw stops it (GAP-0415), keeping its work, and the
	// old gateway starts it no more.
	e.m.statusEvent(t.Context(), e.boxOf("kept"), &stream.Status{Phase: openshell.PhaseProvisioning})
	e.m.statusEvent(t.Context(), e.boxOf("kept"), &stream.Status{Phase: openshell.PhaseReady})
	e.m.tamperStops.Wait()
	found := oldSupervisor()
	if len(found) != 1 || found[0].Severity != "HIGH" || !strings.Contains(found[0].Message, "kept's session started on OpenShell 0.1.3") ||
		!strings.Contains(found[0].Message, "DefenseClaw stops it now, as `defenseclaw sandbox stop kept` does; upgrade OpenShell 0.1.3 to "+openshell.InstallerVersion) ||
		!strings.HasSuffix(found[0].Message, "then `defenseclaw sandbox start kept` starts it on that release's supervisor") {
		t.Fatalf("old-supervisor findings = %+v", found)
	}
	if got := e.get("kept"); got.Phase != "stopped" || got.OldSupervisor || slices.Contains(got.Warnings, oldSupervisorWarning) {
		t.Fatalf("a session on the 0.1.3 supervisor: phase %s, old supervisor %v, warnings %v", got.Phase, got.OldSupervisor, got.Warnings)
	}
	_, err = e.m.Start(t.Context(), "kept", sandboxapi.StartRequest{})
	if apiErr := wantCode(t, err, sandboxapi.CodeUnavailable); !strings.Contains(apiErr.Message, "OpenShell 0.1.3 runs no DefenseClaw sandbox") {
		t.Fatalf("start on 0.1.3 = %+v", apiErr)
	}

	// The in-place upgrade: the start goes on the new release's supervisor.
	e.fake.SetRelease(openshell.InstallerVersion)
	e.startBox("kept", sandboxapi.StartRequest{})
	if got := e.boxOf("kept").rec.SessionRelease; got != openshell.InstallerVersion {
		t.Fatalf("session release after the upgrade = %q", got)
	}
	if slices.Contains(e.get("kept").Warnings, oldSupervisorWarning) || len(oldSupervisor()) != 1 {
		t.Fatalf("after the upgrade: warnings %v, findings %d", e.get("kept").Warnings, len(oldSupervisor()))
	}
}

// A record from before DefenseClaw kept the session's release names no
// release, and the managed way on is the administrator's.
func TestOldSupervisorWordsForARecordWithoutARelease(t *testing.T) {
	msg := oldSupervisorMessage("box", "", "")
	if !strings.Contains(msg, "box's session started before DefenseClaw kept the OpenShell release a session starts on, so it may run a supervisor older than "+openshell.SupportedMin) ||
		!strings.HasSuffix(msg, "DefenseClaw stops it now, as `defenseclaw sandbox stop box` does; `defenseclaw sandbox start box` (or `connect`) starts it again on this gateway's supervisor") {
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

// TestAnOldSupervisorIsStoppedBeforeAnySandboxRunsOnIt (GAP-0415): a session
// that began on the supervisor of an OpenShell older than SupportedMin, or
// one a 1.0.3 record names no release for, keeps that supervisor's network
// broker, which can let its connections bypass its policy, for as long as it
// runs, whatever the gateway runs now. DefenseClaw stops it as soon as it
// sees it, also on an upgraded gateway and for a restarted daemon, and the
// next start runs the gateway's own supervisor. A stop that fails keeps the
// session's release, says so, names it in the view for the CLI, and is tried again on each
// reconcile until the session stops.
func TestAnOldSupervisorIsStoppedBeforeAnySandboxRunsOnIt(t *testing.T) {
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
	sight := func(release string) {
		t.Helper()
		b := e.boxOf("kept")
		e.m.mu.Lock()
		b.rec.SessionRelease = release
		e.m.mu.Unlock()
		// The daemon restarted on 1.0.4 republishes what it finds.
		e.m.lifecycle(t.Context(), b, audit.SandboxPhaseReady, audit.SandboxTriggerWatch, true, nil, nil)
		e.m.tamperStops.Wait()
	}
	finding := func(text string) int {
		n := 0
		for _, ev := range e.events("kept", sandboxapi.ActivityFinding, sandboxapi.ReasonOldSupervisor) {
			if strings.Contains(ev.Message, text) {
				n++
			}
		}
		return n
	}

	// A record 1.0.3 wrote names no release: the session is stopped on the
	// upgraded gateway, and its start runs that gateway's supervisor.
	sight("")
	if got := e.get("kept"); got.Phase != "stopped" || got.OldSupervisor {
		t.Fatalf("a 1.0.3 session on a %s gateway: phase %s, old supervisor %v", openshell.SupportedMin, got.Phase, got.OldSupervisor)
	}
	if finding("kept's session started before DefenseClaw kept the OpenShell release") != 1 ||
		finding("`defenseclaw sandbox start kept` (or `connect`) starts it again on this gateway's supervisor") != 1 {
		t.Fatalf("findings = %+v", e.events("kept", sandboxapi.ActivityFinding, sandboxapi.ReasonOldSupervisor))
	}
	e.startBox("kept", sandboxapi.StartRequest{})
	e.m.tamperStops.Wait()
	if got := e.get("kept"); got.Phase != "ready" || got.OldSupervisor || e.boxOf("kept").rec.SessionRelease != openshell.SupportedMin {
		t.Fatalf("after the start: phase %s, old supervisor %v, release %q", got.Phase, got.OldSupervisor, e.boxOf("kept").rec.SessionRelease)
	}

	// A session on 0.1.3 whose stop fails: it still runs on that supervisor,
	// which the failed stop does not mistake for a new session, the feed
	// says so, and the view names it.
	e.fake.FailNext(openshelltest.MethodStopSandbox, &types.StatusError{Code: types.ErrorInternal, Message: "the gateway is busy"})
	sight("0.1.3")
	got := e.get("kept")
	if got.Phase != "ready" || !got.OldSupervisor || !slices.Contains(got.Warnings, oldSupervisorWarning) || e.boxOf("kept").rec.SessionRelease != "0.1.3" {
		t.Fatalf("after a failed stop: phase %s, old supervisor %v, warnings %v, release %q", got.Phase, got.OldSupervisor, got.Warnings, e.boxOf("kept").rec.SessionRelease)
	}
	if finding("DefenseClaw could not stop kept, whose session still runs the supervisor of OpenShell 0.1.3") != 1 {
		t.Fatalf("findings = %+v", e.events("kept", sandboxapi.ActivityFinding, sandboxapi.ReasonOldSupervisor))
	}
	// The daemon's next periodic reconcile, which forces no transition on a
	// sandbox still ready, tries the stop again, and it stops it.
	must(t, e.m.Reconcile(t.Context()))
	e.m.tamperStops.Wait()
	if got := e.get("kept"); got.Phase != "stopped" || got.OldSupervisor {
		t.Fatalf("the next reconcile: phase %s, old supervisor %v", got.Phase, got.OldSupervisor)
	}

	// A session on the gateway's own supervisor is left running.
	e.startBox("kept", sandboxapi.StartRequest{})
	sight(openshell.SupportedMin)
	if got := e.get("kept"); got.Phase != "ready" || got.OldSupervisor {
		t.Fatalf("a session on %s: phase %s, old supervisor %v", openshell.SupportedMin, got.Phase, got.OldSupervisor)
	}
}
