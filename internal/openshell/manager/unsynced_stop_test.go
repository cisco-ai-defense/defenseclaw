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
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// GAP-1163: a MicroVM's stop loses what its guest did not sync. A stop the
// user asks for, after a raw OpenShell start too, is held when the sync
// fails: the VM keeps running with its work and the refusal says how to
// save it. The organization's own stops (a hook alarm's on_tamper or
// on_silence response, a revoked registration) go ahead and say what they
// may have lost.
func TestAFailedSyncHoldsTheUsersStopButNotTheOrganizations(t *testing.T) {
	e := newVMEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "box", Copy: true})
	answer := "none\nsynced\n"
	e.fake.HandleExec(e.workloadChecks(nil, func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		return openshelltest.ExecResponse{Stdout: []byte(answer)}
	}))
	e.stopBox("box")
	// A raw OpenShell start: the cached phase still says stopped. The
	// harness exits; sync(1) does not finish.
	must(t, e.fake.SetPhase(openshell.DefaultWorkspace, "box", openshell.PhaseReady))
	answer = "exited\n"
	stops := e.fake.Calls(openshelltest.MethodStopSandbox)
	_, err := e.m.Stop(t.Context(), "box")
	if !sandboxapi.IsCode(err, sandboxapi.CodeConflict) || !strings.Contains(err.Error(), "box keeps running") ||
		!strings.Contains(err.Error(), "defenseclaw sandbox pull box") {
		t.Fatalf("user stop after a failed sync = %v", err)
	}
	if got := e.fake.Calls(openshelltest.MethodStopSandbox); got != stops {
		t.Fatalf("the held stop called OpenShell's stop %d times", got-stops)
	}
	if got := e.events("box", "", "stop_unflushed"); len(got) != 0 {
		t.Fatalf("a held stop was reported as one that lost writes: %+v", got)
	}

	// The organization's stop for an alarm goes ahead and says what it may
	// have lost.
	b := e.boxOf("box")
	e.m.mu.Lock()
	b.phase = audit.SandboxPhaseReady
	binding := b.rec.BindingID
	e.m.mu.Unlock()
	e.m.stopForAlarm("box", binding, audit.SandboxFindingHookTamper)
	if got := e.fake.Calls(openshelltest.MethodStopSandbox); got != stops+1 {
		t.Fatalf("the alarm stop made %d stop calls, want 1", got-stops)
	}
	if got := e.events("box", "", "stop_unflushed"); len(got) != 1 || !strings.Contains(got[0].Message, "may come back empty") {
		t.Fatalf("the alarm stop's loss was not said once: %+v", got)
	}
}

// A guest whose exec or sync keeps failing is not left to a delete that
// loses all of its work: the user's stop is held, and held again when
// repeated, also with --yes on a first stop; once a stop was held, the
// stop that accepts the loss (`sandbox stop --yes`) stops it with what
// reached its disk and the feed says what may be lost.
func TestARepeatedStopThatAcceptsTheLossStopsAVMWhoseSyncKeepsFailing(t *testing.T) {
	e := newVMEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "box", Copy: true})
	e.fake.HandleExec(e.workloadChecks(nil, func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		return openshelltest.ExecResponse{Stdout: []byte("exited\n")}
	}))
	stops := e.fake.Calls(openshelltest.MethodStopSandbox)
	accept := sandboxapi.WithUnsyncedStopAccepted(t.Context())
	for i, ctx := range []context.Context{accept, t.Context()} {
		_, err := e.m.Stop(ctx, "box")
		if !sandboxapi.IsCode(err, sandboxapi.CodeConflict) || !strings.Contains(err.Error(), "box keeps running") ||
			!strings.Contains(err.Error(), "`defenseclaw sandbox stop box --yes` stops it anyway") {
			t.Fatalf("stop %d after a failed sync = %v", i+1, err)
		}
	}
	if got := e.fake.Calls(openshelltest.MethodStopSandbox); got != stops {
		t.Fatalf("a held stop called OpenShell's stop %d times", got-stops)
	}
	if _, err := e.m.Stop(accept, "box"); err != nil {
		t.Fatalf("the stop that accepts the loss: %v", err)
	}
	if got := e.fake.Calls(openshelltest.MethodStopSandbox); got != stops+1 {
		t.Fatalf("the accepted stop made %d stop calls, want 1", got-stops)
	}
	if got := e.events("box", "", "stop_unflushed"); len(got) != 1 {
		t.Fatalf("the accepted stop's loss was not said once: %+v", got)
	}
	if got := e.get("box"); got.Phase != "stopped" {
		t.Fatalf("after the accepted stop: %s", got.Phase)
	}
}

// GAP-1594: a held stop accepts the loss only for a while. Long after it the
// sync may work again, and a routine `stop --yes` whose sync then fails is
// held first again, never made at once.
func TestAnOldHoldDoesNotLetAStopYesSkipTheNextHold(t *testing.T) {
	e := newVMEnv(t, nil)
	_, advance := e.fakeClock(time.Now())
	e.create(sandboxapi.CreateRequest{Name: "box", Copy: true})
	e.fake.HandleExec(e.workloadChecks(nil, func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		return openshelltest.ExecResponse{Stdout: []byte("exited\n")}
	}))
	stops := e.fake.Calls(openshelltest.MethodStopSandbox)
	if _, err := e.m.Stop(t.Context(), "box"); !sandboxapi.IsCode(err, sandboxapi.CodeConflict) {
		t.Fatalf("first stop after a failed sync = %v, want held", err)
	}
	advance(unsyncedStopAcceptWindow + time.Minute)
	accept := sandboxapi.WithUnsyncedStopAccepted(t.Context())
	if _, err := e.m.Stop(accept, "box"); !sandboxapi.IsCode(err, sandboxapi.CodeConflict) {
		t.Fatalf("stop --yes long after the hold = %v, want held again", err)
	}
	if got := e.fake.Calls(openshelltest.MethodStopSandbox); got != stops {
		t.Fatalf("a stop --yes long after the hold called OpenShell's stop %d times", got-stops)
	}
	// Right after that new hold, --yes goes ahead.
	if _, err := e.m.Stop(accept, "box"); err != nil {
		t.Fatalf("stop --yes right after the new hold: %v", err)
	}
}

// The listener-loss containment's stop (StopForPolicy) of a VM whose sync
// fails is made at once: one OpenShell stop, and the loss is said.
func TestThePolicyStopOfAVMWhoseSyncFailsIsMadeAtOnce(t *testing.T) {
	e := newVMEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "box", Copy: true})
	e.fake.HandleExec(e.workloadChecks(nil, func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		return openshelltest.ExecResponse{Stdout: []byte("exited\n")}
	}))
	stops := e.fake.Calls(openshelltest.MethodStopSandbox)
	if _, err := e.m.StopForPolicy(t.Context(), "box"); err != nil {
		t.Fatalf("policy stop: %v", err)
	}
	if got := e.fake.Calls(openshelltest.MethodStopSandbox); got != stops+1 {
		t.Fatalf("the policy stop made %d stop calls, want 1", got-stops)
	}
	if got := e.events("box", "", "stop_unflushed"); len(got) != 1 {
		t.Fatalf("the policy stop's loss was not said once: %+v", got)
	}
}
