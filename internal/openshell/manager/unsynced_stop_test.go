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

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// stopBoxAcceptingLoss is the user's stop that accepted the loss of what a
// MicroVM has not synced (the CLI's yes, or --discard-unsynced).
func (e *harnessEnv) stopBoxAcceptingLoss(name string) {
	e.t.Helper()
	if _, err := e.m.Stop(sandboxapi.WithDiscardUnsynced(context.Background()), name); err != nil {
		e.t.Fatalf("Stop %s accepting the loss: %v", name, err)
	}
}

// GAP-0902: a MicroVM's stop went ahead after its disk sync failed, and the
// loss was published only after the stop. DefenseClaw now never stops a
// MicroVM whose sync failed on its own: the user's stop that did not accept
// the loss, a hook alarm's stop and the stop for foreign network rules all
// leave it running, make no StopSandbox call and publish no unflushed stop,
// whether the guest answered without confirming the sync or did not answer
// at all, and on a current session or a legacy one. The user's stop is
// refused with CodeUnsynced and the command that stops it anyway; the
// automatic ones publish a HIGH finding that says why. Only a stop whose
// user accepted the loss goes ahead, and then the feed says what it may have
// lost, once.
func TestNoStopAfterAFailedSyncUnlessTheUserAcceptsTheLoss(t *testing.T) {
	unconfirmed := guestAnswers("exited\n", false)
	silent := func(context.Context, openshelltest.ExecCall) openshelltest.ExecResponse {
		return openshelltest.ExecResponse{Err: errors.New("exec relay closed")}
	}
	type stopper struct {
		name    string
		stop    func(e *harnessEnv, b *box) error
		finding string
	}
	stoppers := []stopper{
		{name: "the user's stop", stop: func(e *harnessEnv, _ *box) error {
			_, err := e.m.Stop(context.Background(), "vmbox")
			return err
		}},
		{name: "a hook alarm", finding: string(audit.SandboxFindingHookTamper), stop: func(e *harnessEnv, b *box) error {
			e.m.stopForAlarm("vmbox", b.rec.BindingID, audit.SandboxFindingHookTamper)
			return nil
		}},
		{name: "foreign network rules", finding: policyReasonForeignRule, stop: func(e *harnessEnv, b *box) error {
			e.m.scheduleForeignStop("vmbox", b.rec.BindingID)
			e.m.tamperStops.Wait()
			return nil
		}},
	}
	for _, guest := range []struct {
		name string
		exec openshelltest.ExecHandler
	}{{"sync not confirmed", unconfirmed}, {"guest does not answer", silent}} {
		for _, legacy := range []bool{false, true} {
			for _, s := range stoppers {
				t.Run(guest.name+"/legacy="+map[bool]string{false: "no", true: "yes"}[legacy]+"/"+s.name, func(t *testing.T) {
					e := newVMEnv(t, nil)
					e.create(sandboxapi.CreateRequest{Name: "vmbox", Copy: true})
					b := e.boxOf("vmbox")
					if legacy {
						e.m.mu.Lock()
						b.rec.SessionRelease = "0.1.3"
						e.m.mu.Unlock()
						must(t, e.m.saveRecord(b))
					}
					e.fake.HandleExec(e.workloadChecks(nil, guest.exec))
					stops := e.fake.Calls(openshelltest.MethodStopSandbox)
					err := s.stop(e, b)
					if s.finding == "" {
						apiErr := wantCode(t, err, sandboxapi.CodeUnsynced)
						if !strings.Contains(apiErr.Message, "sandbox vmbox was not stopped: its MicroVM's disk could not be synced first") ||
							!strings.Contains(apiErr.Message, "it keeps running") ||
							!strings.Contains(apiErr.Detail, "`defenseclaw sandbox stop vmbox --discard-unsynced`") {
							t.Fatalf("the refused stop = %+v", apiErr)
						}
					} else {
						found := e.events("vmbox", sandboxapi.ActivityFinding, s.finding)
						if len(found) == 0 || !strings.Contains(found[len(found)-1].Message, "could not stop the sandbox") ||
							!strings.Contains(found[len(found)-1].Message, "could not be synced first") {
							t.Fatalf("the automatic stop did not say why it kept the sandbox: %+v", found)
						}
					}
					if got := e.fake.Calls(openshelltest.MethodStopSandbox); got != stops {
						t.Fatalf("stopped a MicroVM whose sync failed: %d stop calls", got-stops)
					}
					if got := e.get("vmbox"); got.Phase != "ready" {
						t.Fatalf("the MicroVM did not keep running: %s", got.Phase)
					}
					if got := e.events("vmbox", sandboxapi.ActivityLifecycle, "stop_unflushed"); len(got) != 0 {
						t.Fatalf("a stop that was not made was reported as one that lost writes: %+v", got)
					}

					// The user accepts the loss: the stop goes ahead and says
					// what it may have lost.
					e.stopBoxAcceptingLoss("vmbox")
					if got := e.fake.Calls(openshelltest.MethodStopSandbox); got != stops+1 {
						t.Fatalf("the accepted stop made %d stop calls", got-stops)
					}
					if got := e.get("vmbox"); got.Phase != "stopped" {
						t.Fatalf("the accepted stop left %s", got.Phase)
					}
					if got := e.events("vmbox", sandboxapi.ActivityLifecycle, "stop_unflushed"); len(got) != 1 {
						t.Fatalf("the accepted unflushed stop was not reported once: %+v", got)
					}
				})
			}
		}
	}

	// Docker's stop flushes nothing: a guest that does not answer still stops.
	d := liveEnv(t, "dockerstop", nil)
	d.fake.HandleExec(d.workloadChecks(nil, silent))
	d.stopBox("dockerstop")
	if got := d.get("dockerstop"); got.Phase != "stopped" {
		t.Fatalf("docker stop = %s", got.Phase)
	}
}

// GAP-0901: the daemon's status names every live legacy guest, with the
// command its user runs to end it (the managed lifecycle's status and verify
// read it), and nothing for a current session, a stopped legacy sandbox or
// a docker one whose workload ended.
func TestStatusNamesEveryUnprotectedLegacyGuest(t *testing.T) {
	e, b := legacyGuest(t, "kept", false, nil)
	e.m.lifecycle(t.Context(), b, audit.SandboxPhaseReady, audit.SandboxTriggerWatch, true, nil, nil)
	e.m.tamperStops.Wait()
	st, err := e.m.Status(t.Context())
	must(t, err)
	if len(st.Unprotected) != 1 || st.Unprotected[0] != (sandboxapi.UnprotectedSandbox{Name: "kept", Phase: "ready", Stop: "defenseclaw sandbox stop kept"}) {
		t.Fatalf("unprotected = %+v", st.Unprotected)
	}
	e.stopBox("kept")
	e.create(sandboxapi.CreateRequest{Name: "fresh", Copy: true, Project: e.otherProject("other")})
	st, err = e.m.Status(t.Context())
	must(t, err)
	if len(st.Unprotected) != 0 {
		t.Fatalf("a stopped legacy sandbox or a current session is named unprotected: %+v", st.Unprotected)
	}

	// An ended legacy MicroVM is named with its delete.
	v, vb := legacyGuest(t, "ended", true, nil)
	v.m.lifecycle(t.Context(), vb, audit.SandboxPhaseCompleted, audit.SandboxTriggerWatch, false, nil, nil)
	v.m.tamperStops.Wait()
	st, err = v.m.Status(t.Context())
	must(t, err)
	if len(st.Unprotected) != 1 || st.Unprotected[0].Stop != "defenseclaw sandbox delete ended" || st.Unprotected[0].Phase != "completed" {
		t.Fatalf("ended MicroVM unprotected = %+v", st.Unprotected)
	}
}

// GAP-1163: after a raw OpenShell start (the daemon's cached phase still
// says stopped) the user's stop syncs the MicroVM's disk first like any
// other, and one whose sync fails is not made: the VM keeps running with its
// work, OpenShell is not asked to stop it, and nothing is reported lost.
func TestAStopAfterARawStartIsNotMadeWhenTheSyncFails(t *testing.T) {
	e := newVMEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "box", Copy: true})
	answer := "none\nsynced\n"
	e.fake.HandleExec(e.workloadChecks(nil, func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		return openshelltest.ExecResponse{Stdout: []byte(answer)}
	}))
	e.stopBox("box")
	must(t, e.fake.SetPhase(openshell.DefaultWorkspace, "box", openshell.PhaseReady))
	answer = "exited\n"
	stops := e.fake.Calls(openshelltest.MethodStopSandbox)
	_, err := e.m.Stop(t.Context(), "box")
	apiErr := wantCode(t, err, sandboxapi.CodeUnsynced)
	if !strings.Contains(apiErr.Message, "sandbox box was not stopped") || !strings.Contains(apiErr.Message, "it keeps running") {
		t.Fatalf("user stop after a raw start and a failed sync = %+v", apiErr)
	}
	if got := e.fake.Calls(openshelltest.MethodStopSandbox); got != stops {
		t.Fatalf("the refused stop called OpenShell's stop %d times", got-stops)
	}
	if got := e.events("box", "", "stop_unflushed"); len(got) != 0 {
		t.Fatalf("a stop that was not made was reported as one that lost writes: %+v", got)
	}
	// With the sync working again, the next stop goes ahead synced.
	answer = "exited\nsynced\n"
	e.stopBox("box")
	if got := e.get("box"); got.Phase != "stopped" {
		t.Fatalf("after the synced stop: %s", got.Phase)
	}
}
