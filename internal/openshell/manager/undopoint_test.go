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
	"testing"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// Changes the user kept at the end of a session are accepted in the daemon,
// so the next start takes a new undo point whoever starts the sandbox (the
// TUI, the macOS app, a plain REST start), and survive a daemon restart; the
// start uses the acceptance up, so the next session's changes keep the undo
// point again.
func TestAcceptTakesANewUndoPointAtTheNextStart(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "acceptbox"})
	wantCode(t, acceptErr(e.m.Accept(t.Context(), "acceptbox", sandboxapi.AcceptRequest{})), sandboxapi.CodeConflict)
	e.stopBox("acceptbox")
	snap := e.ws.snapshots["acceptbox"]
	wantCode(t, acceptErr(e.m.Accept(t.Context(), "acceptbox", sandboxapi.AcceptRequest{Snapshot: snap.CreatedAt.Add(-time.Hour)})),
		sandboxapi.CodeConflict)
	sb, err := e.m.Accept(t.Context(), "acceptbox", sandboxapi.AcceptRequest{Snapshot: snap.CreatedAt})
	if err != nil || sb.Snapshot == nil || sb.Snapshot.AcceptedAt.IsZero() {
		t.Fatalf("accept = %+v, %v", sb, err)
	}
	if len(e.events("acceptbox", sandboxapi.ActivityWorkspace, "accepted")) != 1 {
		t.Fatal("the feed does not say the changes were kept")
	}
	e.restartDaemon()
	if got := e.get("acceptbox"); got.Snapshot == nil || got.Snapshot.AcceptedAt.IsZero() {
		t.Fatalf("the acceptance did not survive a restart: %+v", got.Snapshot)
	}
	e.startBox("acceptbox", sandboxapi.StartRequest{})
	if e.ws.snapshots["acceptbox"] == snap {
		t.Fatal("the start after an accept kept the old undo point")
	}
	if got := e.get("acceptbox"); got.Snapshot == nil || !got.Snapshot.AcceptedAt.IsZero() {
		t.Fatalf("the new undo point reads accepted: %+v", got.Snapshot)
	}
	// The new session's changes were not accepted: the next start keeps the
	// undo point for them.
	kept := e.ws.snapshots["acceptbox"]
	e.stopBox("acceptbox")
	e.startBox("acceptbox", sandboxapi.StartRequest{})
	if e.ws.snapshots["acceptbox"] != kept {
		t.Fatal("an acceptance applied twice")
	}
}

// A --no-snapshot start keeps the accepted undo point and uses the
// acceptance up: what that session changes was never accepted.
func TestNoSnapshotStartDropsTheAcceptance(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "nosnap"})
	e.stopBox("nosnap")
	snap := e.ws.snapshots["nosnap"]
	if _, err := e.m.Accept(t.Context(), "nosnap", sandboxapi.AcceptRequest{}); err != nil {
		t.Fatal(err)
	}
	e.startBox("nosnap", sandboxapi.StartRequest{NoSnapshot: true})
	e.stopBox("nosnap")
	e.startBox("nosnap", sandboxapi.StartRequest{})
	if e.ws.snapshots["nosnap"] != snap {
		t.Fatal("the changes of a --no-snapshot session were taken into a new undo point")
	}
}

// Accept applies to a stopped mounted sandbox with an undo point that was
// not undone.
func TestAcceptRefusals(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "copybox", Copy: true, Project: e.otherProject("copybox")})
	e.stopBox("copybox")
	wantCode(t, acceptErr(e.m.Accept(t.Context(), "copybox", sandboxapi.AcceptRequest{})), sandboxapi.CodeInvalid)
	e.create(sandboxapi.CreateRequest{Name: "undone"})
	if _, err := e.m.Undo(t.Context(), "undone", sandboxapi.UndoRequest{Stop: true}); err != nil {
		t.Fatal(err)
	}
	wantCode(t, acceptErr(e.m.Accept(t.Context(), "undone", sandboxapi.AcceptRequest{})), sandboxapi.CodeConflict)
	e.create(sandboxapi.CreateRequest{Name: "nosnapshot", NoSnapshot: true, Project: e.otherProject("nosnapshot")})
	e.stopBox("nosnapshot")
	wantCode(t, acceptErr(e.m.Accept(t.Context(), "nosnapshot", sandboxapi.AcceptRequest{})), sandboxapi.CodeNotFound)
	wantCode(t, acceptErr(e.m.Accept(t.Context(), "nobox", sandboxapi.AcceptRequest{})), sandboxapi.CodeNotFound)
}

// A keep answers the review of one session. A sandbox started again since
// (from the TUI, the macOS app or a detached run while the question was
// open) keeps the same undo point, with changes nobody reviewed on top: an
// accept that names the reviewed session is refused, so undo still reverts
// them. The count survives a daemon restart.
func TestAcceptRefusesASessionStartedSinceTheReview(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "raced"})
	stopped, err := e.m.Stop(t.Context(), "raced")
	must(t, err)
	reviewed, snap := stopped.Session, e.ws.snapshots["raced"]
	if reviewed == 0 {
		t.Fatal("the sandbox counts no session")
	}
	e.startBox("raced", sandboxapi.StartRequest{})
	e.stopBox("raced")
	if e.ws.snapshots["raced"] != snap {
		t.Fatal("the start took a new undo point over changes nobody accepted")
	}
	wantCode(t, acceptErr(e.m.Accept(t.Context(), "raced", sandboxapi.AcceptRequest{Snapshot: snap.CreatedAt, Session: reviewed})),
		sandboxapi.CodeConflict)
	e.restartDaemon()
	now := e.get("raced").Session
	if now != reviewed+1 {
		t.Fatalf("session = %d after a restart, want %d", now, reviewed+1)
	}
	if sb, err := e.m.Accept(t.Context(), "raced", sandboxapi.AcceptRequest{Snapshot: snap.CreatedAt, Session: now}); err != nil ||
		sb.Snapshot == nil || sb.Snapshot.AcceptedAt.IsZero() {
		t.Fatalf("accept of the session it names = %+v, %v", sb, err)
	}
}

// A start that fails before the sandbox runs uses nothing up: the changes
// the user kept stay accepted (and survive a restart), so the next start
// still takes a new undo point.
func TestAFailedStartKeepsTheAcceptance(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "failstart"})
	e.stopBox("failstart")
	snap := e.ws.snapshots["failstart"]
	if _, err := e.m.Accept(t.Context(), "failstart", sandboxapi.AcceptRequest{Snapshot: snap.CreatedAt}); err != nil {
		t.Fatal(err)
	}
	e.fake.FailNext(openshelltest.MethodStartSandbox, &types.StatusError{Code: types.ErrorInternal, Message: "driver busy"})
	if _, err := e.m.Start(t.Context(), "failstart", sandboxapi.StartRequest{NoSnapshot: true}); err == nil {
		t.Fatal("start succeeded")
	}
	if got := e.get("failstart"); got.Phase == "ready" || got.Snapshot == nil || got.Snapshot.AcceptedAt.IsZero() {
		t.Fatalf("after a start that never ran the sandbox: phase %s, snapshot %+v; want it stopped and still accepted", got.Phase, got.Snapshot)
	}
	e.restartDaemon()
	e.startBox("failstart", sandboxapi.StartRequest{})
	if e.ws.snapshots["failstart"] == snap {
		t.Fatal("the start after a failed one kept the undo point the user accepted the changes on")
	}
}

// A start that failed on DefenseClaw's side while OpenShell went on with it
// (the request was cut off, the connection dropped): the sandbox comes up
// anyway, and what that session changes on top of the accepted snapshot was
// not accepted. The next start keeps the undo point.
func TestASessionAfterAFailedStartEndsTheAcceptance(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "cutoff"})
	e.stopBox("cutoff")
	snap := e.ws.snapshots["cutoff"]
	if _, err := e.m.Accept(t.Context(), "cutoff", sandboxapi.AcceptRequest{Snapshot: snap.CreatedAt}); err != nil {
		t.Fatal(err)
	}
	e.fake.FailNext(openshelltest.MethodStartSandbox, &types.StatusError{Code: types.ErrorUnavailable, Message: "connection reset"})
	if _, err := e.m.Start(t.Context(), "cutoff", sandboxapi.StartRequest{NoSnapshot: true}); err == nil {
		t.Fatal("start succeeded")
	}
	must(t, e.fake.SetPhase(openshell.DefaultWorkspace, "cutoff", types.SandboxReady))
	must(t, e.m.Reconcile(t.Context()))
	if got := e.get("cutoff"); got.Phase != "ready" || got.Snapshot == nil || !got.Snapshot.AcceptedAt.IsZero() {
		t.Fatalf("the sandbox came up anyway: phase %s, snapshot %+v; want it ready and the acceptance ended", got.Phase, got.Snapshot)
	}
	e.stopBox("cutoff")
	e.startBox("cutoff", sandboxapi.StartRequest{})
	if e.ws.snapshots["cutoff"] != snap {
		t.Fatal("the start took a new undo point over a session nobody accepted")
	}
}

func acceptErr(_ *sandboxapi.Sandbox, err error) error { return err }
