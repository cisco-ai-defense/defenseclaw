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

package sandboxcli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// The undo point of a mounted project. The daemon decides at every start:
// it takes a fresh snapshot unless the folder still holds changes an
// earlier session made that were neither undone nor accepted (a detached
// run, a terminal-less end), whose undo point it keeps so `undo` still
// reverts them. The user accepts the changes by keeping them at the end of
// a session ("Keep changes?" answered yes, --yes, or on_exit: keep), which
// the CLI reports to the daemon (sandboxapi.AcceptRequest), or with `start
// --new-snapshot`; the next start then takes a fresh snapshot, whoever
// starts the sandbox, so an accepted session is the base of the next one.

// acceptChanges tells the daemon the user kept the changes made on top of
// sb's current snapshot, the one they were reviewed against (best effort:
// without it, the next start keeps the undo point, which only loses
// convenience).
func (a *App) acceptChanges(ctx context.Context, api API, sb *sandboxapi.Sandbox) {
	if sb == nil || sb.Snapshot == nil || sb.Snapshot.CreatedAt.IsZero() || !sb.Snapshot.UndoneAt.IsZero() {
		// An undone snapshot has no changes on top to accept.
		return
	}
	if _, err := api.Accept(ctx, sb.Name, sandboxapi.AcceptRequest{Snapshot: sb.Snapshot.CreatedAt}); err != nil {
		a.warn("could not record that you kept the changes (" + apiError(err).Error() + "); the next start keeps the undo point, and `" +
			CommandName + " start " + sb.Name + " --new-snapshot` takes a new one")
	}
}

// acceptedUndoPoint is the snapshot the user accepted the changes on top
// of, as an earlier CLI recorded it (cli/accepted.json) before the daemon
// kept acceptances: the next start still honours it.
type acceptedUndoPoint struct {
	SandboxID string    `json:"sandbox_id,omitempty"`
	Snapshot  time.Time `json:"snapshot_created_at"`
}

// legacyAcceptedFile is where an earlier CLI recorded an acceptance.
const legacyAcceptedFile = "accepted.json"

// forgetLegacyAcceptance removes an acceptance an earlier CLI recorded,
// once a start used it.
func (a *App) forgetLegacyAcceptance(name string) {
	if dir, err := a.cliStateDir(name); err == nil {
		_ = os.Remove(filepath.Join(dir, legacyAcceptedFile))
	}
}

// accepted reports whether an earlier CLI recorded that the user accepted
// the changes on top of sb's snapshot.
func (a *App) accepted(sb *sandboxapi.Sandbox) bool {
	if sb.WorkdirMode != config.OpenShellWorkdirMount || sb.Snapshot == nil || !sb.Snapshot.UndoneAt.IsZero() {
		return false
	}
	dir, err := a.cliStateDir(sb.Name)
	if err != nil {
		return false
	}
	data, err := safefile.ReadRegularFileBounded(filepath.Join(dir, legacyAcceptedFile), 4<<10)
	if err != nil {
		return false
	}
	var rec acceptedUndoPoint
	if json.Unmarshal(data, &rec) != nil {
		return false
	}
	return rec.SandboxID == sb.ID && rec.Snapshot.Equal(sb.Snapshot.CreatedAt)
}

// startSandbox starts a stopped sandbox for a new session. The daemon takes
// a fresh snapshot when the user accepted the changes on top of the current
// one (or o says so); an acceptance an earlier CLI recorded asks for one
// too. It reports whether the undo point from before the start was kept,
// which the returned sandbox shows: its snapshot is still that one. A
// session (connect) accepts the changes at its end; `sandbox start`
// (session false) says how to accept them with --new-snapshot instead.
func (a *App) startSandbox(ctx context.Context, api API, sb *sandboxapi.Sandbox, o StartOptions, session bool) (*sandboxapi.Sandbox, bool, error) {
	req := sandboxapi.StartRequest{NoSnapshot: o.NoSnapshot, NewSnapshot: o.NewSnapshot}
	legacy := a.accepted(sb)
	if !req.NoSnapshot && !req.NewSnapshot && legacy {
		req.NewSnapshot = true
	}
	// The session can change the copy: what it held as the sandbox stopped
	// is not known after this (a start that fails may still have started
	// it).
	a.forgetStoppedCopy(sb.Name)
	started, err := api.Start(ctx, sb.Name, req)
	if err != nil {
		return nil, false, a.startError(ctx, api, sb, err)
	}
	if legacy {
		// Used up, as the daemon uses its own acceptance up at a start.
		a.forgetLegacyAcceptance(sb.Name)
	}
	kept := keptUndoPoint(sb, started)
	if kept && !o.NoSnapshot {
		accept := "keeping the changes at the end of this session accepts them"
		if !session {
			accept = "to accept them instead, stop it and start it again with --new-snapshot (`" + CommandName + " stop " + sb.Name + "`, then `" +
				CommandName + " start " + sb.Name + " --new-snapshot`)"
		}
		a.note("kept the undo point from " + a.clock(started.Snapshot.CreatedAt) + ": the folder still holds changes made since that were not kept " +
			"at the end of a session, so `" + CommandName + " undo " + sb.Name + "` still reverts them; " + accept)
	}
	return started, kept, nil
}

// startError explains a refused start: a sandbox the policy no longer
// lets start as it was created (a live mount the organization now runs on
// a copy, a harness it no longer allows) can only be deleted and run
// again.
func (a *App) startError(ctx context.Context, api API, sb *sandboxapi.Sandbox, err error) error {
	msg := apiError(err).Error()
	var e *sandboxapi.Error
	if errors.As(err, &e) && e.Violation != nil {
		switch e.Violation.Key {
		case "workdir.mode", "harness", "harness.allowed":
			return fmt.Errorf("%s; delete it (`%s delete %s`) and run it again", msg, CommandName, sb.Name)
		}
	}
	return a.landlockHint(errors.New(msg), func() openshell.Driver { return statusDriver(ctx, api) })
}

// keptUndoPoint reports whether a start kept the undo point it found: the
// sandbox still has the snapshot it had before, not undone.
func keptUndoPoint(before, after *sandboxapi.Sandbox) bool {
	return before != nil && after != nil && before.Snapshot != nil && after.Snapshot != nil &&
		before.Snapshot.UndoneAt.IsZero() && after.Snapshot.CreatedAt.Equal(before.Snapshot.CreatedAt)
}
