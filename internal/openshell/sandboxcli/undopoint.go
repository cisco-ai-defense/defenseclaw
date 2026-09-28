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
	"path/filepath"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// The undo point of a mounted project. The daemon decides at every start:
// it takes a fresh snapshot unless the folder still holds changes an
// earlier session made that were neither undone nor accepted (a detached
// run, a terminal-less end), whose undo point it keeps so
// `undo` still reverts them. The user accepts the changes by keeping them
// at the end of a session ("Keep changes?" answered yes, --yes, or
// on_exit: keep), which the CLI records here, or with `start
// --new-snapshot`; the next start then asks for a fresh snapshot, so an
// accepted session is the base of the next one.

// acceptedUndoPoint is the snapshot the user accepted the changes on top of.
type acceptedUndoPoint struct {
	SandboxID string    `json:"sandbox_id,omitempty"`
	Snapshot  time.Time `json:"snapshot_created_at"`
}

// acceptUndoPoint records that the user kept the changes made on top of
// sb's current snapshot (best effort: without the record, the next start
// keeps the undo point, which only loses convenience).
func (a *App) acceptUndoPoint(sb *sandboxapi.Sandbox) {
	if sb == nil || sb.Snapshot == nil || sb.Snapshot.CreatedAt.IsZero() {
		return
	}
	dir, err := a.cliStateDir(sb.Name)
	if err != nil {
		return
	}
	data, err := json.Marshal(acceptedUndoPoint{SandboxID: sb.ID, Snapshot: sb.Snapshot.CreatedAt.UTC()})
	if err != nil {
		return
	}
	if err := safefile.WritePrivate(filepath.Join(dir, "accepted.json"), data); err != nil {
		a.warn("could not record that you kept the changes: " + err.Error())
	}
}

// accepted reports whether the user accepted the changes on top of sb's
// snapshot.
func (a *App) accepted(sb *sandboxapi.Sandbox) bool {
	if sb.WorkdirMode != config.OpenShellWorkdirMount || sb.Snapshot == nil || !sb.Snapshot.UndoneAt.IsZero() {
		return false
	}
	dir, err := a.cliStateDir(sb.Name)
	if err != nil {
		return false
	}
	data, err := safefile.ReadRegularFileBounded(filepath.Join(dir, "accepted.json"), 4<<10)
	if err != nil {
		return false
	}
	var rec acceptedUndoPoint
	if json.Unmarshal(data, &rec) != nil {
		return false
	}
	return rec.SandboxID == sb.ID && rec.Snapshot.Equal(sb.Snapshot.CreatedAt)
}

// startSandbox starts a stopped sandbox for a new session. It asks for a
// fresh snapshot when the user accepted the changes on top of the current
// one (or o says so), and otherwise leaves the choice to the daemon. It
// reports whether the undo point from before the start was kept, which
// the returned sandbox shows: its snapshot is still that one. A session
// (connect) accepts the changes at its end; `sandbox start` (session
// false) says how to accept them with --new-snapshot instead.
func (a *App) startSandbox(ctx context.Context, api API, sb *sandboxapi.Sandbox, o StartOptions, session bool) (*sandboxapi.Sandbox, bool, error) {
	req := sandboxapi.StartRequest{NoSnapshot: o.NoSnapshot, NewSnapshot: o.NewSnapshot}
	if !req.NoSnapshot && !req.NewSnapshot && a.accepted(sb) {
		req.NewSnapshot = true
	}
	started, err := api.Start(ctx, sb.Name, req)
	if err != nil {
		return nil, false, a.startError(sb, err)
	}
	a.forgetCleanCopy(sb.Name)
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
func (a *App) startError(sb *sandboxapi.Sandbox, err error) error {
	msg := apiError(err).Error()
	var e *sandboxapi.Error
	if errors.As(err, &e) && e.Violation != nil {
		switch e.Violation.Key {
		case "workdir.mode", "harness", "harness.allowed":
			return fmt.Errorf("%s; delete it (`%s delete %s`) and run it again", msg, CommandName, sb.Name)
		}
	}
	return errors.New(msg)
}

// keptUndoPoint reports whether a start kept the undo point it found: the
// sandbox still has the snapshot it had before, not undone.
func keptUndoPoint(before, after *sandboxapi.Sandbox) bool {
	return before != nil && after != nil && before.Snapshot != nil && after.Snapshot != nil &&
		before.Snapshot.UndoneAt.IsZero() && after.Snapshot.CreatedAt.Equal(before.Snapshot.CreatedAt)
}
