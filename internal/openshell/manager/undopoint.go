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

package manager

import (
	"context"
	"errors"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// The undo point of a mounted project. Every start decides whether the new
// session gets a fresh pre-session snapshot (Manager.start): it keeps the
// earlier one while the folder still holds changes an earlier session made
// that were neither undone nor accepted (keepSnapshot), so undo still
// reverts them, whoever starts the sandbox (the CLI, the TUI, the macOS
// app, `undo --restart`). The user accepts the changes by keeping them at
// the end of a session ("Keep changes?" answered yes, --yes, or on_exit:
// keep), which the CLI reports here (POST /sandboxes/{name}/accept), or
// with `start --new-snapshot`: the next start then takes a fresh snapshot,
// so an accepted session is the base of the next one.

// acceptedSnapshot is the user's acceptance of the changes made on top of a
// pre-session snapshot, which it names by creation time.
type acceptedSnapshot struct {
	Snapshot time.Time `json:"snapshot_created_at"`
	At       time.Time `json:"accepted_at"`
}

// acceptedFor reports whether a accepts the changes on top of snap: snap is
// the snapshot it names, and not undone.
func (a *acceptedSnapshot) acceptedFor(snap *workspace.SnapshotRecord) bool {
	return a != nil && snap != nil && snap.UndoneAt == nil && a.Snapshot.Equal(snap.CreatedAt)
}

// Accept records that the user kept the changes a session made on top of a
// stopped mounted sandbox's pre-session snapshot, so its next start takes a
// fresh snapshot instead of keeping this one. A running sandbox is refused:
// what it changes after the review would be accepted unreviewed. With
// req.Snapshot set, a sandbox whose snapshot is another one by now is
// refused too.
func (m *Manager) Accept(ctx context.Context, name string, req sandboxapi.AcceptRequest) (*sandboxapi.Sandbox, error) {
	b, unlock, err := m.lockBox(name)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := m.refuseRetained(b); err != nil {
		return nil, err
	}
	m.mu.Lock()
	mode := b.rec.WorkdirMode
	m.mu.Unlock()
	if mode != config.OpenShellWorkdirMount {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid,
			"%s works on a copy, which has no undo point to accept; `defenseclaw sandbox pull %s --apply` brings its work back", name, name)
	}
	gw, err := m.gateway(ctx)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, defaultOpTimeout)
	defer cancel()
	if err := m.checkSandbox(ctx, gw, b); err != nil {
		return nil, err
	}
	m.mu.Lock()
	sb := b.sb
	m.mu.Unlock()
	if !stoppedPhase(sb.Status.Phase) {
		return nil, sandboxapi.Errorf(sandboxapi.CodeConflict,
			"sandbox %s is running; stop it before accepting its changes, or what it changes after the review is accepted too", name)
	}
	snap, err := m.ws.LoadSnapshot(m.opts.DataDir, name)
	switch {
	case errors.Is(err, workspace.ErrSnapshotNotFound) || (err == nil && snap == nil):
		return nil, sandboxapi.Errorf(sandboxapi.CodeNotFound, "sandbox %s has no undo point", name)
	case err != nil:
		return nil, workspaceError(err)
	case snap.UndoneAt != nil:
		return nil, sandboxapi.Errorf(sandboxapi.CodeConflict,
			"sandbox %s was undone since: its folder is back at its undo point, so there are no changes to accept", name)
	case !req.Snapshot.IsZero() && !req.Snapshot.Equal(snap.CreatedAt):
		return nil, sandboxapi.Errorf(sandboxapi.CodeConflict,
			"sandbox %s has another undo point by now than the one its changes were reviewed against; review them again", name)
	}
	m.mu.Lock()
	b.rec.Accepted = &acceptedSnapshot{Snapshot: snap.CreatedAt.UTC(), At: m.now().UTC()}
	m.mu.Unlock()
	if err := m.saveRecord(b); err != nil {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInternal, "save sandbox state: %v", err)
	}
	m.logf("sandbox %s: the changes on top of its undo point were accepted; its next start takes a new one", name)
	m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityWorkspace, Sandbox: name, Reason: "accepted",
		Message: "the changes in sandbox " + name + "'s folder were kept: its next start takes a new undo point"})
	v := m.viewOf(b)
	return &v, nil
}

// acceptedNow reports whether the user accepted the changes on top of the
// sandbox's current pre-session snapshot.
func (m *Manager) acceptedNow(rec record) bool {
	if rec.Accepted == nil {
		return false
	}
	snap, err := m.ws.LoadSnapshot(m.opts.DataDir, rec.Name)
	return err == nil && rec.Accepted.acceptedFor(snap)
}

// dropAcceptance forgets an acceptance once a start used it: what the new
// session changes on top was not accepted (a --no-snapshot start keeps the
// accepted snapshot, and the next start must keep it again).
func (m *Manager) dropAcceptance(b *box) error {
	m.mu.Lock()
	had := b.rec.Accepted != nil
	b.rec.Accepted = nil
	m.mu.Unlock()
	if !had {
		return nil
	}
	return m.saveRecord(b)
}
