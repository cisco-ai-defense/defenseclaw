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
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// A create that is rolled back (the user pressed Ctrl-C while the image
// built, or a step failed) asks OpenShell to delete the sandbox it made. A
// MicroVM that is still provisioning outlives that delete for a while, and
// then the reconcile found a sandbox this daemon neither knew nor
// registered: on a managed computer it announced it as foreign ("it wasn't
// started with defenseclaw sandbox run"), though the person did start it
// with that command, and a second run of the same name failed with "already
// exists" until it went (GAP-0557). The daemon remembers the names it rolled
// back: such a sandbox is its own leftover, removed quietly, and the name is
// free to be created again at once.

// undoneWindow is how long after a rollback a sandbox of that name is
// taken for its leftover.
const undoneWindow = 30 * time.Minute

// noteUndone records that the create of name was rolled back.
func (m *Manager) noteUndone(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.undone == nil {
		m.undone = map[string]time.Time{}
	}
	now := m.now()
	for n, at := range m.undone {
		if now.Sub(at) > undoneWindow {
			delete(m.undone, n)
		}
	}
	m.undone[name] = now
}

// undoneCreate reports a name whose create was rolled back lately.
func (m *Manager) undoneCreate(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	at, ok := m.undone[name]
	if ok && m.now().Sub(at) > undoneWindow {
		delete(m.undone, name)
		return false
	}
	return ok
}

// forgetUndone drops name once a create of it succeeded.
func (m *Manager) forgetUndone(name string) {
	m.mu.Lock()
	delete(m.undone, name)
	m.mu.Unlock()
}

// reclaimUndone removes the leftover of a rolled-back create of name, if
// OpenShell still has one that carries this data directory's labels, and
// waits until it is gone, so a create of the name can go ahead. Nothing
// happens for a name that was not rolled back lately, or whose sandbox
// someone else made.
func (m *Manager) reclaimUndone(ctx context.Context, gw *Gateway, name string) {
	if !m.undoneCreate(name) {
		return
	}
	if err := m.deleteCreated(ctx, gw, name); err != nil {
		m.logf("create %s: remove the leftover of the rolled-back create: %v", name, err)
	}
}

// removeUndoneLeftover asks OpenShell to delete sb, a leftover of a create
// this daemon rolled back that is still there; the next reconcile asks
// again until it is gone. It reports whether sb is such a leftover whose
// delete OpenShell took: one whose delete failed still runs, so the caller
// stops and records it as it does any foreign sandbox (GAP-0658).
func (m *Manager) removeUndoneLeftover(ctx context.Context, gw *Gateway, sb *openshell.Sandbox) bool {
	if !m.undoneCreate(sb.Name) || !m.ownsLabels(sb.Labels) {
		return false
	}
	m.mu.Lock()
	b := m.boxes[sb.Name]
	creating := b != nil && b.creating
	m.mu.Unlock()
	if creating {
		return false
	}
	if _, err := gw.Client.DeleteSandbox(ctx, sb.Name); err != nil && !openshell.IsNotFound(err) {
		m.logf("remove the leftover of the rolled-back create of %s: %v", sb.Name, err)
		return false
	}
	return true
}
