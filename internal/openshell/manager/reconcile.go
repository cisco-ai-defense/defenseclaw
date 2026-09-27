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

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// loadRecords restores the boxes the daemon knew before a restart.
func (m *Manager) loadRecords() error {
	recs, errs := m.records.loadAll()
	for _, err := range errs {
		m.logf("%v", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range recs {
		if r.Owner != "" && r.Owner != m.opts.Owner {
			continue
		}
		b := &box{rec: *r, seenChunks: map[string]struct{}{}}
		m.boxes[r.Name] = b
		for _, pattern := range r.Unblocks {
			_ = m.unblocks.Add(egress.Unblock{Pattern: pattern, SandboxID: scopeID(r.ID, r.Name)})
		}
	}
	return nil
}

// Reconcile brings DefenseClaw's state in line with OpenShell's: it adopts
// sandboxes labelled for this data dir, releases everything held for
// sandboxes that are gone, revokes stale bindings, deletes orphaned
// providers, restarts watchers and republishes the lifecycle of every
// sandbox.
func (m *Manager) Reconcile(ctx context.Context) error {
	return m.reconcile(ctx, false)
}

func (m *Manager) reconcile(ctx context.Context, startup bool) error {
	m.reconcileMu.Lock()
	defer m.reconcileMu.Unlock()
	gw, err := m.gateway(ctx)
	if err != nil {
		return err
	}
	sbs, err := gw.Client.ListSandboxes(ctx, m.managedSelector())
	if err != nil {
		m.dropGateway(gw, err)
		return err
	}
	live := map[string]*openshell.Sandbox{}
	for _, sb := range sbs {
		live[sb.Name] = sb
	}

	// Sandboxes OpenShell has.
	for _, sb := range sbs {
		b := m.adopt(sb)
		if b == nil {
			continue
		}
		m.mu.Lock()
		creating := b.creating
		m.mu.Unlock()
		if creating {
			continue
		}
		phase := auditPhase(sb.Status.Phase)
		m.lifecycle(ctx, b, phase, audit.SandboxTriggerReconcile, startup, nil, sb.Status.ExitCode)
		m.startWatch(b)
		m.triageSandbox(ctx, b)
	}

	// Sandboxes DefenseClaw holds state for that OpenShell no longer has.
	m.mu.Lock()
	var gone []*box
	for name, b := range m.boxes {
		if _, ok := live[name]; !ok && !b.creating && !b.deleted {
			gone = append(gone, b)
		}
	}
	m.mu.Unlock()
	for _, b := range gone {
		if !b.op.TryLock() {
			continue // an operation is running; the next pass decides
		}
		m.gc(ctx, gw, b)
		b.op.Unlock()
	}

	// Bindings without a sandbox.
	m.mu.Lock()
	known := map[string]bool{}
	creating := map[string]bool{}
	for name, b := range m.boxes {
		known[b.rec.BindingID] = true
		if b.creating {
			creating[name] = true
		}
	}
	m.mu.Unlock()
	for _, binding := range m.opts.Bindings.List() {
		if known[binding.ID] || creating[binding.SandboxName] {
			continue
		}
		if _, ok := live[binding.SandboxName]; ok {
			continue
		}
		m.logf("revoking the binding of vanished sandbox %s", binding.SandboxName)
		_ = m.revokeBinding(binding.ID)
	}

	// Providers without a sandbox.
	if list, err := gw.Client.ListProviders(ctx); err == nil {
		for _, p := range list {
			if p.Labels[LabelManaged] != "true" || p.Labels[LabelOwner] != m.opts.Owner {
				continue
			}
			if _, ok := live[p.Labels[LabelSandbox]]; ok {
				continue
			}
			m.mu.Lock()
			b := m.boxes[p.Labels[LabelSandbox]]
			creating := b != nil && b.creating
			m.mu.Unlock()
			if creating {
				continue
			}
			if _, err := gw.Client.DeleteProvider(ctx, p.Name); err != nil && !openshell.IsNotFound(err) {
				m.logf("delete orphaned provider %s: %v", p.Name, err)
			}
		}
	}
	m.pruneApprovals()
	m.mu.Lock()
	m.lastReconcile = m.now()
	m.mu.Unlock()
	m.refreshEgress()
	return nil
}

// adopt returns the box for a live OpenShell sandbox, creating one from
// its labels and binding when the daemon holds no record, and marking it
// orphaned when no binding exists either.
func (m *Manager) adopt(sb *openshell.Sandbox) *box {
	binding, berr := m.opts.Bindings.Lookup(sb.Name)
	m.mu.Lock()
	b := m.boxes[sb.Name]
	if b == nil {
		b = &box{rec: record{
			Name: sb.Name, ID: sb.ID, Harness: sb.Labels[LabelHarness], Owner: m.opts.Owner,
			Profile: sb.Labels[LabelProfile], Pack: sb.Labels[LabelPack], WorkdirMode: sb.Labels[LabelWorkdirMode],
			CreatedAt: sb.CreatedAt, Image: templateImage(sb),
		}, seenChunks: map[string]struct{}{}}
		m.boxes[sb.Name] = b
	}
	if b.creating {
		m.mu.Unlock()
		return b
	}
	b.sb, b.missing = sb, false
	if b.rec.ID == "" {
		b.rec.ID = sb.ID
	}
	switch {
	case berr == nil:
		b.orphaned = false
		if b.rec.BindingID == "" {
			b.rec.BindingID = binding.ID
		}
	case errors.Is(berr, sandboxauth.ErrNotFound):
		b.orphaned = true
	}
	needCred := b.cred.Username == "" && b.rec.BindingID != "" && !b.orphaned
	username := b.rec.EgressUser
	rec := b.rec
	m.mu.Unlock()
	if needCred {
		if cred, ok := recoverCredential(sb, username); ok {
			eff, err := m.resolveBox(b)
			if err == nil {
				if err := m.creds.Register(cred, m.principal(rec.BindingID, scopeID(sb.ID, sb.Name), sb.Name, eff)); err == nil {
					m.mu.Lock()
					b.cred = cred
					b.rec.EgressUser = cred.Username
					m.mu.Unlock()
				}
			}
		}
	} else if _, err := m.resolveBox(b); err != nil {
		m.logf("resolve the policy of %s: %v", sb.Name, err)
	}
	if b.orphaned {
		m.logf("sandbox %s has DefenseClaw labels but no binding; its hooks cannot authenticate", sb.Name)
	}
	return b
}

func templateImage(sb *openshell.Sandbox) string {
	if sb.Spec.Template != nil {
		return sb.Spec.Template.Image
	}
	return ""
}

// gc releases what a sandbox deleted outside DefenseClaw held.
func (m *Manager) gc(ctx context.Context, gw *Gateway, b *box) {
	m.mu.Lock()
	name := b.rec.Name
	m.mu.Unlock()
	m.logf("sandbox %s is gone from OpenShell; releasing its binding, providers and mounts", name)
	m.stopWatch(b)
	m.mu.Lock()
	b.missing = true
	m.mu.Unlock()
	_, warnings := m.cleanup(ctx, gw, b, true)
	for _, w := range warnings {
		m.logf("release %s: %s", name, w)
	}
	m.lifecycle(ctx, b, audit.SandboxPhaseDeleted, audit.SandboxTriggerReconcile, false, nil, nil)
	m.forget(b)
}

// reconcileOne handles a watcher's report that its sandbox is gone.
func (m *Manager) reconcileOne(ctx context.Context, name string) {
	gw, err := m.gateway(ctx)
	if err != nil {
		return
	}
	if _, err := gw.Client.GetSandbox(ctx, name); !openshell.IsNotFound(err) {
		return
	}
	m.mu.Lock()
	b := m.boxes[name]
	m.mu.Unlock()
	if b == nil || !b.op.TryLock() {
		return
	}
	defer b.op.Unlock()
	m.mu.Lock()
	skip := b.creating || b.deleted
	m.mu.Unlock()
	if !skip {
		m.gc(ctx, gw, b)
	}
}
