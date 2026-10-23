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
	"fmt"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// loadRecords restores the boxes the daemon knew before a restart.
func (m *Manager) loadRecords() error {
	recs, errs := m.records.loadAll()
	for _, err := range errs {
		m.logf("%v", err)
	}
	m.destMu.Lock()
	for _, r := range recs {
		if t := m.loadDestinations(r.Name); t != nil && !r.Retained {
			m.dests[r.Name] = t
		}
	}
	m.destMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range recs {
		if r.Owner != "" && r.Owner != m.opts.Owner {
			// The record is this data dir's (it lives in it), but the
			// sandbox was created under another owner id: the owner lives
			// in images.json, which was lost or replaced since. Skipping
			// the record would let reconciliation revoke the running
			// sandbox's binding and leave it beyond DefenseClaw's reach;
			// it is managed under the owner its labels carry instead.
			m.logf("sandbox %s was created under owner id %s, not this data dir's %s (was %s replaced?); "+
				"DefenseClaw keeps managing it under %s", r.Name, r.Owner, m.opts.Owner, "sandboxes/images.json", r.Owner)
		}
		b := &box{rec: *r, seenChunks: map[string]struct{}{}, retained: r.Retained}
		b.hooks.restore(r.HookCounts)
		if c := r.HookCounts; c != nil {
			b.reach.since, b.reach.reason, b.reach.noHookYet = c.UnreachableSince, c.UnreachableReason, c.NoHookYet
			b.silentSince = c.SilentSince
		}
		m.boxes[r.Name] = b
		for _, pattern := range r.Unblocks {
			_ = m.unblocks.Add(egress.Unblock{Pattern: pattern, SandboxID: scopeID(r.ID, r.Name)})
		}
		for _, host := range r.Approved {
			_ = m.approved.Add(egress.Unblock{Pattern: host, SandboxID: scopeID(r.ID, r.Name)})
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

func (m *Manager) reconcile(ctx context.Context, startup bool) (err error) {
	m.reconcileMu.Lock()
	defer m.reconcileMu.Unlock()
	managedDaemon := m.authority() != nil
	if managedDaemon {
		defer func() {
			if err != nil {
				m.reportWithoutGateway(ctx)
				return
			}
			m.reportForeignContainers(ctx)
			// Records kept while no sandbox was registered go out now if one is.
			m.flushManagedEvents(ctx, m.anyRegistration())
		}()
	}
	// Adoption stamps records with the driver the gateway runs now.
	gw, err := m.driverGateway(ctx)
	if err != nil {
		return err
	}
	sbs, err := m.listManaged(ctx, gw)
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
		b := m.adopt(sb, gw.Driver)
		if b == nil {
			continue
		}
		m.mu.Lock()
		creating := b.creating
		m.mu.Unlock()
		if creating {
			continue
		}
		if m.noteGateway(b, gw) {
			if err := m.saveRecord(b); err != nil {
				m.logf("save the record of %s: %v", sb.Name, err)
			}
		}
		phase := auditPhase(sb.Status.Phase)
		m.lifecycle(ctx, b, phase, audit.SandboxTriggerReconcile, startup, nil, sb.Status.ExitCode)
		m.reconcileOldSupervisor(ctx, b)
		m.startWatch(b)
		m.triageSandbox(ctx, b)
	}

	// Sandboxes DefenseClaw holds state for that OpenShell no longer has.
	m.mu.Lock()
	var gone []*box
	for name, b := range m.boxes {
		if _, ok := live[name]; !ok && !b.creating && !b.deleted && !b.retained {
			gone = append(gone, b)
		}
	}
	m.mu.Unlock()
	for _, b := range gone {
		if !b.op.TryLock() {
			continue // an operation is running; the next pass decides
		}
		// The list is a snapshot: a create may have finished, or a delete
		// and a create of the same name, while this pass was listing. Only
		// a sandbox OpenShell says is gone now is released, and only by
		// the gateway and workspace it was created on.
		if m.current(b) && m.goneNow(ctx, gw, b) && !m.gatewayElsewhere(ctx, gw, b) {
			m.gc(ctx, gw, b)
		}
		b.op.Unlock()
	}

	// Bindings without a sandbox. The bindings are listed before the boxes
	// are: a create reserves its box (creating) before it mints its
	// binding, so each binding listed belongs to a box seen below, known or
	// creating. Listed after, a binding minted between the two reads looked
	// vanished and was revoked under the create.
	bindings := m.opts.Bindings.List()
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
	for _, binding := range bindings {
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
			// A sandbox DefenseClaw still holds (created after the list,
			// or kept by the pass above) owns its providers.
			m.mu.Lock()
			b := m.boxes[p.Labels[LabelSandbox]]
			held := b != nil && !b.deleted && !b.retained
			m.mu.Unlock()
			if held {
				continue
			}
			if _, err := gw.Client.GetSandbox(ctx, p.Labels[LabelSandbox]); !openshell.IsNotFound(err) {
				continue
			}
			if _, err := gw.Client.DeleteProvider(ctx, p.Name); err != nil && !openshell.IsNotFound(err) {
				m.logf("delete orphaned provider %s: %v", p.Name, err)
			}
		}
	}
	if managedDaemon {
		m.refreshDecisions(ctx)
		m.reconcileForeign(ctx, gw, live)
	}
	m.deleteExpired(ctx)
	m.pruneApprovals()
	m.mu.Lock()
	m.lastReconcile = m.now()
	m.mu.Unlock()
	m.refreshEgress()
	m.enforceAll(ctx)
	return nil
}

// reportWithoutGateway is what a managed daemon's reconcile owes the
// managed gateway while the OpenShell gateway can't be reached or listed:
// neither needs it. The containers that run an agent are looked into, at
// most once a reconcile interval (the reconnects come faster), and the
// records kept go out. Outside managed mode it does nothing.
func (m *Manager) reportWithoutGateway(ctx context.Context) {
	if m.authority() == nil {
		return
	}
	st := m.managedSide()
	st.mu.Lock()
	due := st.containersAt.IsZero() || m.now().Sub(st.containersAt) >= m.opts.ReconcileInterval
	st.mu.Unlock()
	if due {
		m.reportForeignContainers(ctx)
	}
	m.flushManagedEvents(ctx, m.anyRegistration())
}

// reconcileForeign stops, or reports, every sandbox on the user's OpenShell
// gateway that DefenseClaw did not create and register (a managed daemon):
// one without this data dir's labels (made with OpenShell's own CLI, say),
// or a labelled one the managed gateway never registered. A managed host
// runs the person's agents only in sandboxes its policy resolved, so
// foreign_sandboxes is stop unless every floor in force says alert. live
// are the sandboxes this pass found labelled for this data dir.
func (m *Manager) reconcileForeign(ctx context.Context, gw *Gateway, live map[string]*openshell.Sandbox) {
	all, err := gw.Client.ListSandboxes(ctx, nil)
	if err != nil {
		m.logf("list every sandbox of the OpenShell gateway: %v", err)
		return
	}
	pass := foreignPass{
		stop:         m.foreignSandboxAction() == config.OpenShellForeignSandboxesStop,
		registration: m.anyRegistration(),
		running:      map[string]bool{},
	}
	st := m.managedSide()
	left := 0 // foreign sandboxes this pass leaves running (ForeignSandboxesRunning)
	defer func() {
		// A removal that is no longer pending (the sandbox is gone or no
		// longer runs) is forgotten; one the context cut short stays.
		if ctx.Err() != nil {
			return
		}
		st.mu.Lock()
		for key := range st.foreignRemoving {
			if !pass.running[key] {
				delete(st.foreignRemoving, key)
			}
		}
		st.foreignLeft = left
		st.mu.Unlock()
	}()
	for _, sb := range all {
		if ctx.Err() != nil {
			return
		}
		if m.removeUndoneLeftover(ctx, gw, sb) {
			// Its own leftover of a create that was rolled back, not a
			// foreign sandbox (GAP-0557).
			continue
		}
		if !m.foreignSandbox(sb, live) {
			continue
		}
		if m.foreignOne(ctx, pass, gw, "", sb) {
			left++
		}
	}
	// The account's other OpenShell gateways (one the user started by hand
	// and registered with the CLI, say) run no managed sandbox: everything
	// running on them is foreign (GAP-0678). What they leave running does
	// not keep the managed gateway up (ForeignSandboxesRunning).
	if m.opts.OtherGateways == nil {
		return
	}
	for _, other := range m.opts.OtherGateways(ctx, gw) {
		if ctx.Err() == nil {
			if sbs, err := other.Client.ListSandboxes(ctx, nil); err != nil {
				m.logf("list the sandboxes of OpenShell gateway %s: %v", other.Name, err)
			} else {
				for _, sb := range sbs {
					if ctx.Err() != nil {
						break
					}
					m.foreignOne(ctx, pass, other, other.Name, sb)
				}
			}
		}
		if other.Close != nil {
			_ = other.Close()
		}
	}
}

// foreignPass is what one reconcileForeign pass holds for each foreign
// sandbox: the action, the registration its records go under, and the keys
// of the foreign sandboxes found running.
type foreignPass struct {
	stop         bool
	registration string
	running      map[string]bool
}

// foreignOne stops or reports one foreign sandbox of gw (otherGateway names
// gw when it is not the managed gateway) and reports whether it is left
// running.
func (m *Manager) foreignOne(ctx context.Context, pass foreignPass, gw *Gateway, otherGateway string, sb *openshell.Sandbox) bool {
	st := m.managedSide()
	key := "sandbox:" + firstNonEmpty(sb.ID, sb.Name)
	where := "the OpenShell gateway"
	if otherGateway != "" {
		key = "sandbox:" + otherGateway + "/" + firstNonEmpty(sb.ID, sb.Name)
		where = "the other OpenShell gateway " + otherGateway
	}
	switch auditPhase(sb.Status.Phase) {
	case audit.SandboxPhaseProvisioning, audit.SandboxPhaseStarting, audit.SandboxPhaseReady, audit.SandboxPhaseUnknown,
		audit.SandboxPhaseError: // a sandbox in error may still run its containers
	default:
		return false // not running: nothing runs under no policy
	}
	pass.running[key] = true
	left := false
	action := config.OpenShellForeignSandboxesAlert
	outcome := foreignStopped
	if pass.stop {
		action = config.OpenShellForeignSandboxesStop
		st.mu.Lock()
		tries, pending := st.foreignRemoving[key]
		st.mu.Unlock()
		var err error
		if outcome, err = m.stopForeign(ctx, gw, sb); err != nil {
			// Still running: the next reconcile tries again.
			m.logf("%s: stop foreign sandbox %s on %s: %v", gatewaylog.ErrCodeOpenShellAdminViolation, sb.Name, where, err)
			return true
		}
		if outcome == foreignRemoving {
			left = true
			tries++
			st.mu.Lock()
			st.foreignRemoving[key] = tries
			st.mu.Unlock()
			if tries == foreignRemoveTries {
				m.logf("%s: foreign sandbox %s on %s is still %s after %d removals; it is removed again at every reconcile",
					gatewaylog.ErrCodeOpenShellAdminViolation, sb.Name, where, sb.Status.Phase, tries)
				m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityFinding, Sandbox: sb.Name, Severity: "HIGH",
					Reason: sandboxrelay.EventForeignSandbox, Message: truncate(sandboxapi.ForeignNotRemoved(sb.Name, string(sb.Status.Phase)), 512)})
			}
		}
		if pending {
			// Recorded and told when its removal began: this pass only
			// tried again.
			return left
		}
	} else {
		left = true
		st.mu.Lock()
		seen := st.reported[key]
		st.reported[key] = true
		st.mu.Unlock()
		if seen {
			return left
		}
	}
	m.logf("%s: sandbox %s on %s was not started with defenseclaw sandbox run (%s)",
		gatewaylog.ErrCodeOpenShellAdminViolation, sb.Name, where, action)
	m.managedEvent(ctx, pass.registration, sandboxrelay.EventForeignSandbox, map[string]any{
		"sandbox": truncate(sb.Name, 128), "sandbox_id": truncate(sb.ID, 128), "action": action,
		"harness": truncate(sb.Labels[LabelHarness], 64),
	})
	msg := sandboxapi.ForeignStopped(sb.Name)
	switch {
	case !pass.stop:
		msg = sandboxapi.ForeignAlerted(sb.Name)
	case outcome == foreignRemoved:
		msg = sandboxapi.ForeignRemoved(sb.Name)
	case outcome == foreignRemoving:
		msg = sandboxapi.ForeignRemoving(sb.Name)
	}
	m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityFinding, Sandbox: sb.Name, Severity: "HIGH",
		Reason: sandboxrelay.EventForeignSandbox, Message: truncate(msg, 512)})
	return left
}

// ForeignSandboxesRunning reports whether the last reconcile of a managed
// daemon left a foreign sandbox running on the OpenShell gateway
// (foreign_sandboxes: alert, or a stop or delete that has not taken yet). The
// daemon does not stop that gateway as idle: the sandbox runs on it, and an
// alerted one would fail under the person (GAP-0263).
func (m *Manager) ForeignSandboxesRunning() bool {
	st := m.managedSide()
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.foreignLeft > 0
}

// foreignOutcome is what one stop of a foreign sandbox did (stopForeign).
type foreignOutcome int

const (
	// foreignStopped: OpenShell stopped it.
	foreignStopped foreignOutcome = iota
	// foreignRemoved: it was deleted and is gone.
	foreignRemoved
	// foreignRemoving: the delete was taken, but the sandbox is still
	// there (a MicroVM still provisioning, say); every reconcile deletes
	// it again (managedState.foreignRemoving).
	foreignRemoving
)

// foreignRemoveTries is the number of reconciles a foreign sandbox may
// outlive its delete before the person is told to remove it.
const foreignRemoveTries = 3

// stopForeign stops a foreign sandbox whatever its phase: OpenShell stops
// only a Ready sandbox, so one it refuses to stop that is not Ready (still
// provisioning or starting, or in error) is deleted instead, since nothing
// may run under no policy. A delete OpenShell takes is removed only once
// the sandbox is gone (GAP-0264: a provisioning MicroVM outlived its
// delete). An error leaves the sandbox for the next reconcile. The record's
// action stays stop: the sandbox no longer runs either way.
func (m *Manager) stopForeign(ctx context.Context, gw *Gateway, sb *openshell.Sandbox) (foreignOutcome, error) {
	_, err := gw.Client.StopSandbox(ctx, sb.Name)
	if err == nil || openshell.IsNotFound(err) {
		return foreignStopped, nil
	}
	if auditPhase(sb.Status.Phase) == audit.SandboxPhaseReady {
		return foreignStopped, err
	}
	m.logf("%s: OpenShell did not stop foreign sandbox %s (%s): %v; deleting it", gatewaylog.ErrCodeOpenShellAdminViolation,
		sb.Name, sb.Status.Phase, err)
	if _, derr := gw.Client.DeleteSandbox(ctx, sb.Name); derr != nil && !openshell.IsNotFound(derr) {
		return foreignStopped, fmt.Errorf("%w; delete: %w", err, derr)
	}
	now, gerr := gw.Client.GetSandbox(ctx, sb.Name)
	switch {
	case openshell.IsNotFound(gerr):
		return foreignRemoved, nil
	case gerr == nil && sb.ID != "" && now.ID != "" && now.ID != sb.ID:
		return foreignRemoved, nil // gone; another sandbox took the name
	default:
		return foreignRemoving, nil
	}
}

// registrationBindGrace is how long a sandbox this daemon created may run
// before its registration is bound (the managed daemon binds it right
// after the create returns): as long as a pending registration lives.
const registrationBindGrace = sandboxreg.PendingTTL

// foreignSandbox reports a sandbox on the gateway DefenseClaw did not
// create and register: not labelled for this data dir, or labelled with no
// box, a box of another sandbox of that name, or a box without a
// registration (registrationOf). A box being created is never foreign, nor
// one this daemon created (its record and binding are its own) within
// registrationBindGrace of its create.
func (m *Manager) foreignSandbox(sb *openshell.Sandbox, live map[string]*openshell.Sandbox) bool {
	m.mu.Lock()
	b := m.boxes[sb.Name]
	if b != nil && b.creating {
		m.mu.Unlock()
		return false
	}
	_, labelled := live[sb.Name]
	if !labelled || b == nil || b.deleted || b.retained || (b.rec.ID != "" && sb.ID != "" && b.rec.ID != sb.ID) {
		m.mu.Unlock()
		return true
	}
	own := !b.unrecorded && b.rec.BindingID != ""
	since := b.rec.CreatedAt
	if b.rec.ReadyAt.After(since) {
		since = b.rec.ReadyAt
	}
	m.mu.Unlock()
	if m.registrationOf(b) != "" {
		return false
	}
	return !own || m.now().Sub(since) >= registrationBindGrace
}

// foreignSandboxAction is stop unless the floor of every registered
// sandbox says alert (stop wins, "" is stop when managed). With no
// registered sandbox it is the daemon's own floor's: the one of the
// person's newest registration, which the managed daemon keeps, or the
// strictest before any.
func (m *Manager) foreignSandboxAction() string {
	var floors []config.OpenShellAdminConfig
	for _, b := range m.liveBoxes() {
		if m.registrationOf(b) == "" {
			continue
		}
		m.mu.Lock()
		eff := b.eff
		m.mu.Unlock()
		floors = append(floors, m.floor(eff))
	}
	if len(floors) == 0 {
		floors = append(floors, m.config().OpenShell.Admin)
	}
	for _, f := range floors {
		if !strings.EqualFold(strings.TrimSpace(f.ForeignSandboxes), config.OpenShellForeignSandboxesAlert) {
			return config.OpenShellForeignSandboxesStop
		}
	}
	return config.OpenShellForeignSandboxesAlert
}

// anyRegistration is a registration of the person's live sandboxes, which
// a record about none of them is posted under ("" when there is none).
func (m *Manager) anyRegistration() string {
	best := ""
	for _, b := range m.liveBoxes() {
		if r := m.registrationOf(b); r != "" && (best == "" || r < best) {
			best = r
		}
	}
	return best
}

// listManaged lists the sandboxes on gw that carry this data dir's labels:
// its own owner's, and those of an earlier owner id a record was created
// under (see loadRecords), limited to the names recorded under it, so a
// sandbox of another data dir that still uses that id is never adopted.
func (m *Manager) listManaged(ctx context.Context, gw *Gateway) ([]*openshell.Sandbox, error) {
	earlier := map[string]map[string]bool{}
	m.mu.Lock()
	for name, b := range m.boxes {
		if o := b.rec.Owner; o != "" && o != m.opts.Owner {
			if earlier[o] == nil {
				earlier[o] = map[string]bool{}
			}
			earlier[o][name] = true
		}
	}
	m.mu.Unlock()
	out, err := gw.Client.ListSandboxes(ctx, m.managedSelector())
	if err != nil {
		return nil, err
	}
	owners := make([]string, 0, len(earlier))
	for o := range earlier {
		owners = append(owners, o)
	}
	sort.Strings(owners)
	for _, owner := range owners {
		sbs, err := gw.Client.ListSandboxes(ctx, map[string]string{LabelManaged: "true", LabelOwner: owner})
		if err != nil {
			return nil, err
		}
		for _, sb := range sbs {
			if earlier[owner][sb.Name] {
				out = append(out, sb)
			}
		}
	}
	return out, nil
}

// goneNow asks OpenShell whether b's sandbox is gone (NotFound, or a
// different sandbox under the same name).
func (m *Manager) goneNow(ctx context.Context, gw *Gateway, b *box) bool {
	m.mu.Lock()
	name, id := b.rec.Name, b.rec.ID
	m.mu.Unlock()
	sb, err := gw.Client.GetSandbox(ctx, name)
	switch {
	case openshell.IsNotFound(err):
		return true
	case err != nil:
		return false
	default:
		return id != "" && sb.ID != "" && sb.ID != id
	}
}

// adopt returns the box for a live OpenShell sandbox, creating one from
// its labels and binding when the daemon holds no record, and marking it
// orphaned when no binding exists either. A sandbox adopted without a
// record is taken to run on the gateway's driver: it is live there.
func (m *Manager) adopt(sb *openshell.Sandbox, driver openshell.Driver) *box {
	binding, berr := m.opts.Bindings.Lookup(sb.Name)
	m.mu.Lock()
	b := m.boxes[sb.Name]
	if b == nil {
		// No readable record: the labels name the harness, profile and
		// pack, but not the run flags or the project, so the sandbox's
		// policy cannot be rebuilt. It fails closed (errUnrecorded).
		b = &box{rec: record{
			Name: sb.Name, ID: sb.ID, Harness: sb.Labels[LabelHarness], Owner: m.opts.Owner,
			Profile: sb.Labels[LabelProfile], Pack: sb.Labels[LabelPack], WorkdirMode: sb.Labels[LabelWorkdirMode],
			CreatedAt: sb.CreatedAt, Image: templateImage(sb), Driver: string(driver.Name),
		}, seenChunks: map[string]struct{}{}, unrecorded: true}
		m.boxes[sb.Name] = b
	}
	if b.creating {
		m.mu.Unlock()
		return b
	}
	if b.retained {
		// The name is held by the kept snapshot of an earlier sandbox; the
		// live one is left alone until that is deleted.
		m.mu.Unlock()
		m.logf("sandbox %s exists in OpenShell, but the name holds the kept snapshot of a deleted sandbox; "+
			"run `defenseclaw sandbox delete %s` to drop the snapshot and adopt it", sb.Name, sb.Name)
		return nil
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
	m.mu.Unlock()
	if needCred {
		// The credential comes back before the policy resolves: a sandbox
		// whose policy does not resolve then has it suspended (the proxy's
		// 403 names why, next to the degraded record that says what to do)
		// rather than unknown to the proxy, whose 407s read as a stale or
		// revoked credential in a second alert (GAP-0180).
		cred, ok := recoverCredential(sb, username)
		if needCred = ok; ok {
			m.mu.Lock()
			b.cred = cred
			b.rec.EgressUser = cred.Username
			m.mu.Unlock()
		}
	}
	eff, err := m.resolveBox(b)
	if err != nil {
		m.logf("resolve the policy of %s: %v", sb.Name, err)
	} else if needCred {
		m.syncCredential(b, eff)
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
	m.finishGuard(ctx, b)
	m.stopWatch(b)
	m.mu.Lock()
	b.missing = true
	m.mu.Unlock()
	// The user deleted the sandbox elsewhere, but the project folder may
	// still hold what its agent did: its snapshot is kept, and so is the
	// box, for undo, review and delete.
	_, warnings, retained := m.cleanup(ctx, gw, b, true)
	for _, w := range warnings {
		m.logf("release %s: %s", name, w)
	}
	m.lifecycle(ctx, b, audit.SandboxPhaseDeleted, audit.SandboxTriggerReconcile, false, nil, nil)
	if retained {
		m.logf("sandbox %s: its pre-session snapshot is kept; `defenseclaw sandbox undo %s` restores the folder, "+
			"`defenseclaw sandbox delete %s` drops it", name, name, name)
		m.retire(b)
		return
	}
	m.forget(b)
}

// reconcileOne handles a watcher's report that its sandbox is gone.
func (m *Manager) reconcileOne(ctx context.Context, name string) {
	gw, err := m.gateway(ctx)
	if err != nil {
		return
	}
	m.mu.Lock()
	b := m.boxes[name]
	m.mu.Unlock()
	if b == nil || !b.op.TryLock() {
		return
	}
	defer b.op.Unlock()
	if m.current(b) && m.goneNow(ctx, gw, b) && !m.gatewayElsewhere(ctx, gw, b) {
		m.gc(ctx, gw, b)
	}
}

// gatewayElsewhere reports a sandbox created on another gateway
// registration, endpoint or workspace than gw's: DefenseClaw followed the
// CLI's active gateway to another one, say, or openshell.gateway changed.
// Not finding it on gw proves nothing then, and releasing it would revoke
// the binding and drop the snapshot of a sandbox that may still run. It is
// marked missing and reported (once per place) instead. So is a sandbox
// created on another compute driver than gw runs now: the gateway was
// switched (docker to vm, say), and releasing it would also drop its staged
// copy, while its unpulled work is still in the sandbox the other driver
// keeps.
func (m *Manager) gatewayElsewhere(ctx context.Context, gw *Gateway, b *box) bool {
	m.mu.Lock()
	rec := b.rec
	m.mu.Unlock()
	where := gatewayMismatch(rec, gw)
	otherDriver := where != "" && samePlace(rec, gw)
	m.mu.Lock()
	changed := b.elsewhere != where
	b.elsewhere, b.otherDriver = where, otherDriver
	if where != "" {
		b.missing = true
	}
	id := b.identity()
	m.mu.Unlock()
	if where == "" || !changed {
		return where != ""
	}
	msg := "sandbox " + rec.Name + " was created on " + where + ", but DefenseClaw is connected to " +
		gatewayPlace(gw.Name, gw.Endpoint, gw.Client.Workspace()) + "; it is not released while DefenseClaw is connected elsewhere"
	if otherDriver {
		msg = "sandbox " + rec.Name + " was created on " + where + "; it runs " + string(gw.Driver.Name) +
			" now, and one gateway runs one driver: the sandbox is not released while the gateway runs another driver"
	}
	m.logf("%s: %s", gatewaylog.ErrCodeOpenShellUnavailable, msg)
	m.tel.RecordSandboxHealth(ctx, audit.SandboxHealthEvent{Sandbox: id, State: audit.SandboxHealthDegraded,
		ErrorCode: errorToken(gatewaylog.ErrCodeOpenShellUnavailable), ErrorSummary: truncate(msg, 512), Timestamp: m.now()})
	return true
}

// gatewayMismatch describes where rec's sandbox was created when that is
// not gw's gateway and workspace, or not the compute driver gw runs ("" when
// it is, or rec does not say).
func gatewayMismatch(rec record, gw *Gateway) string {
	if !samePlace(rec, gw) {
		return gatewayPlace(rec.Gateway, rec.GatewayEndpoint, rec.GatewayWorkspace)
	}
	if created := recordDriver(rec); created != gw.Driver.Name {
		return gatewayPlace(gw.Name, gw.Endpoint, gw.Client.Workspace()) + " when it ran the " + string(created) + " compute driver"
	}
	return ""
}

// samePlace reports whether rec's sandbox was created on gw's gateway
// registration, endpoint and workspace, as far as rec says.
func samePlace(rec record, gw *Gateway) bool {
	ws := gw.Client.Workspace()
	return (rec.Gateway == "" || rec.Gateway == gw.Name) && (rec.GatewayEndpoint == "" || rec.GatewayEndpoint == gw.Endpoint) &&
		(rec.GatewayWorkspace == "" || rec.GatewayWorkspace == ws)
}

// recordDriver is the compute driver rec's sandbox was created on: docker
// for a record from before the driver was kept, and a name this build does
// not drive as the record has it.
func recordDriver(rec record) openshell.ComputeDriver {
	if d, ok := openshell.LookupDriver(rec.Driver); ok {
		return d.Name
	}
	return openshell.ComputeDriver(rec.Driver)
}

// gatewayPlace names a gateway registration and workspace for a message.
func gatewayPlace(name, endpoint, workspace string) string {
	return fmt.Sprintf("gateway %s (%s, workspace %s)", firstNonEmpty(name, "-"), firstNonEmpty(endpoint, "-"), firstNonEmpty(workspace, "-"))
}

// noteGateway records where a sandbox found on gw lives, for a record
// that does not say yet or that names another place (the registration was
// renamed, say): it is evidently on gw. The compute driver it was created
// on stays: one gw does not run any more is still reported. It reports
// whether the record changed.
func (m *Manager) noteGateway(b *box, gw *Gateway) bool {
	ws := gw.Client.Workspace()
	m.mu.Lock()
	defer m.mu.Unlock()
	b.elsewhere = gatewayMismatch(record{Driver: b.rec.Driver}, gw)
	b.otherDriver = b.elsewhere != ""
	if b.rec.Gateway == gw.Name && b.rec.GatewayEndpoint == gw.Endpoint && b.rec.GatewayWorkspace == ws {
		return false
	}
	b.rec.Gateway, b.rec.GatewayEndpoint, b.rec.GatewayWorkspace = gw.Name, gw.Endpoint, ws
	return true
}

// current reports whether b is still the live, settled box for its name.
func (m *Manager) current(b *box) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !b.creating && !b.deleted && m.boxes[b.rec.Name] == b
}
