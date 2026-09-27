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
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// box returns the named sandbox, or a not-found error.
func (m *Manager) box(name string) (*box, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.boxes[name]
	if !ok || b.deleted {
		return nil, sandboxapi.Errorf(sandboxapi.CodeNotFound, "no DefenseClaw sandbox named %s", name)
	}
	return b, nil
}

// lockBox takes a sandbox's operation lock for a lifecycle operation. A
// sandbox being created is refused at once: its create holds the lock for
// as long as it runs, an image build included (defaultCreateTimeout).
func (m *Manager) lockBox(name string) (*box, func(), error) {
	b, err := m.box(name)
	if err != nil {
		return nil, nil, err
	}
	m.mu.Lock()
	creating := b.creating
	m.mu.Unlock()
	if creating {
		return nil, nil, sandboxapi.Errorf(sandboxapi.CodeConflict, "sandbox %s is being created", name)
	}
	b.op.Lock()
	m.mu.Lock()
	gone := b.deleted || b.creating
	m.mu.Unlock()
	if gone {
		b.op.Unlock()
		return nil, nil, sandboxapi.Errorf(sandboxapi.CodeConflict, "sandbox %s is being created or deleted", name)
	}
	return b, b.op.Unlock, nil
}

// Status reports the subsystem.
func (m *Manager) Status(ctx context.Context) (*sandboxapi.Status, error) {
	cfg := m.config()
	st := &sandboxapi.Status{
		Enabled: cfg.OpenShell.Enabled, IngressAddr: m.opts.IngressAddr, EgressAddr: m.opts.EgressAddr,
	}
	if gw, err := m.gateway(ctx); err != nil {
		st.Reason = sandboxapi.AsError(err).Error()
	} else {
		st.Available = true
		st.Gateway = &sandboxapi.Gateway{Name: gw.Name, Endpoint: gw.Endpoint, Workspace: gw.Client.Workspace(), Version: gw.Version, Healthy: true}
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		st.Available, st.Reason = false, openshell.ErrUnsupportedPlatform.Error()
	}
	if eff, err := m.baseEffective(cfg); err == nil {
		st.Profile = eff.Profile
		if eff.Pack != nil {
			st.Pack = eff.Pack.Name
		}
		st.Admin = wireAdmin(eff.Admin)
	} else if st.Reason == "" {
		st.Reason = err.Error()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, b := range m.boxes {
		if b.deleted || b.retained {
			continue
		}
		st.Sandboxes++
		if b.phase == audit.SandboxPhaseReady {
			st.Running++
		}
	}
	for _, a := range m.approvals {
		if a.status == sandboxapi.ApprovalPending {
			st.PendingApprovals++
		}
	}
	st.LastReconcile = m.lastReconcile
	return st, nil
}

// List returns every sandbox, refreshed from OpenShell when it is reachable.
func (m *Manager) List(ctx context.Context) ([]sandboxapi.Sandbox, error) {
	if gw, err := m.gateway(ctx); err == nil {
		if sbs, err := gw.Client.ListSandboxes(ctx, m.managedSelector()); err == nil {
			m.mu.Lock()
			for _, sb := range sbs {
				if b := m.boxes[sb.Name]; b != nil && !b.creating && !b.retained {
					b.sb, b.missing = sb, false
				}
			}
			m.mu.Unlock()
		} else {
			m.dropGateway(gw, err)
		}
	}
	m.mu.Lock()
	out := make([]sandboxapi.Sandbox, 0, len(m.boxes))
	bindings := make([]string, 0, len(m.boxes))
	for _, b := range m.boxes {
		if !b.deleted {
			out = append(out, m.view(b))
			bindings = append(bindings, b.rec.BindingID)
		}
	}
	proxy := m.proxy
	m.mu.Unlock()
	for i := range out {
		m.decorate(&out[i], proxy, bindings[i])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Get returns one sandbox.
func (m *Manager) Get(ctx context.Context, name string) (*sandboxapi.Sandbox, error) {
	b, err := m.box(name)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	retained := b.retained
	m.mu.Unlock()
	if gw, err := m.gateway(ctx); err == nil && !retained {
		sb, err := gw.Client.GetSandbox(ctx, name)
		m.mu.Lock()
		switch {
		case err == nil && !b.creating:
			b.sb, b.missing = sb, false
		case openshell.IsNotFound(err) && !b.creating:
			b.missing = true
		}
		m.mu.Unlock()
		if err != nil && !openshell.IsNotFound(err) {
			m.dropGateway(gw, err)
		}
	}
	v := m.viewOf(b)
	return &v, nil
}

// Stop stops a sandbox and keeps it (and its mounts and binding) for a
// later start.
func (m *Manager) Stop(ctx context.Context, name string) (*sandboxapi.Sandbox, error) {
	b, unlock, err := m.lockBox(name)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := m.refuseRetained(b); err != nil {
		return nil, err
	}
	if err := m.stop(ctx, b); err != nil {
		return nil, err
	}
	v := m.viewOf(b)
	return &v, nil
}

// refuseRetained refuses what needs a live sandbox on a retained box (a
// deleted sandbox whose snapshot is kept).
func (m *Manager) refuseRetained(b *box) error {
	m.mu.Lock()
	retained, name := b.retained, b.rec.Name
	m.mu.Unlock()
	if !retained {
		return nil
	}
	return sandboxapi.Errorf(sandboxapi.CodeConflict,
		"sandbox %s was deleted; only its pre-session snapshot is kept (undo, review or delete it)", name)
}

func (m *Manager) stop(ctx context.Context, b *box) error {
	gw, err := m.gateway(ctx)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, defaultOpTimeout)
	defer cancel()
	name := b.rec.Name
	m.lifecycle(ctx, b, audit.SandboxPhaseStopping, audit.SandboxTriggerStop, false, nil, nil)
	if _, err := gw.Client.StopSandbox(ctx, name); err != nil {
		m.dropGateway(gw, err)
		m.stopFailed(ctx, gw, b)
		return upstream("stop sandbox "+name, err)
	}
	sb, err := gw.Client.WaitStopped(ctx, name)
	if err != nil {
		m.stopFailed(ctx, gw, b)
		return upstream("wait for sandbox "+name+" to stop", err)
	}
	m.mu.Lock()
	b.sb = sb
	m.mu.Unlock()
	m.lifecycle(ctx, b, auditPhase(sb.Status.Phase), audit.SandboxTriggerStop, false, nil, sb.Status.ExitCode)
	return nil
}

// stopFailed puts a sandbox whose stop failed back into the phase OpenShell
// reports, so triage, enforcement and the hook-silence check (which all
// follow ready sandboxes only) resume for one still running, and lets the
// next hook tamper of its session schedule another stop.
func (m *Manager) stopFailed(ctx context.Context, gw *Gateway, b *box) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	m.mu.Lock()
	name := b.rec.Name
	b.tamperStop = false
	m.mu.Unlock()
	sb, err := gw.Client.GetSandbox(ctx, name)
	if err != nil {
		return
	}
	m.mu.Lock()
	b.sb = sb
	m.mu.Unlock()
	if phase := auditPhase(sb.Status.Phase); phase != audit.SandboxPhaseStopping && phase != audit.SandboxPhaseUnknown {
		m.lifecycle(ctx, b, phase, audit.SandboxTriggerStop, false, nil, sb.Status.ExitCode)
	}
}

// Start starts a stopped sandbox. The ingress token is rotated first, so a
// credential from an earlier session is useless, and a mounted project gets
// a fresh snapshot for the new session.
func (m *Manager) Start(ctx context.Context, name string, req sandboxapi.StartRequest) (*sandboxapi.Sandbox, error) {
	b, unlock, err := m.lockBox(name)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := m.refuseRetained(b); err != nil {
		return nil, err
	}
	if err := m.start(ctx, b, req); err != nil {
		return nil, err
	}
	v := m.viewOf(b)
	return &v, nil
}

func (m *Manager) start(ctx context.Context, b *box, req sandboxapi.StartRequest) error {
	if err := m.listenersReady(); err != nil {
		return err
	}
	gw, err := m.gateway(ctx)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, defaultOpTimeout)
	defer cancel()
	m.mu.Lock()
	rec := b.rec
	orphaned := b.orphaned
	m.mu.Unlock()
	if orphaned {
		return sandboxapi.Errorf(sandboxapi.CodeConflict, "sandbox %s has no DefenseClaw binding; delete it and run a new one", rec.Name)
	}
	// Only a stopped sandbox starts a new session: everything below (the
	// token rotation, the pre-session snapshot, the tool-call ledger and
	// the guard baseline) would otherwise be reset under a running agent,
	// wiping what this session's undo and tamper detection rely on.
	sb, err := gw.Client.GetSandbox(ctx, rec.Name)
	if err != nil {
		m.dropGateway(gw, err)
		return upstream("look up sandbox "+rec.Name, err)
	}
	m.mu.Lock()
	b.sb = sb
	m.mu.Unlock()
	if !stoppedPhase(sb.Status.Phase) {
		return sandboxapi.Errorf(sandboxapi.CodeConflict, "sandbox %s is %s, not stopped; stop it before starting a new session",
			rec.Name, strings.ToLower(string(sb.Status.Phase)))
	}
	eff, violations, err := m.resolveBoxViolations(b)
	if err != nil {
		return err
	}
	if err := m.checkStart(ctx, rec, eff, violations); err != nil {
		return err
	}
	binding, err := m.opts.Bindings.Get(rec.BindingID)
	if err != nil {
		return sandboxapi.Errorf(sandboxapi.CodeInternal, "look up the sandbox binding: %v", err)
	}
	// With token_delivery: provider the token is rotated, so a credential
	// from an earlier session is useless, and the provider carries the new
	// one into the sandbox. With token_delivery: env the token is a plain
	// variable of the sandbox spec, which OpenShell cannot change after
	// create: it is kept for the sandbox's life (the agent can read it
	// either way) rather than rotated into a token no hook presents.
	if tokenDelivery(rec) == config.OpenShellTokenDeliveryProvider {
		var token string
		if binding, token, err = m.opts.Bindings.Rotate(rec.BindingID); err != nil {
			return sandboxapi.Errorf(sandboxapi.CodeInternal, "rotate the sandbox binding: %v", err)
		}
		if m.opts.ForgetBinding != nil {
			m.opts.ForgetBinding(binding.ID)
		}
		pname := providerName(rec.Name, roleIngress, 0)
		p, err := gw.Client.GetProvider(ctx, pname)
		if err != nil {
			return upstream("get provider "+pname, err)
		}
		if p.Spec.Credentials == nil {
			p.Spec.Credentials = map[string]string{}
		}
		p.Spec.Credentials[openshell.EnvSandboxToken] = token
		if _, err := gw.Client.UpdateProvider(ctx, p); err != nil {
			return upstream("rotate provider "+pname, err)
		}
	}
	if rec.WorkdirMode == config.OpenShellWorkdirMount && !req.NoSnapshot && rec.Project != "" {
		if kept, why := m.keepSnapshot(ctx, rec.Name, req.NewSnapshot); kept {
			// Replacing it would take the earlier session's changes into the
			// new baseline, and undo could never revert them.
			m.logf("sandbox %s: kept its pre-session snapshot: %s", rec.Name, why)
			m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityWorkspace, Sandbox: rec.Name, Reason: "snapshot_kept",
				Message: "kept the pre-session snapshot: " + why + "; undo still reverts them (`sandbox start --new-snapshot` accepts them)"})
		} else {
			if _, err := m.ws.Snapshot(ctx, workspace.SnapshotOptions{
				Project: rec.Project, Name: rec.Name, DataDir: m.opts.DataDir, Replace: true,
				Skip: maskedRels(binding, rec.Workdir), Protected: eff.PolicySources(),
			}); err != nil {
				return workspaceError(err)
			}
			m.recordSnapshot(ctx, b)
		}
	}
	// The harness starts with the sandbox: every tool call of the new
	// session reaches this process, so its tool-call ledger is complete.
	m.toolCalls.Begin(rec.BindingID)
	m.mu.Lock()
	b.tamperStop = false
	m.mu.Unlock()
	if guarded(rec) {
		// A new session: the guard starts over from what the project
		// holds now, before the sandbox runs again.
		m.takeGuardBaseline(ctx, &rec)
		m.mu.Lock()
		b.rec.Guard = rec.Guard
		m.mu.Unlock()
		if err := m.saveRecord(b); err != nil {
			return sandboxapi.Errorf(sandboxapi.CodeInternal, "save sandbox state: %v", err)
		}
	}
	m.lifecycle(ctx, b, audit.SandboxPhaseStarting, audit.SandboxTriggerStart, false, nil, nil)
	if _, err := gw.Client.StartSandbox(ctx, rec.Name); err != nil {
		m.dropGateway(gw, err)
		return upstream("start sandbox "+rec.Name, err)
	}
	sb, err = gw.Client.WaitReady(ctx, rec.Name)
	if err != nil {
		return upstream("wait for sandbox "+rec.Name, err)
	}
	if err := settle(ctx, m.opts.SettleDelay); err != nil {
		return err
	}
	m.mu.Lock()
	b.sb = sb
	// A new session: its rule budget and approval rate start over.
	b.rulesAdded, b.autoApproved = 0, nil
	m.mu.Unlock()
	m.lifecycle(ctx, b, auditPhase(sb.Status.Phase), audit.SandboxTriggerStart, false, nil, nil)
	m.startWatch(b)
	m.enforceApprovedRules(ctx, gw, b, eff)
	return nil
}

// keepSnapshot reports whether a start must keep the sandbox's pre-session
// snapshot instead of taking a fresh one, and why: the folder still holds
// changes an earlier session made that were neither undone nor accepted
// (newSnapshot). A fresh snapshot would make them part of the new
// baseline, out of undo's reach. When the folder cannot be compared with
// the snapshot, it is kept too: replacing it could lose the only way back.
func (m *Manager) keepSnapshot(ctx context.Context, name string, newSnapshot bool) (bool, string) {
	if newSnapshot {
		return false, ""
	}
	snap, err := m.ws.LoadSnapshot(m.opts.DataDir, name)
	if err != nil || snap == nil || snap.UndoneAt != nil {
		return false, ""
	}
	// Only whether anything changed matters here: no content scanners.
	rep, err := m.ws.Review(ctx, workspace.ReviewOptions{DataDir: m.opts.DataDir, Name: name, Scanners: []workspace.ContentScanner{}})
	if err != nil {
		return true, "the folder could not be compared with it (" + truncate(err.Error(), 200) + "), so it may hold an earlier session's changes"
	}
	if rep.FilesChanged == 0 && len(rep.Changes) == 0 && len(rep.Flags) == 0 {
		return false, ""
	}
	return true, fmt.Sprintf("the folder still holds %d changed file(s) from an earlier session", max(rep.FilesChanged, len(rep.Changes)))
}

// stoppedPhase reports an OpenShell phase in which the workload no longer
// runs, so nothing in the sandbox can write the project folder.
func stoppedPhase(p openshell.SandboxPhase) bool {
	switch p {
	case openshell.PhaseStopped, openshell.PhaseCompleted, openshell.PhaseError:
		return true
	}
	return false
}

// tokenDelivery is how a sandbox received its ingress token. Records from
// before the field existed tell by their ingress provider.
func tokenDelivery(rec record) string {
	if rec.TokenDelivery != "" {
		return rec.TokenDelivery
	}
	if slices.Contains(rec.Providers, providerName(rec.Name, roleIngress, 0)) {
		return config.OpenShellTokenDeliveryProvider
	}
	return config.OpenShellTokenDeliveryEnv
}

// maskedRels turns the binding's sandbox mask paths back into
// project-relative paths for a snapshot.
func maskedRels(binding sandboxauth.Binding, workdir string) []string {
	var out []string
	prefix := workdir + "/"
	for _, p := range binding.Workdir.Masks {
		if rel, ok := cutPrefix(p, prefix); ok {
			out = append(out, rel)
		}
	}
	return out
}

// Delete deletes a sandbox and everything DefenseClaw created for it: the
// providers, the binding (its token stops working at once), the egress
// credential and unblocks, the mount pins and mask files, and by default
// the snapshot.
func (m *Manager) Delete(ctx context.Context, name string, req sandboxapi.DeleteRequest) (*sandboxapi.DeleteResponse, error) {
	b, unlock, err := m.lockBox(name)
	if err != nil {
		return nil, err
	}
	defer unlock()
	m.mu.Lock()
	retained := b.retained
	m.mu.Unlock()
	if retained {
		return m.deleteRetained(ctx, b, req)
	}
	gw, err := m.gateway(ctx)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, defaultOpTimeout)
	defer cancel()
	// The watcher keeps running until the sandbox is gone: a delete that
	// fails leaves it running, still watched and triaged.
	m.lifecycle(ctx, b, audit.SandboxPhaseDeleting, audit.SandboxTriggerDelete, false, nil, nil)
	if _, err := gw.Client.DeleteSandbox(ctx, name); err != nil {
		m.dropGateway(gw, err)
		m.deleteFailed(ctx, gw, b)
		return nil, upstream("delete sandbox "+name, err)
	}
	if err := gw.Client.WaitDeleted(ctx, name); err != nil {
		m.deleteFailed(ctx, gw, b)
		return nil, upstream("wait for sandbox "+name+" deletion", err)
	}
	m.stopWatch(b)
	resp := &sandboxapi.DeleteResponse{Name: name, Deleted: true}
	resp.Providers, resp.Warnings, retained = m.cleanup(ctx, gw, b, req.KeepSnapshot)
	m.lifecycle(ctx, b, audit.SandboxPhaseDeleted, audit.SandboxTriggerDelete, false, nil, nil)
	if retained {
		// The kept snapshot stays reachable: undo, review and delete find
		// it under the sandbox's name.
		m.retire(b)
		return resp, nil
	}
	m.forget(b)
	return resp, nil
}

// deleteRetained drops what is left of a deleted sandbox whose snapshot was
// kept: the snapshot and the record.
func (m *Manager) deleteRetained(ctx context.Context, b *box, req sandboxapi.DeleteRequest) (*sandboxapi.DeleteResponse, error) {
	m.mu.Lock()
	name := b.rec.Name
	m.mu.Unlock()
	if req.KeepSnapshot {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid,
			"sandbox %s was deleted already and only its snapshot is left; delete it without --keep-snapshot to drop that", name)
	}
	resp := &sandboxapi.DeleteResponse{Name: name, Deleted: true}
	if err := m.ws.DeleteSnapshot(ctx, m.opts.DataDir, name); err != nil && !errors.Is(err, workspace.ErrSnapshotNotFound) {
		return nil, workspaceError(err)
	}
	if err := m.removeRecord(b); err != nil {
		resp.Warnings = append(resp.Warnings, err.Error())
	}
	m.forget(b)
	return resp, nil
}

// deleteFailed puts a sandbox whose delete failed back into the phase
// OpenShell reports and makes sure it is watched.
func (m *Manager) deleteFailed(ctx context.Context, gw *Gateway, b *box) {
	ctx = context.WithoutCancel(ctx)
	m.mu.Lock()
	name := b.rec.Name
	m.mu.Unlock()
	if sb, err := gw.Client.GetSandbox(ctx, name); err == nil {
		m.mu.Lock()
		b.sb = sb
		m.mu.Unlock()
		if phase := auditPhase(sb.Status.Phase); phase != audit.SandboxPhaseDeleting {
			m.lifecycle(ctx, b, phase, audit.SandboxTriggerDelete, false, nil, sb.Status.ExitCode)
		}
	}
	m.startWatch(b)
}

// cleanup releases everything a gone sandbox held. It is shared by Delete
// and by reconciliation of sandboxes deleted outside DefenseClaw. With
// keepSnapshot, a mounted project's pre-session snapshot and the sandbox's
// record stay, and retained reports it: the caller retires the box, so
// undo, review and delete still reach the snapshot.
func (m *Manager) cleanup(ctx context.Context, gw *Gateway, b *box, keepSnapshot bool) (providers, warnings []string, retained bool) {
	m.mu.Lock()
	rec := b.rec
	m.mu.Unlock()
	warn := func(err error) {
		if err != nil {
			warnings = append(warnings, err.Error())
		}
	}
	for _, p := range m.sandboxProviders(ctx, gw, rec) {
		if _, err := gw.Client.DeleteProvider(ctx, p); err != nil && !openshell.IsNotFound(err) {
			warn(err)
			continue
		}
		providers = append(providers, p)
	}
	if rec.BindingID != "" {
		warn(m.revokeBinding(rec.BindingID))
		m.creds.Revoke(rec.BindingID)
	}
	m.unblocks.RemoveSandbox(scopeID(rec.ID, rec.Name))
	for _, it := range m.batcher.Forget(rec.Name) {
		_ = it
	}
	m.dropApprovals(rec.Name)
	if rec.WorkdirMode == config.OpenShellWorkdirMount {
		warn(m.ws.ReleaseMount(m.opts.DataDir, rec.Name))
		if keepSnapshot {
			snap, err := m.ws.LoadSnapshot(m.opts.DataDir, rec.Name)
			retained = err == nil && snap != nil
		} else if err := m.ws.DeleteSnapshot(ctx, m.opts.DataDir, rec.Name); err != nil && !errors.Is(err, workspace.ErrSnapshotNotFound) {
			warn(err)
		}
	} else if err := m.ws.DeleteCopy(m.opts.DataDir, rec.Name); err != nil && !errors.Is(err, workspace.ErrCopyNotFound) {
		warn(err)
	}
	warn(m.removeRunConfig(rec.Name))
	if !retained {
		warn(m.removeRecord(b))
	}
	return providers, warnings, retained
}

// sandboxProviders lists the providers DefenseClaw created for a sandbox:
// those recorded plus any labelled for it.
func (m *Manager) sandboxProviders(ctx context.Context, gw *Gateway, rec record) []string {
	set := map[string]bool{}
	for _, p := range rec.Providers {
		set[p] = true
	}
	if list, err := gw.Client.ListProviders(ctx); err == nil {
		for _, p := range list {
			if p.Labels[LabelManaged] == "true" && p.Labels[LabelOwner] == m.opts.Owner && p.Labels[LabelSandbox] == rec.Name {
				set[p.Name] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// retire keeps a gone sandbox's box for its pre-session snapshot only: the
// record drops everything that belonged to the live sandbox and is saved
// as retained, so the snapshot stays reachable across restarts. Callers
// ran cleanup (which released the rest) and hold b.op. A retained record
// never resolves a policy, so one adopted without its run flags
// (unrecorded) is written too.
func (m *Manager) retire(b *box) {
	m.mu.Lock()
	b.retained, b.missing, b.unrecorded = true, false, false
	b.sb, b.eff, b.decider, b.cred = nil, nil, nil, egress.Credential{}
	b.rec.Retained = true
	b.rec.BindingID, b.rec.Providers, b.rec.EgressUser, b.rec.Cursor, b.rec.Unblocks = "", nil, "", "", nil
	name := b.rec.Name
	m.mu.Unlock()
	if err := m.saveRecord(b); err != nil {
		m.logf("keep the snapshot record of %s: %v", name, err)
	}
	m.refreshEgress()
}

func (m *Manager) forget(b *box) {
	m.mu.Lock()
	b.deleted = true
	if m.boxes[b.rec.Name] == b {
		delete(m.boxes, b.rec.Name)
	}
	m.mu.Unlock()
	m.refreshEgress()
}

// Undo restores a mounted project to its pre-session snapshot. The sandbox
// must be stopped (the agent could otherwise race the restore): Stop stops
// it first, Restart starts it again afterwards.
func (m *Manager) Undo(ctx context.Context, name string, req sandboxapi.UndoRequest) (*sandboxapi.UndoResponse, error) {
	b, unlock, err := m.lockBox(name)
	if err != nil {
		return nil, err
	}
	defer unlock()
	m.mu.Lock()
	rec, retained := b.rec, b.retained
	m.mu.Unlock()
	if rec.WorkdirMode != config.OpenShellWorkdirMount {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "undo applies to mounted projects; a copy-mode sandbox never changed the folder")
	}
	// Undo restores the whole folder: another sandbox mounting it (or a
	// folder inside or around it) must not be running meanwhile.
	if !req.Preview {
		if other := m.sharingMount(b, rec.Project, true); other != "" {
			return nil, sandboxapi.Errorf(sandboxapi.CodeConflict,
				"sandbox %s also mounts %s and may be running; stop it before undoing, because undo restores the whole folder", other, rec.Project)
		}
	}
	// Ask OpenShell whether the agent can still write to the folder. A
	// retained box has no sandbox left (a live one under its name is
	// another sandbox), so there is nothing to stop or restart.
	running := false
	if !retained {
		gw, err := m.gateway(ctx)
		switch {
		case err == nil:
			sb, err := gw.Client.GetSandbox(ctx, name)
			switch {
			case err == nil:
				m.mu.Lock()
				b.sb = sb
				m.mu.Unlock()
				running = !stoppedPhase(sb.Status.Phase)
			case !openshell.IsNotFound(err):
				if !req.Preview {
					return nil, upstream("look up sandbox "+name, err)
				}
			}
		case !req.Preview:
			return nil, err
		}
	}
	resp := &sandboxapi.UndoResponse{Name: name}
	if running && !req.Preview {
		if !req.Stop {
			return nil, sandboxapi.Errorf(sandboxapi.CodeConflict, "stop sandbox %s before undoing its changes", name)
		}
		if err := m.stop(ctx, b); err != nil {
			return nil, err
		}
		resp.Stopped = true
	}
	res, err := m.ws.Undo(ctx, workspace.UndoOptions{DataDir: m.opts.DataDir, Name: name, Preview: req.Preview, KeepRefs: req.KeepRefs})
	m.mu.Lock()
	id := b.identity()
	m.mu.Unlock()
	if err != nil {
		_ = m.tel.RecordSandboxWorkspace(ctx, audit.SandboxWorkspaceEvent{Sandbox: id, Operation: audit.SandboxWorkspaceUndo,
			Result: audit.SandboxWorkspaceFailed, FailureClass: "undo_failed", Initiator: "operator", Timestamp: m.now()})
		if errors.Is(err, workspace.ErrSnapshotNotFound) {
			return nil, sandboxapi.Errorf(sandboxapi.CodeNotFound, "sandbox %s has no snapshot to undo to", name)
		}
		return nil, workspaceError(err)
	}
	resp.Result = res
	if !req.Preview {
		n := int64(len(res.Changes))
		result := audit.SandboxWorkspaceApplied
		if n == 0 {
			result = audit.SandboxWorkspaceNoChange
		}
		_ = m.tel.RecordSandboxWorkspace(ctx, audit.SandboxWorkspaceEvent{Sandbox: id, Operation: audit.SandboxWorkspaceUndo,
			Result: result, Initiator: "operator", FileCount: &n, Timestamp: m.now()})
		m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityWorkspace, Sandbox: name, Reason: "undo",
			Message: "the project folder was restored to its pre-session snapshot"})
	}
	if req.Restart && resp.Stopped {
		if err := m.start(ctx, b, sandboxapi.StartRequest{}); err != nil {
			return resp, err
		}
		resp.Restarted = true
	}
	return resp, nil
}

// Review lists what the session changed in a mounted project and which of
// those changes can run code on the host.
func (m *Manager) Review(ctx context.Context, name string, req sandboxapi.ReviewRequest) (*sandboxapi.ReviewResponse, error) {
	b, err := m.box(name)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	rec := b.rec
	eff := b.eff
	id := b.identity()
	m.mu.Unlock()
	if rec.WorkdirMode != config.OpenShellWorkdirMount {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "review applies to mounted projects; pull a copy-mode sandbox instead")
	}
	opts := workspace.ReviewOptions{DataDir: m.opts.DataDir, Name: name}
	if eff != nil {
		opts.SensitiveGlobs = eff.Workspace.Review
	}
	report, err := m.ws.Review(ctx, opts)
	if err != nil {
		if errors.Is(err, workspace.ErrSnapshotNotFound) {
			return nil, sandboxapi.Errorf(sandboxapi.CodeNotFound, "sandbox %s has no snapshot to review against", name)
		}
		return nil, workspaceError(err)
	}
	resp := &sandboxapi.ReviewResponse{Name: name, Report: report, Summary: report.SummaryLine(), RiskLine: report.RiskLine()}
	if req.Diff {
		diff, err := m.ws.ReviewDiff(ctx, m.opts.DataDir, name)
		if err != nil {
			return nil, workspaceError(err)
		}
		resp.Diff = string(diff)
	}
	files, added, removed := int64(report.FilesChanged), int64(report.Insertions), int64(report.Deletions)
	flagged := int64(len(report.HostExecLabels()))
	ev := audit.SandboxWorkspaceEvent{Sandbox: id, Operation: audit.SandboxWorkspaceReview, Initiator: "operator",
		FileCount: &files, LinesAdded: &added, LinesRemoved: &removed, FlaggedCount: &flagged, Timestamp: m.now()}
	for _, f := range report.Flags {
		ev.Paths = append(ev.Paths, f.Path)
	}
	_ = m.tel.RecordSandboxWorkspace(ctx, ev)
	return resp, nil
}

// recordSnapshot emits the snapshot record of a box.
func (m *Manager) recordSnapshot(ctx context.Context, b *box) {
	m.mu.Lock()
	id := b.identity()
	name := b.rec.Name
	m.mu.Unlock()
	snap, err := m.ws.LoadSnapshot(m.opts.DataDir, name)
	if err != nil || snap == nil {
		return
	}
	ev := audit.SandboxWorkspaceEvent{Sandbox: id, Operation: audit.SandboxWorkspaceSnapshot, Initiator: "operator",
		SnapshotKind: snapshotKind(snap.Kind), Timestamp: m.now()}
	if snap.Git != nil {
		ev.SnapshotRef = snap.Git.Ref
	}
	_ = m.tel.RecordSandboxWorkspace(ctx, ev)
}

// ReportWorkspace records a copy-mode workspace step the CLI ran (upload,
// or pull with apply, branch or patch) with the sandbox's identity.
func (m *Manager) ReportWorkspace(ctx context.Context, name string, r sandboxapi.WorkspaceReport) error {
	b, err := m.box(name)
	if err != nil {
		return err
	}
	ev := audit.SandboxWorkspaceEvent{
		Result: audit.SandboxWorkspaceResult(r.Result), FailureClass: r.FailureClass, Initiator: "operator",
		FileCount: r.FileCount, LinesAdded: r.LinesAdded, LinesRemoved: r.LinesRemoved, FlaggedCount: r.FlaggedCount,
		ByteCount: r.ByteCount, Paths: r.Paths, Timestamp: m.now(),
	}
	switch r.Operation {
	case sandboxapi.WorkspaceUpload:
		ev.Operation = audit.SandboxWorkspaceUpload
		if r.PullMode != "" {
			return sandboxapi.Errorf(sandboxapi.CodeInvalid, "pull_mode applies to pulls only")
		}
	case sandboxapi.WorkspacePull:
		ev.Operation = audit.SandboxWorkspacePull
		switch r.PullMode {
		case audit.SandboxPullApply, audit.SandboxPullBranch, audit.SandboxPullPatch:
			ev.PullMode = r.PullMode
		default:
			return sandboxapi.Errorf(sandboxapi.CodeInvalid, "pull_mode must be apply, branch or patch")
		}
	default:
		return sandboxapi.Errorf(sandboxapi.CodeInvalid, "operation must be upload or pull")
	}
	switch ev.Result {
	case "", audit.SandboxWorkspaceApplied, audit.SandboxWorkspaceCompleted, audit.SandboxWorkspaceFailed,
		audit.SandboxWorkspaceNoChange, audit.SandboxWorkspacePartial, audit.SandboxWorkspaceSkipped:
	default:
		return sandboxapi.Errorf(sandboxapi.CodeInvalid, "unknown workspace result %q", r.Result)
	}
	for _, count := range []*int64{r.FileCount, r.LinesAdded, r.LinesRemoved, r.FlaggedCount, r.ByteCount} {
		if count != nil && *count < 0 {
			return sandboxapi.Errorf(sandboxapi.CodeInvalid, "counts must not be negative")
		}
	}
	m.mu.Lock()
	ev.Sandbox = b.identity()
	m.mu.Unlock()
	if err := m.tel.RecordSandboxWorkspace(ctx, ev); err != nil {
		return &sandboxapi.Error{Code: sandboxapi.CodeInvalid, Message: "the workspace report was not recorded", Detail: err.Error()}
	}
	msg := "uploaded the project copy"
	if ev.Operation == audit.SandboxWorkspacePull {
		msg = "pulled the sandbox's changes (" + r.PullMode + ")"
	}
	if ev.Result == audit.SandboxWorkspaceFailed {
		msg += " — failed"
	}
	m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityWorkspace, Sandbox: name, Reason: r.Operation, Message: msg})
	return nil
}
