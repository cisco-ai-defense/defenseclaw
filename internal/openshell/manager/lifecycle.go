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
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
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
	gw, err := m.gateway(ctx)
	if err == nil && m.now().Sub(time.Unix(0, m.gwCheckedAt.Load())) >= driverRecheck {
		// The CLI and the TUI decide on the driver said here; a restart
		// since the last check may have changed it.
		gw, err = m.recheckDriver(ctx, gw)
	}
	if err != nil {
		st.Reason = sandboxapi.AsError(err).Error()
	} else {
		st.Available = true
		st.Gateway = &sandboxapi.Gateway{Name: gw.Name, Endpoint: gw.Endpoint, Workspace: gw.Client.Workspace(), Version: gw.Version, Healthy: true,
			Driver: string(gw.Driver.Name)}
	}
	if err := openshell.CheckHost(runtime.GOOS, runtime.GOARCH); err != nil {
		st.Available, st.Reason = false, err.Error()
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
	st.StartedAt = m.startedAt.UTC()
	return st, nil
}

// List returns every sandbox, refreshed from OpenShell when it is reachable.
func (m *Manager) List(ctx context.Context) ([]sandboxapi.Sandbox, error) {
	if gw, err := m.gateway(ctx); err == nil {
		if sbs, err := m.listManaged(ctx, gw); err == nil {
			m.mu.Lock()
			for _, sb := range sbs {
				if b := m.boxes[sb.Name]; b != nil && !b.creating && !b.retained && m.sameSandboxLocked(b, sb) {
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
	shared := make([]openshell.ComputeDriver, 0, len(m.boxes))
	blocked := make([][]string, 0, len(m.boxes))
	accepted := make([]*acceptedSnapshot, 0, len(m.boxes))
	for _, b := range m.boxes {
		if !b.deleted {
			out = append(out, m.view(b))
			bindings = append(bindings, b.rec.BindingID)
			shared = append(shared, sharedLimitsOf(b))
			blocked = append(blocked, b.blockedHostList())
			accepted = append(accepted, b.rec.Accepted)
		}
	}
	proxy := m.proxy
	m.mu.Unlock()
	for i := range out {
		m.decorate(&out[i], proxy, bindings[i], blocked[i], accepted[i])
	}
	m.sharedLimitsWarnings(out, shared)
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
		case err == nil && !b.creating && m.sameSandboxLocked(b, sb):
			b.sb, b.missing = sb, false
		case (err == nil || openshell.IsNotFound(err)) && !b.creating:
			// Gone, or another sandbox took the name.
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
		"sandbox %s was deleted; only its undo point is kept (undo, review or delete it)", name)
}

func (m *Manager) stop(ctx context.Context, b *box) error {
	gw, err := m.gateway(ctx)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, defaultOpTimeout)
	defer cancel()
	m.mu.Lock()
	name := b.rec.Name
	m.mu.Unlock()
	if err := m.checkSandbox(ctx, gw, b); err != nil {
		return err
	}
	// The harness exits on its own first, so its end-of-session hook runs
	// and its terminal ends as after /exit (graceful.go); a detached run
	// the stop ends is marked interrupted, and once the stop is published
	// its log is kept for `sandbox logs` of the stopped sandbox (runlog.go).
	run := m.endHarness(ctx, gw, b)
	m.lifecycle(ctx, b, audit.SandboxPhaseStopping, audit.SandboxTriggerStop, false, nil, nil)
	m.keepRunLog(ctx, gw, b, run)
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
	m.mu.Lock()
	b.tamperStop = false
	m.mu.Unlock()
	m.restorePhase(ctx, gw, b, audit.SandboxTriggerStop, audit.SandboxPhaseStopping)
}

// restorePhase records the phase OpenShell reports for a sandbox after an
// operation on it failed, unless OpenShell still reports the operation's
// own transitional phase (pending): the phase recorded before the call
// (starting, stopping, deleting) would otherwise stay, and everything that
// follows ready or stopped sandboxes only would misjudge it.
func (m *Manager) restorePhase(ctx context.Context, gw *Gateway, b *box, trigger audit.SandboxLifecycleTrigger, pending audit.SandboxPhase) {
	ctx, cancel := detached(ctx, rollbackTimeout)
	defer cancel()
	gw = m.liveGateway(ctx, gw)
	m.mu.Lock()
	name := b.rec.Name
	m.mu.Unlock()
	sb, err := gw.Client.GetSandbox(ctx, name)
	if err != nil || !m.sameSandbox(b, sb) {
		return
	}
	m.mu.Lock()
	b.sb = sb
	m.mu.Unlock()
	if phase := auditPhase(sb.Status.Phase); phase != pending && phase != audit.SandboxPhaseUnknown {
		m.lifecycle(ctx, b, phase, trigger, false, nil, sb.Status.ExitCode)
	}
}

// checkSandbox refuses an operation on b when the OpenShell sandbox under
// its name is not b's (sameSandbox), marking b missing.
func (m *Manager) checkSandbox(ctx context.Context, gw *Gateway, b *box) error {
	m.mu.Lock()
	name := b.rec.Name
	m.mu.Unlock()
	sb, err := gw.Client.GetSandbox(ctx, name)
	if err != nil {
		m.dropGateway(gw, err)
		return upstream("look up sandbox "+name, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.sameSandboxLocked(b, sb) {
		b.missing = true
		return errReplaced(name)
	}
	b.sb, b.missing = sb, false
	return nil
}

// Start starts a stopped sandbox. The ingress token is rotated first, so a
// credential from an earlier session is useless, and a mounted project gets
// a fresh snapshot for the new session unless the folder still holds an
// earlier session's changes that nobody accepted (keepSnapshot, Accept).
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
	// The record is judged against the driver the gateway runs now.
	gw, err := m.driverGateway(ctx)
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
	// Before the gateway is asked about it: a gateway that runs another
	// driver may not know the sandbox at all.
	if err := driverStartRefusal(gw, rec); err != nil {
		return err
	}
	// Only a stopped sandbox starts a new session: everything below (the
	// token rotation, the pre-session snapshot, the tool-call ledger and
	// the guard baseline) would otherwise be reset under a running agent,
	// wiping what this session's undo and tamper detection rely on.
	if err := m.checkSandbox(ctx, gw, b); err != nil {
		return err
	}
	m.mu.Lock()
	sb := b.sb
	m.mu.Unlock()
	if !stoppedPhase(sb.Status.Phase) {
		return sandboxapi.Errorf(sandboxapi.CodeConflict, "sandbox %s is %s, not stopped; stop it before starting a new session",
			rec.Name, strings.ToLower(string(sb.Status.Phase)))
	}
	eff, violations, err := m.resolveBoxViolations(b)
	if err != nil {
		return err
	}
	if err := m.checkStart(ctx, gw, rec, eff, violations); err != nil {
		return err
	}
	binding, err := m.opts.Bindings.Get(rec.BindingID)
	if err != nil {
		return sandboxapi.Errorf(sandboxapi.CodeInternal, "look up the sandbox binding: %v", err)
	}
	if rec.WorkdirMode == config.OpenShellWorkdirMount && rec.Project != "" {
		if err := m.checkNewSecrets(ctx, rec, eff, binding); err != nil {
			return err
		}
	}
	// The harness run files follow the re-resolved policy (safe mode, MCP
	// servers) before the sandbox runs again.
	mcp, runConfig, verify, err := m.refreshRunConfig(ctx, rec, eff, sb.Spec.Environment)
	if err != nil {
		return err
	}
	m.mu.Lock()
	b.rec.MCP, b.rec.RunConfig, b.rec.Verify = mcp, runConfig, verify
	m.mu.Unlock()
	// The workload check after the start compares with what was just
	// written, not with the files the last session had.
	rec.Verify = verify
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
		if !managedBy(p.Labels, m.ownerOf(rec)) || p.Labels[LabelSandbox] != rec.Name {
			// Provider names are gateway-global: the new token must never
			// go into a provider another sandbox took the name of.
			return sandboxapi.Errorf(sandboxapi.CodeConflict,
				"the OpenShell provider %s is not the one DefenseClaw created for sandbox %s; delete the sandbox and run a new one", pname, rec.Name)
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
		// Changes the user kept at the end of a session (Accept) are the
		// base of the next one, as with --new-snapshot.
		snap, err := m.ws.LoadSnapshot(m.opts.DataDir, rec.Name)
		if err != nil {
			snap = nil
		}
		if kept, why := m.keepSnapshot(ctx, rec.Name, snap, req.NewSnapshot || rec.Accepted.acceptedFor(snap, rec.Sessions)); kept {
			// Replacing it would take the earlier session's changes into the
			// new baseline, and undo could never revert them.
			m.logf("sandbox %s: kept its pre-session snapshot: %s", rec.Name, why)
			m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityWorkspace, Sandbox: rec.Name, Reason: "snapshot_kept",
				Message: "sandbox " + rec.Name + " kept its undo point: " + why + ", which undo still reverts (`defenseclaw sandbox start " +
					rec.Name + " --new-snapshot` accepts the changes instead)"})
		} else {
			keep, keepBytes := m.keepIgnored()
			if _, err := m.ws.Snapshot(ctx, workspace.SnapshotOptions{
				Project: rec.Project, Name: rec.Name, DataDir: m.opts.DataDir, Replace: true,
				Skip: maskedRels(binding, rec.Workdir), Protected: eff.PolicySources(),
				KeepIgnored: keep, KeepIgnoredBytes: keepBytes,
			}); err != nil {
				return workspaceError(err)
			}
			m.recordSnapshot(ctx, b)
		}
	}
	// An acceptance covers the sessions before this start, not what the new
	// one changes on top (a --no-snapshot start keeps the accepted
	// snapshot): it names the session it was given after (acceptedFor), so
	// the new session ends it once the sandbox runs, and a start that fails
	// before that leaves it in place.
	// The harness starts with the sandbox: every tool call of the new
	// session reaches this process, so its tool-call ledger is complete.
	// The binding outlives the session, so the CONNECT refusals the last
	// session's agent was never told of go: they are not the new agent's.
	m.toolCalls.Begin(rec.BindingID)
	m.refusals.forget(rec.BindingID)
	m.mu.Lock()
	b.tamperStop = false
	m.mu.Unlock()
	if guarded(rec) {
		// The last session's guard has ended with its final pass (which it
		// lacks when the sandbox stopped while the daemon was down), so the
		// new baseline never takes in a repository the workload left.
		m.finishGuard(ctx, b)
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
		m.restorePhase(ctx, gw, b, audit.SandboxTriggerStart, audit.SandboxPhaseStarting)
		return upstream("start sandbox "+rec.Name, err)
	}
	sb, err = gw.Client.WaitReady(ctx, rec.Name)
	if err != nil {
		m.restorePhase(ctx, gw, b, audit.SandboxTriggerStart, audit.SandboxPhaseStarting)
		return upstream("wait for sandbox "+rec.Name, err)
	}
	if err := settle(ctx, m.opts.SettleDelay); err != nil {
		return err
	}
	if !gw.Driver.SkipWorkloadCheck {
		if err := m.verifyStarted(ctx, gw, b, rec); err != nil {
			return err
		}
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
// snapshot snap (nil: none could be loaded) instead of taking a fresh one,
// and why: the folder still holds changes an earlier session made that were
// neither undone nor accepted (newSnapshot). A fresh snapshot would make
// them part of the new baseline, out of undo's reach. When the folder
// cannot be compared with the snapshot, it is kept too: replacing it could
// lose the only way back.
func (m *Manager) keepSnapshot(ctx context.Context, name string, snap *workspace.SnapshotRecord, newSnapshot bool) (bool, string) {
	if newSnapshot || snap == nil || snap.UndoneAt != nil {
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
	if n := max(rep.FilesChanged, len(rep.Changes)); n > 0 {
		files := "changed files"
		if n == 1 {
			files = "changed file"
		}
		return true, fmt.Sprintf("the folder still holds %d %s from an earlier session", n, files)
	}
	return true, "the folder still holds changes from an earlier session"
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

// checkNewSecrets refuses to start a mounted sandbox whose project now
// holds files the secret scan would mask (by name, pattern or content)
// that its masks leave visible: they are fixed when the sandbox is
// created, so a secret file added since (a credential the user put in the
// project between sessions, a mask pattern the policy added) would be
// shared with the next session unnoticed. A scan that cannot finish fails
// closed, as it does on create.
func (m *Manager) checkNewSecrets(ctx context.Context, rec record, eff *packs.Effective, binding sandboxauth.Binding) error {
	found, err := m.ws.ScanSecrets(ctx, workspace.MountOptions{
		Project: rec.Project, Name: rec.Name, DataDir: m.opts.DataDir,
		Masks: eff.Workspace.Masks, Unmask: eff.Workspace.Unmask, Protected: eff.PolicySources(),
	})
	if err != nil {
		return workspaceError(err)
	}
	have := maskedRels(binding, rec.Workdir)
	var visible []string
	for _, mk := range found {
		if !slices.ContainsFunc(have, func(h string) bool { return mk.Rel == h || strings.HasPrefix(mk.Rel, h+"/") }) {
			visible = append(visible, sandboxapi.DisplayText(mk.Rel))
		}
	}
	if len(visible) == 0 {
		return nil
	}
	sort.Strings(visible)
	shown := visible
	if len(shown) > 5 {
		shown = append(slices.Clip(shown[:5]), fmt.Sprintf("and %d more", len(visible)-5))
	}
	msg := fmt.Sprintf("%d file(s) that look like secrets are in the project now, which sandbox %s does not mask "+
		"(its masks are fixed when it is created): %s", len(visible), rec.Name, strings.Join(shown, ", "))
	m.logf("sandbox %s: start refused: %s", rec.Name, msg)
	m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityWorkspace, Sandbox: rec.Name, Reason: "secrets_unmasked",
		Message: truncate("✗ not started: "+msg, 512)})
	return &sandboxapi.Error{Code: sandboxapi.CodeConflict, Message: msg,
		Detail: "move them out of the project, or delete the sandbox and run it again, which masks them (--unmask shares one on purpose)"}
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
// the snapshot. A run image (vm) stays, even one no other sandbox uses:
// the next sandbox of its posture boots it, where a rebuilt one would get
// a new image ID and a new prepared disk from the driver (image prune
// removes it with its overlay image; see image.Builder.pruneRunImages).
func (m *Manager) Delete(ctx context.Context, name string, req sandboxapi.DeleteRequest) (*sandboxapi.DeleteResponse, error) {
	b, unlock, err := m.lockBox(name)
	if err != nil {
		return nil, err
	}
	defer unlock()
	m.mu.Lock()
	retained := b.retained
	m.mu.Unlock()
	// A delete runs to its end once it started, even when the caller goes
	// away: one cut short would leave the providers, the binding, the mount
	// pins or the snapshot half released.
	ctx, cancel := detached(ctx, defaultOpTimeout)
	defer cancel()
	if retained {
		return m.deleteRetained(ctx, b, req)
	}
	gw, err := m.gateway(ctx)
	if err != nil {
		return nil, err
	}
	// A sandbox OpenShell no longer has (deleted outside DefenseClaw), or
	// whose name another sandbox took, is only released here: the other
	// sandbox is left alone. One created on another compute driver than
	// the gateway runs now is released whatever the gateway answers: this
	// gateway cannot remove it, and what the other driver made is named.
	m.mu.Lock()
	created := recordDriver(b.rec)
	m.mu.Unlock()
	otherDriver := created != gw.Driver.Name
	sb, err := gw.Client.GetSandbox(ctx, name)
	gone := openshell.IsNotFound(err)
	switch {
	case err != nil && !gone && !otherDriver:
		m.dropGateway(gw, err)
		return nil, upstream("look up sandbox "+name, err)
	case err != nil && !gone:
		m.dropGateway(gw, err)
		gone = true
	case err == nil && !m.sameSandbox(b, sb):
		gone = true
	}
	var warnings []string
	switch {
	case otherDriver:
		// The gateway's own record of it, if it still has one, is asked to
		// go; the rest is the other driver's.
		if !gone {
			if _, err := gw.Client.DeleteSandbox(ctx, name); err == nil {
				waitCtx, cancel := context.WithTimeout(ctx, otherDriverDeleteWait)
				_ = gw.Client.WaitDeleted(waitCtx, name)
				cancel()
			} else {
				m.dropGateway(gw, err)
			}
		}
		warnings = append(warnings, otherDriverLeftovers(name, created, gw.Driver.Name))
	case gone:
		m.mu.Lock()
		where := gatewayMismatch(b.rec, gw)
		m.mu.Unlock()
		if where != "" {
			warnings = append(warnings, "sandbox "+name+" was created on "+where+", which DefenseClaw is not connected to; "+
				"DefenseClaw released what it held for it, but the OpenShell sandbox and its providers there are left")
		} else {
			warnings = append(warnings, "OpenShell no longer had sandbox "+name+" (or another sandbox took its name); DefenseClaw released what it held for it")
		}
	default:
		// The watcher keeps running until the sandbox is gone: a delete that
		// fails leaves it running, still watched and triaged.
		m.lifecycle(ctx, b, audit.SandboxPhaseDeleting, audit.SandboxTriggerDelete, false, nil, nil)
		if _, err := gw.Client.DeleteSandbox(ctx, name); err != nil && !openshell.IsNotFound(err) {
			m.dropGateway(gw, err)
			m.deleteFailed(ctx, gw, b)
			return nil, upstream("delete sandbox "+name, err)
		}
		if err := gw.Client.WaitDeleted(ctx, name); err != nil {
			m.deleteFailed(ctx, gw, b)
			return nil, upstream("wait for sandbox "+name+" deletion", err)
		}
	}
	// The workload is gone: what it left in the project stays on this
	// machine, so the guard makes its final pass before it is released.
	m.finishGuard(ctx, b)
	m.stopWatch(b)
	resp := &sandboxapi.DeleteResponse{Name: name, Deleted: true, Warnings: warnings}
	var cleanupWarnings []string
	resp.Providers, cleanupWarnings, retained = m.cleanup(ctx, gw, b, req.KeepSnapshot)
	resp.Warnings = append(resp.Warnings, cleanupWarnings...)
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

// otherDriverDeleteWait bounds the wait for a gateway to drop its record
// of a sandbox made on another compute driver, which it may never manage.
const otherDriverDeleteWait = 30 * time.Second

// otherDriverLeftovers is the warning of a delete of a sandbox created on
// another compute driver than the gateway runs now: DefenseClaw's side is
// released, and what that driver made may be left for the user.
func otherDriverLeftovers(name string, created, now openshell.ComputeDriver) string {
	msg := "sandbox " + name + " was created on the " + string(created) + " compute driver, and the gateway runs " + string(now) +
		" now: DefenseClaw released what it held for it (its binding, providers, snapshot and staged copy), but not what the " +
		string(created) + " driver made"
	if created == openshell.DriverDocker {
		return msg + ": its container may be left (still running on a Docker VM such as Colima, or in the Error phase on Docker Desktop); " +
			"`docker ps -a` lists it and `docker rm -f` removes it"
	}
	return msg
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
	m.removeSandboxDir(name)
	m.forget(b)
	return resp, nil
}

// deleteFailed puts a sandbox whose delete failed back into the phase
// OpenShell reports and makes sure it is watched.
func (m *Manager) deleteFailed(ctx context.Context, gw *Gateway, b *box) {
	m.restorePhase(ctx, gw, b, audit.SandboxTriggerDelete, audit.SandboxPhaseDeleting)
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
	names, profileOf := m.sandboxProviders(ctx, gw, rec)
	var credProfiles []string
	for _, p := range names {
		if _, err := gw.Client.DeleteProvider(ctx, p); err != nil && !openshell.IsNotFound(err) {
			warn(err)
			continue
		}
		providers = append(providers, p)
		if id := profileOf[p]; strings.HasPrefix(id, credentialProfilePrefix) {
			credProfiles = append(credProfiles, id)
		}
	}
	m.releaseCredentialProfiles(ctx, gw, credProfiles)
	if rec.BindingID != "" {
		warn(m.revokeBinding(rec.BindingID))
		m.creds.Revoke(rec.BindingID)
		m.refusals.forget(rec.BindingID)
		m.recheckEgress(rec.BindingID)
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
	warn(m.removeRunLog(rec.Name))
	if !retained {
		warn(m.removeRecord(b))
		m.removeSandboxDir(rec.Name)
	}
	return providers, warnings, retained
}

// sandboxProviders lists the providers DefenseClaw created for a sandbox:
// those recorded plus any labelled for it, with the provider profile each
// was created from (when the gateway lists it). Provider names are
// gateway-global, so a recorded name the gateway lists with another
// sandbox's or owner's labels (the name was taken since) is left out.
func (m *Manager) sandboxProviders(ctx context.Context, gw *Gateway, rec record) ([]string, map[string]string) {
	set := map[string]bool{}
	for _, p := range rec.Providers {
		set[p] = true
	}
	profileOf := map[string]string{}
	if list, err := gw.Client.ListProviders(ctx); err == nil {
		owner := m.ownerOf(rec)
		for _, p := range list {
			ours := managedBy(p.Labels, owner) && p.Labels[LabelSandbox] == rec.Name
			switch {
			case ours:
				set[p.Name] = true
			case set[p.Name]:
				delete(set, p.Name)
				m.logf("sandbox %s: provider %s now belongs to another sandbox; it is left alone", rec.Name, p.Name)
			}
			if set[p.Name] {
				profileOf[p.Name] = p.Type
			}
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, profileOf
}

// releaseCredentialProfiles deletes the --credential provider profiles
// (dc-cred-*) a deleted sandbox's providers were created from, once no
// provider on the gateway uses them any more. They are gateway-global and
// shared by every sandbox, of any DefenseClaw daemon, that binds the same
// variable to the same endpoint, so one still in use stays: this daemon's
// creates hold credentialGC while they import a profile and create its
// provider, and OpenShell itself refuses to delete a profile a provider
// uses. A create by another daemon that loses the race imports the profile
// again (see providers).
func (m *Manager) releaseCredentialProfiles(ctx context.Context, gw *Gateway, ids []string) {
	if len(ids) == 0 {
		return
	}
	m.credentialGC.Lock()
	defer m.credentialGC.Unlock()
	list, err := gw.Client.ListProviders(ctx)
	if err != nil {
		return
	}
	used := map[string]bool{}
	for _, p := range list {
		used[p.Type] = true
	}
	for _, id := range dedupeSorted(ids) {
		if used[id] {
			continue
		}
		if _, err := gw.Client.DeleteProfile(ctx, id); err != nil && !openshell.IsNotFound(err) {
			m.logf("provider profile %s is kept: %v", id, err)
		}
	}
}

func dedupeSorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return slices.Compact(out)
}

// removeSandboxDir removes <data>/sandboxes/<name> once everything the
// sandbox kept there is gone (never while it holds anything). A retired
// sandbox keeps it until its snapshot is dropped too.
func (m *Manager) removeSandboxDir(name string) {
	if openshell.ValidSandboxName(name) && name != recordDirName {
		_ = os.Remove(filepath.Join(m.opts.DataDir, "sandboxes", name))
	}
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
	b.rec.ApprovedRules = nil
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
		// Copy mode changes the folder only through `pull --apply`, which
		// the CLI runs as the user; so does the undo of it.
		return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid,
			"%s works on a copy, which changes your folder only through `pull --apply`; `defenseclaw sandbox undo %s` reverts the last apply", name, name)
	}
	// Undo restores the whole folder: another sandbox mounting it (or a
	// folder inside or around it) must not be running meanwhile.
	if !req.Preview {
		if other := m.sharingMount(b, rec.Project, true); other != "" {
			return nil, sandboxapi.Errorf(sandboxapi.CodeConflict,
				"sandbox %s also mounts %s and may be running; stop it before undoing, because undo restores the whole folder", other, rec.Project)
		}
		// The restore is a sequence of git steps on the user's folder: once
		// it started it runs to its end even when the caller goes away,
		// and so do the stop before it and the restart after it.
		var cancel context.CancelFunc
		ctx, cancel = detached(ctx, undoTimeout)
		defer cancel()
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
			case err == nil && m.sameSandbox(b, sb):
				m.mu.Lock()
				b.sb = sb
				m.mu.Unlock()
				running = !stoppedPhase(sb.Status.Phase)
			case err == nil:
				// Another sandbox took the name: this one's agent is gone.
				m.mu.Lock()
				b.missing = true
				m.mu.Unlock()
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
	m.mu.Lock()
	quarantined := quarantinedPaths(b.rec.Guard)
	m.mu.Unlock()
	res, err := m.ws.Undo(ctx, workspace.UndoOptions{DataDir: m.opts.DataDir, Name: name, Preview: req.Preview, KeepRefs: req.KeepRefs,
		Quarantined: quarantined})
	m.mu.Lock()
	id := b.identity()
	m.mu.Unlock()
	if err != nil {
		_ = m.tel.RecordSandboxWorkspace(ctx, audit.SandboxWorkspaceEvent{Sandbox: id, Operation: audit.SandboxWorkspaceUndo,
			Result: audit.SandboxWorkspaceFailed, FailureClass: "undo_failed", Initiator: "operator", Timestamp: m.now()})
		if errors.Is(err, workspace.ErrSnapshotNotFound) {
			return nil, sandboxapi.Errorf(sandboxapi.CodeNotFound, "sandbox %s has no undo point", name)
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
			Message: "the project folder was restored to its undo point"})
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
			return nil, sandboxapi.Errorf(sandboxapi.CodeNotFound, "sandbox %s has no undo point to review against", name)
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
	case sandboxapi.WorkspaceUndo:
		ev.Operation = audit.SandboxWorkspaceUndo
		if r.PullMode != "" {
			return sandboxapi.Errorf(sandboxapi.CodeInvalid, "pull_mode applies to pulls only")
		}
	default:
		return sandboxapi.Errorf(sandboxapi.CodeInvalid, "operation must be upload, pull or undo")
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
	switch ev.Operation {
	case audit.SandboxWorkspacePull:
		msg = "pulled the sandbox's changes (" + r.PullMode + ")"
	case audit.SandboxWorkspaceUndo:
		msg = "reverted the last apply of the sandbox's changes"
	}
	if ev.Result == audit.SandboxWorkspaceFailed {
		msg += " — failed"
	}
	m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityWorkspace, Sandbox: name, Reason: r.Operation, Message: msg})
	return nil
}
