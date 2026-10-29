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
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/triage"
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
	if m.opts.Listeners != nil {
		if err := m.opts.Listeners(); err != nil {
			// A gateway or host cause found above stays the primary reason.
			st.Available = false
			if st.Reason == "" {
				st.Reason = err.Error()
			}
		}
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
	// Every guest is counted at the place its record names (proveGuests).
	m.proveGuests(ctx)
	here := m.lastGw.Load()
	m.mu.Lock()
	defer m.mu.Unlock()
	live := 0
	for _, b := range m.boxes {
		if b.deleted || b.retained {
			continue
		}
		st.Sandboxes++
		if b.phase == audit.SandboxPhaseReady {
			st.Running++
		}
		if !b.missing && holdsCompute(b.phase, b.rec.Driver, b.rec.PhaseReason) {
			live++
		}
		if kind, phase := unprotectedKind(b, here); kind != "" {
			u := sandboxapi.UnprotectedSandbox{Name: b.rec.Name, Phase: string(cmp.Or(phase, audit.SandboxPhaseUnknown))}
			switch kind {
			case sandboxapi.UnprotectedUnknown:
				u.Reason, u.Detail = kind, unknownWhy(b, here)
			case sandboxapi.UnprotectedContained:
				u.Reason = kind
				fallthrough
			default:
				u.Stop = legacyStopCommand(b.rec.Name, phase)
				if !atConnectedPlace(b, here) {
					u.Detail = unprotectedWayOn(b, here, kind, phase)
				}
			}
			st.Unprotected = append(st.Unprotected, u)
		}
	}
	slices.SortFunc(st.Unprotected, func(a, b sandboxapi.UnprotectedSandbox) int { return strings.Compare(a.Name, b.Name) })
	st.Live = &live
	for _, a := range m.approvals {
		if a.status == sandboxapi.ApprovalPending {
			st.PendingApprovals++
		}
	}
	st.LastReconcile = m.lastReconcile
	st.StartedAt = m.startedAt.UTC()
	st.TelemetryFailures, st.TelemetryError = m.tel.failureStatus()
	return st, nil
}

// List returns every sandbox, refreshed from OpenShell when it is reachable.
func (m *Manager) List(ctx context.Context) ([]sandboxapi.Sandbox, error) {
	live := false
	if gw, err := m.gateway(ctx); err == nil {
		if sbs, err := m.listManaged(ctx, gw); err == nil {
			live = true
			m.mu.Lock()
			for _, sb := range sbs {
				if b := m.boxes[sb.Name]; b != nil && !b.creating && !b.retained && m.sameSandboxLocked(b, sb) {
					foundOnLocked(b, gw, sb)
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
	accepted := make([]*acceptedSnapshot, 0, len(m.boxes))
	for _, b := range m.boxes {
		if !b.deleted {
			v := m.view(b)
			if !live {
				unconfirmedPhase(&v)
			}
			out = append(out, v)
			bindings = append(bindings, b.rec.BindingID)
			shared = append(shared, sharedLimitsOf(b))
			accepted = append(accepted, b.rec.Accepted)
		}
	}
	proxy := m.proxy
	m.mu.Unlock()
	for i := range out {
		m.decorate(&out[i], proxy, bindings[i], accepted[i])
	}
	m.sharedLimitsWarnings(out, shared)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// KnownComputeCount counts sandboxes that may hold compute from the
// manager's saved phases, without contacting OpenShell. It is used while
// managed sandboxes are off and their account gateway cannot start.
func (m *Manager) KnownComputeCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, b := range m.boxes {
		if !b.deleted && !b.retained && holdsCompute(b.phase, b.rec.Driver, b.rec.PhaseReason) {
			n++
		}
	}
	return n
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
	live := retained
	if gw, err := m.gateway(ctx); err == nil && !retained {
		sb, err := gw.Client.GetSandbox(ctx, name)
		m.mu.Lock()
		report := func(context.Context) {}
		switch {
		case err == nil && !b.creating && m.sameSandboxLocked(b, sb):
			foundOnLocked(b, gw, sb)
		case (err == nil || openshell.IsNotFound(err)) && !b.creating:
			// Gone from gw, or another sandbox took the name there.
			report = m.missingFromLocked(gw, b)
		}
		m.mu.Unlock()
		report(ctx)
		live = err == nil || openshell.IsNotFound(err)
		if !live {
			m.dropGateway(gw, err)
		}
	}
	v := m.viewOf(b)
	if !live {
		unconfirmedPhase(&v)
	}
	return &v, nil
}

// unconfirmedPhase is the phase of a sandbox the OpenShell gateway could not
// be asked about: a running or starting phase last seen is not known to hold
// any more (the gateway stopped, or another account's took its port), so it
// reads unknown, not provisioning or ready for as long as the gateway is
// down (GAP-0202). A stopped or missing sandbox stays so.
func unconfirmedPhase(v *sandboxapi.Sandbox) {
	switch v.Phase {
	case "ready", "provisioning":
		v.Phase = string(audit.SandboxPhaseUnknown)
	}
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

// refreshModelCredential gives the sandbox's model provider the credential
// the caller's environment holds now (StartRequest.LLM): a provider keeps
// what its sandbox was created with, so once that key expired (a Bedrock
// API key lasts hours) every model call of a later session failed until
// the sandbox was deleted and run again. Only for the profile the sandbox
// was created with, and only the variables that profile delivers.
//
// OpenShell never hands a provider's credential values back (the SDK's
// provider has none after a get), so whether the key changed is judged
// against rec.LLMDigest, the digest of the one DefenseClaw last gave the
// provider. It returns the digest the provider's credential has now.
func (m *Manager) refreshModelCredential(ctx context.Context, gw *Gateway, rec record, llm *sandboxapi.LLMCredential) (string, error) {
	if llm == nil || llm.Profile == "" || llm.Profile != rec.CredentialProfile || len(llm.Credentials) == 0 {
		return rec.LLMDigest, nil
	}
	pname := providerName(rec.Name, roleLLM, 0)
	p, err := gw.Client.GetProvider(ctx, pname)
	switch {
	case openshell.IsNotFound(err):
		return rec.LLMDigest, nil
	case err != nil:
		return "", upstream("get provider "+pname, err)
	case !managedBy(p.Labels, rec.Owner) || p.Labels[LabelSandbox] != rec.Name:
		return "", sandboxapi.Errorf(sandboxapi.CodeConflict,
			"the OpenShell provider %s is not the one DefenseClaw created for sandbox %s; delete the sandbox and run a new one", pname, rec.Name)
	}
	profile, err := gw.Client.GetProfile(ctx, p.Type)
	switch {
	case openshell.IsNotFound(err):
		// Nothing says which variables the provider delivers: it keeps its key.
		m.logf("sandbox %s: provider profile %s is gone; the model credential is not renewed", rec.Name, p.Type)
		return rec.LLMDigest, nil
	case err != nil:
		return "", upstream("get provider profile "+p.Type, err)
	}
	delivered := map[string]bool{}
	for _, c := range profile.Credentials {
		for _, env := range c.EnvVars {
			delivered[env] = true
		}
	}
	creds := map[string]string{}
	for k, v := range llm.Credentials {
		if delivered[k] && validSecretValue(v) {
			creds[k] = v
		}
	}
	digest := credentialDigest(creds)
	if len(creds) == 0 || digest == rec.LLMDigest {
		return rec.LLMDigest, nil
	}
	// The gateway merges the keys an update names into the provider's.
	p.Spec.Credentials = creds
	if _, err := gw.Client.UpdateProvider(ctx, p); err != nil {
		return "", upstream("update provider "+pname, err)
	}
	m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityLifecycle, Sandbox: rec.Name, Reason: "model_credential_updated",
		Message: "sandbox " + rec.Name + " takes the model credential your environment holds now"})
	return digest, nil
}

// credentialDigest is the SHA-256 of a provider's credentials (names and
// values), which the record keeps in place of the values.
func credentialDigest(creds map[string]string) string {
	if len(creds) == 0 {
		return ""
	}
	h := sha256.New()
	for _, k := range slices.Sorted(maps.Keys(creds)) {
		fmt.Fprintf(h, "%s\x00%s\n", k, creds[k])
	}
	return hex.EncodeToString(h.Sum(nil))
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

// stop stops the sandbox of b once its harness has exited and, on a driver
// whose stop does not flush (the MicroVM driver), after sync(1) in the
// guest. A flush that fails holds the stop back (unsyncedStopRefusal: the VM
// keeps running and loses nothing), unless the caller accepted that loss
// (sandboxapi.DiscardUnsynced), which only the user's own stop does, after
// it asked them (GAP-0902): DefenseClaw never stops a MicroVM after a failed
// sync on its own, for a hook alarm, a policy, a lost listener or the
// stop-sandboxes of a sign-out alike. A stop it makes for a security alarm
// (WithEmergencyStop) contains the VM instead (containUnsynced), and says
// whether it could. Once OpenShell takes an accepted one,
// the feed says what it may have lost (flushFailed), never for a stop that
// was refused or not made. One whose main process
// completed or failed OpenShell returns as it is: it keeps its phase, and
// with it the OpenShell gateway (HoldsCompute), until OpenShell reports
// another.
func (m *Manager) stop(ctx context.Context, b *box) error {
	gw, err := m.gateway(ctx)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, defaultOpTimeout)
	defer cancel()
	m.mu.Lock()
	name, reason, driver := b.rec.Name, b.rec.PhaseReason, b.rec.Driver
	// OpenShell stops nothing of a sandbox whose workload ended: its phase
	// stays until OpenShell reports another.
	ended := b.phase == audit.SandboxPhaseCompleted ||
		b.phase == audit.SandboxPhaseError && !openshell.VMGone(reason) && !openshell.ProvisioningTimedOut(reason)
	m.mu.Unlock()
	if err := m.checkSandbox(ctx, gw, b); err != nil {
		return err
	}
	// The harness exits on its own first, so its end-of-session hook runs
	// and its terminal ends as after /exit (graceful.go); a detached run
	// the stop ends is marked interrupted, and once the stop is published
	// its log is kept for `sandbox logs` of the stopped sandbox (runlog.go).
	run, flushErr := m.endHarness(ctx, gw, b)
	if flushErr != nil && !sandboxapi.DiscardUnsynced(ctx) {
		m.logf("sandbox %s: not stopped: its disk could not be synced first: %v", name, flushErr)
		if why, ok := emergencyStop(ctx); ok {
			return containedStopRefusal(name, flushErr, m.containUnsynced(ctx, b, why))
		}
		return unsyncedStopRefusal(name, flushErr)
	}
	if !ended {
		m.lifecycle(ctx, b, audit.SandboxPhaseStopping, audit.SandboxTriggerStop, false, nil, nil)
	}
	m.keepRunLog(ctx, gw, b, run)
	stopped, err := gw.Client.StopSandbox(ctx, name)
	if err != nil && transientGatewayError(err) {
		// The connection closed under the call (the gateway restarted, or
		// another call dropped the connection): the stop goes again on a fresh
		// one instead of ending the session with gRPC's words (GAP-0601).
		if cur, ok := m.reconnect(ctx, gw, err); ok {
			gw = cur
			if now, gerr := gw.Client.GetSandbox(ctx, name); gerr == nil && auditPhase(now.Status.Phase) == audit.SandboxPhaseStopped {
				err = nil
			} else {
				_, err = gw.Client.StopSandbox(ctx, name)
			}
		}
	}
	if err != nil {
		m.dropGateway(gw, err)
		m.stopFailed(ctx, gw, b)
		if e := m.errorPhaseRefusal(name, reason, driver, err); e != nil {
			return e
		}
		if e := m.errorPhaseNow(b); e != nil {
			return e
		}
		if connectionClosed(err) {
			// gRPC's own words reached the user's session end (GAP-0337).
			return sandboxapi.Errorf(sandboxapi.CodeUnavailable, "the connection to the OpenShell gateway closed while %s was stopping "+
				"(a restart of Docker or of the gateway does that); `defenseclaw sandbox status %s` shows where it stands", name, name)
		}
		return upstream("stop sandbox "+name, err)
	}
	if ph := stoppedAsIs(stopped); ph != "" {
		// OpenShell returns a sandbox whose workload completed, or whose
		// main process failed, as it is: it stops nothing, and flushes
		// nothing, of its MicroVM, which may still run what its workload
		// left running, so it still holds the gateway
		// (openshell.HoldsGateway; the caller says how to stop it:
		// openshell.StopWayOn).
		var cond *audit.SandboxCondition
		if ph == audit.SandboxPhaseError && reason != "" {
			cond = &audit.SandboxCondition{Reason: reason}
		}
		m.mu.Lock()
		b.sb = stopped
		m.mu.Unlock()
		m.lifecycle(ctx, b, ph, audit.SandboxTriggerStop, false, cond, stopped.Status.ExitCode)
		return nil
	}
	// OpenShell took the stop: what the flush did not confirm is lost now.
	if flushErr != nil {
		m.flushFailed(name, flushErr)
	}
	sb, err := gw.Client.WaitStopped(ctx, name)
	if err != nil && transientGatewayError(err) {
		if cur, ok := m.reconnect(ctx, gw, err); ok {
			gw = cur
			sb, err = gw.Client.WaitStopped(ctx, name)
		}
	}
	if err != nil {
		m.stopFailed(ctx, gw, b)
		// OpenShell before 0.1.5 takes the stop of a MicroVM in its error
		// state and then fails the wait ("sandbox is in error state"): the
		// sandbox, why and the way on, not OpenShell's words alone
		// (GAP-0871).
		if e := m.errorPhaseNow(b); e != nil {
			return e
		}
		return upstream("wait for sandbox "+name+" to stop", err)
	}
	m.mu.Lock()
	b.sb = sb
	m.mu.Unlock()
	m.lifecycle(ctx, b, auditPhase(sb.Status.Phase), audit.SandboxTriggerStop, false, nil, sb.Status.ExitCode)
	return nil
}

// unsyncedStopRefusal refuses the stop of the MicroVM name whose disk could
// not be synced first (err): its stop does not flush, so what the guest
// wrote since its last sync would be lost. It keeps running instead, and
// the user decides (sandboxapi.CodeUnsynced): the CLI asks, and says what is
// lost, before it stops it with sandboxapi.StopRequest.DiscardUnsynced.
func unsyncedStopRefusal(name string, err error) error {
	return &sandboxapi.Error{Code: sandboxapi.CodeUnsynced,
		Message: "sandbox " + name + " was not stopped: its MicroVM's disk could not be synced first (" + truncate(sandboxapi.DisplayText(err.Error()), 200) +
			"), so a stop now would lose what it wrote since its last sync; it keeps running",
		Detail: "save the work you need and stop it again, or stop it anyway, losing that: `defenseclaw sandbox stop " + name +
			" --discard-unsynced` (on a terminal, `defenseclaw sandbox stop " + name + "` asks first)"}
}

// containedStopRefusal is the error of a stop DefenseClaw made for a
// security alarm (WithEmergencyStop), or of a start's stop of a sandbox it
// must not leave running (stopUnverified), that left the MicroVM name
// running because its disk could not be synced first (flushErr), contained
// instead (containUnsynced); containErr is what of the containment could
// not be done or confirmed.
func containedStopRefusal(name string, flushErr, containErr error) error {
	state := "DefenseClaw contained it instead: " + containedContainment
	if containErr != nil {
		state = "and DefenseClaw could not confirm it contained (" + truncate(sandboxapi.DisplayText(containErr.Error()), 300) + ")"
	}
	return &sandboxapi.Error{Code: sandboxapi.CodeUnsynced,
		Message: "sandbox " + name + " was not stopped: its MicroVM's disk could not be synced first (" + truncate(sandboxapi.DisplayText(flushErr.Error()), 200) +
			"), so it keeps running, " + containedUnprotected + "; " + state,
		Detail: "save the work you need, then stop it: `defenseclaw sandbox stop " + name + "` (on a terminal it asks before it stops the VM without the sync)"}
}

// emergencyStopKey is the context key of WithEmergencyStop.
type emergencyStopKey struct{}

// WithEmergencyStop is ctx for a stop DefenseClaw makes on its own for a
// security alarm, why in words (a hook alarm, repeated foreign network
// rules, a lost listener, a revoked registration): one that must not leave
// the sandbox as it is. Where that stop would lose what a MicroVM has not
// synced, DefenseClaw never makes it (GAP-0902): it contains the VM
// instead (containUnsynced) and the stop fails with what it did.
func WithEmergencyStop(ctx context.Context, why string) context.Context {
	return context.WithValue(ctx, emergencyStopKey{}, why)
}

// EmergencyStopReason is the why of a WithEmergencyStop ctx, "" for any
// other.
func EmergencyStopReason(ctx context.Context) string {
	why, _ := ctx.Value(emergencyStopKey{}).(string)
	return why
}

// emergencyStop reports a WithEmergencyStop ctx and its why.
func emergencyStop(ctx context.Context) (string, bool) {
	why := EmergencyStopReason(ctx)
	return why, why != ""
}

// lockStart takes the gateway's lifecycle lock for a create or a start
// (Options.StartLock), which it holds over OpenShell's call only: while
// DefenseClaw restarts or upgrades the gateway (doctor --fix, setup, the
// OpenShell upgrade), whose check of the sandboxes would not see one
// started after it, the call is refused.
//
// Only lockRun takes it.
func (m *Manager) lockStart() (func(), error) {
	if m.opts.StartLock == nil {
		return func() {}, nil
	}
	unlock, err := m.opts.StartLock()
	switch {
	case errors.Is(err, openshell.ErrGatewayBusy):
		return nil, &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Message: "DefenseClaw is restarting or upgrading the OpenShell gateway",
			Detail: "start the sandbox again once `defenseclaw sandbox doctor --fix`, `defenseclaw sandbox setup` or the OpenShell upgrade has finished"}
	case err != nil:
		return nil, sandboxapi.Errorf(sandboxapi.CodeInternal, "take the OpenShell gateway's lifecycle lock: %v", err)
	}
	return unlock, nil
}

// lockRun takes the start lock (lockStart) for the gateway call that runs
// a new sandbox or session (CreateSandbox, StartSandbox), checks once more
// that no guest DefenseClaw cannot show protected runs
// (unprotectedRunRefusal; except as for legacyRunRefusal), and holds
// runGate shared until the returned func. A guest recorded contained
// (containUnsynced) after the create's or start's first check is so
// refused here, and one contained while the call runs is recorded only
// once it returned: that sandbox then ran before it, as one already
// running does. The caller unlocks right after the call.
func (m *Manager) lockRun(except string) (func(), error) {
	unlockStart, err := m.lockStart()
	if err != nil {
		return nil, err
	}
	m.runGate.RLock()
	if err := m.unprotectedRunRefusal(except); err != nil {
		m.runGate.RUnlock()
		unlockStart()
		return nil, err
	}
	return func() {
		m.runGate.RUnlock()
		unlockStart()
	}, nil
}

// stoppedAsIs is the phase of a sandbox OpenShell's stop returned as it
// was, as OpenShell (0.1.3 and 0.1.5) does for one whose workload completed
// or whose main process failed (the error state with an exit code); ""
// for one it stops.
func stoppedAsIs(sb *openshell.Sandbox) audit.SandboxPhase {
	if sb == nil {
		return ""
	}
	switch ph := auditPhase(sb.Status.Phase); {
	case ph == audit.SandboxPhaseCompleted, ph == audit.SandboxPhaseError && sb.Status.ExitCode != nil:
		return ph
	}
	return ""
}

// transientGatewayError reports a call that failed because the connection to
// the OpenShell gateway closed or dropped, not because OpenShell refused it.
func transientGatewayError(err error) bool {
	return err != nil && (connectionClosed(err) || openshell.IsUnavailable(err))
}

// reconnect forgets gw when err says it broke and returns the connection in
// use now (dialled again when there is none), or false when there is none.
func (m *Manager) reconnect(ctx context.Context, gw *Gateway, err error) (*Gateway, bool) {
	m.dropGateway(gw, err)
	cur, gerr := m.gateway(ctx)
	if gerr != nil {
		return gw, false
	}
	return cur, true
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
	if err == nil && !m.sameSandbox(b, sb) {
		return
	}
	phase := audit.SandboxPhaseUnknown
	if err == nil {
		m.mu.Lock()
		b.sb = sb
		m.mu.Unlock()
		phase = auditPhase(sb.Status.Phase)
	}
	if phase == audit.SandboxPhaseUnknown && pending == audit.SandboxPhaseDeleting {
		// OpenShell refused the delete and does not say what it left: the
		// VM may run as before. Its phase is unknown, which holds its
		// compute, not DefenseClaw's own deleting, which does not: a stop
		// would skip its sync, and the status would count it idle for the
		// gateway's stop (GAP-1084).
		m.lifecycle(ctx, b, audit.SandboxPhaseUnknown, trigger, false, nil, nil)
		return
	}
	if phase != pending && phase != audit.SandboxPhaseUnknown {
		// A failing condition explains an error phase (statusEvent), which
		// the status then names (GAP-0297).
		var cond *audit.SandboxCondition
		for _, c := range sb.Status.Conditions {
			if phase == audit.SandboxPhaseError && !strings.EqualFold(c.Status, "true") {
				if cond == nil || strings.EqualFold(c.Type, "Ready") {
					cond = &audit.SandboxCondition{Type: c.Type, Status: c.Status, Reason: c.Reason, Message: c.Message}
				}
				if strings.EqualFold(c.Type, "Ready") {
					break
				}
			}
		}
		m.lifecycle(ctx, b, phase, trigger, false, cond, sb.Status.ExitCode)
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
	if !m.sameSandboxLocked(b, sb) {
		report := m.missingFromLocked(gw, b)
		m.mu.Unlock()
		report(ctx)
		return errReplaced(name)
	}
	foundOnLocked(b, gw, sb)
	m.mu.Unlock()
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

// endSessionUnblocks drops a managed sandbox's session unblocks (and the
// session answers to its proxy asks, which are such unblocks) before it
// starts a new session: on a managed computer a session answer lasts while
// the sandbox runs, and a stored "always" decision is what outlives a stop
// (plan section 6.2, GAP-0574, GAP-0676). Outside managed mode an unblock
// for a sandbox lasts as long as the sandbox.
func (m *Manager) endSessionUnblocks(b *box) {
	if !m.managedMode() {
		return
	}
	m.mu.Lock()
	scope, had := scopeID(b.rec.ID, b.rec.Name), len(b.rec.Unblocks) > 0 || len(b.rec.Approved) > 0
	b.rec.Unblocks, b.rec.Approved = nil, nil
	name := b.rec.Name
	// The answers of the last session: an ask of the new one for the same
	// destination is not one approved moments ago, which proxyAsk and
	// hostPortAsk would otherwise not raise again.
	for id, a := range m.approvals {
		if a.sandbox == name && a.status == sandboxapi.ApprovalApproved && !a.always {
			delete(m.approvals, id)
		}
	}
	m.mu.Unlock()
	if m.unblocks.RemoveSandbox(scope)+m.approved.RemoveSandbox(scope) == 0 && !had {
		return
	}
	if err := m.saveRecord(b); err != nil {
		m.logf("drop the session unblocks of %s: %v", name, err)
	}
	m.refreshEgress()
}

// endSessionRules removes from a managed sandbox's OpenShell policy the
// rules the person approved for its last session (record.ApprovedRules,
// operator), which outlived a stop like the session unblocks did: on a
// managed computer an approval lasts while the sandbox runs, and only a
// saved "always" decision of the managed gateway that opens every endpoint
// of a rule (coveredByDecisions) keeps it for the next session. Rules
// DefenseClaw approved on its own stay: the policy approves them again.
// Outside managed mode an approved rule lasts as long as the sandbox.
func (m *Manager) endSessionRules(ctx context.Context, gw *Gateway, b *box, eff *packs.Effective) error {
	if !m.managedMode() {
		return nil
	}
	m.mu.Lock()
	name, origins := b.rec.Name, b.rec.ApprovedRules
	m.mu.Unlock()
	mine := false
	for _, origin := range origins {
		mine = mine || origin == actorOperator
	}
	if !mine {
		return nil
	}
	cfg, err := gw.Client.SandboxConfig(ctx, name)
	if err != nil {
		var rules []string
		for rule, origin := range origins {
			if origin == actorOperator {
				rules = append(rules, rule)
			}
		}
		sort.Strings(rules)
		return &sessionRulesError{rules: rules, err: upstream("read the policy of sandbox "+name, err)}
	}
	var decided map[string]bool
	if m.authority() != nil {
		decided = decidedHosts(m.savedDecisions(m.registrationOf(b), m.floor(eff)))
	}
	var gone, ended []string
	var ops []openshell.PolicyMergeOperation
	for rule, origin := range origins {
		if origin != actorOperator {
			continue
		}
		var current v1.NetworkPolicyRule
		var ok bool
		if cfg != nil && cfg.Policy != nil {
			current, ok = cfg.Policy.NetworkPolicies[rule]
		}
		switch {
		case !ok:
			gone = append(gone, rule)
		case !coveredByDecisions(triage.FromChunk(name, openshell.PolicyChunk{RuleName: rule, ProposedRule: &current}), decided):
			ended = append(ended, rule)
			ops = append(ops, openshell.PolicyMergeOperation{RemoveRule: &v1.RemoveNetworkRule{RuleName: rule}})
		}
	}
	if len(ops) == 0 {
		m.forgetApprovedRules(b, gone)
		return nil
	}
	sort.Strings(ended)
	res, err := gw.Client.MergePolicy(ctx, name, ops, openshell.PolicyUpdateOptions{
		Annotations: map[string]string{"source": "defenseclaw", "reason": "session-ended"},
	})
	if err != nil {
		m.forgetApprovedRules(b, gone)
		return &sessionRulesError{rules: ended, err: upstream("end the session approvals of sandbox "+name, err)}
	}
	m.logf("sandbox %s: the rules approved for its last session ended with it: %s", name, strings.Join(ended, ", "))
	m.forgetApprovedRules(b, append(gone, ended...))
	m.mu.Lock()
	id := b.identity()
	if res != nil && res.Version != 0 {
		id.PolicyVersion = res.Version
	}
	m.mu.Unlock()
	for _, rule := range ended {
		ev := audit.SandboxPolicyEvent{Sandbox: id, Operation: audit.SandboxPolicyRuleRemove, Actor: "policy", Origin: "internal",
			Target: rule, Reason: policyReasonApprovalRequired, ChangeCount: 1, Timestamp: m.now()}
		if res != nil {
			ev.PolicyHash = res.PolicyHash
		}
		m.tel.RecordSandboxPolicy(ctx, ev)
	}
	return nil
}

// sessionRulesError is a failed endSessionRules: the rules it could not
// remove (every rule the person approved when the policy could not be
// read) and why.
type sessionRulesError struct {
	rules []string
	err   error
}

func (e *sessionRulesError) Error() string { return e.err.Error() }
func (e *sessionRulesError) Unwrap() error { return e.err }

// sessionRulesLeft is the refusal of a start whose sandbox still has rules
// approved for its last session after both tries to remove them: the new
// session must not run with them (GAP-0014), so it was stopped again.
// stopErr is that stop's failure: the sandbox then still runs with the
// rules, and the refusal says so and how to end it instead. The gateway's
// own words stay in the log.
func sessionRulesLeft(name string, err, stopErr error, stopFlushes bool) error {
	rules, these := "the network rules", "the rules"
	what := "the network rules approved for its last session"
	var left *sessionRulesError
	if errors.As(err, &left) && len(left.rules) == 1 {
		rules, these = "the network rule "+left.rules[0], "the rule"
		what = rules + ", approved for its last session,"
	} else if left != nil && len(left.rules) > 1 {
		rules = "the network rules " + strings.Join(left.rules, ", ")
		what = rules + ", approved for its last session,"
	}
	code := sandboxapi.CodeUpstream
	var apiErr *sandboxapi.Error
	if errors.As(err, &apiErr) {
		code = apiErr.Code
	}
	if stopErr != nil {
		return &sandboxapi.Error{Code: code,
			Message: "sandbox " + name + " is still running with " + rules + " approved for its last session: " + these +
				" could not be removed from its policy, and DefenseClaw could not stop the sandbox again",
			Detail: "a new session must not keep what was approved for the last one: stop it now with `defenseclaw sandbox stop " + name +
				"`, then start it again (the removal is tried first); if this repeats, `defenseclaw sandbox doctor` checks the OpenShell gateway"}
	}
	return &sandboxapi.Error{Code: code,
		Message: "sandbox " + name + " did not start: " + what + " could not be removed from its policy, " +
			"so " + stoppedUnverifiedOutcome(stopFlushes),
		Detail: "a new session does not keep what was approved for the last one; start it again " +
			"(the removal is tried first), and if this repeats, `defenseclaw sandbox doctor` checks the OpenShell gateway"}
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
	// A new session takes the supervisor of the gateway's release.
	if err := m.sandboxReleaseRefusal(gw); err != nil {
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
	// A MicroVM whose workload ended still runs its VM, which OpenShell's
	// start ends with no flush: only one the user asked to end goes on.
	if err := lingeringStartRefusal(rec.Name, gw.Driver, sb, rec.PhaseReason, req.EndVM); err != nil {
		return err
	}
	// No new session while a legacy guest runs unprotected; this one's
	// start ends it when it is an ended legacy MicroVM (--end-vm).
	if err := m.legacyRunRefusal(ctx, rec.Name); err != nil {
		return err
	}
	// Containment may have detached providers or removed rules before an
	// OpenShell error prevented its final confirmation, and the legacy VM
	// may have stopped since: the record said so before the first change
	// (OldSupervisorNetworkRestore), so the create-time policy comes back
	// even when the closed-network checkpoint was not reached. The closed
	// and providers fields alone are what earlier 1.0.4 builds of this
	// change recorded, until 1.0.4 ships.
	// A contained VM (record.Contained) gets the same.
	restoreLegacyNetwork := rec.OldSupervisorNetworkRestore || rec.OldSupervisorNetworkClosed || len(rec.OldSupervisorProviders) > 0 ||
		rec.Contained != "" || oldSupervisorLingering(auditPhase(sb.Status.Phase), rec)
	// A sandbox an OpenShell before 0.1.5 created keeps a Docker bootstrap
	// that 0.1.5 cannot read (GAP-0300): it moves to 0.1.5's format first.
	if err := m.migrateBootstrap(gw, rec.Name, sb); err != nil {
		return err
	}
	m.endSessionUnblocks(b)
	eff, violations, err := m.resolveBoxViolations(b)
	if err != nil {
		return err
	}
	if err := m.checkStart(ctx, gw, rec, eff, violations); err != nil {
		return err
	}
	// Before the sandbox runs again; a gateway that will not change the
	// policy of a stopped sandbox gets a second try once it runs.
	rulesLeft := m.endSessionRules(ctx, gw, b, eff)
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
	if rec.TokenDelivery == config.OpenShellTokenDeliveryProvider {
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
		if !managedBy(p.Labels, rec.Owner) || p.Labels[LabelSandbox] != rec.Name {
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
	digest, err := m.refreshModelCredential(ctx, gw, rec, req.LLM)
	if err != nil {
		return err
	}
	if digest != rec.LLMDigest {
		m.mu.Lock()
		b.rec.LLMDigest = digest
		// The rejection was of the old key.
		b.hooks.forgetModelRejection()
		m.mu.Unlock()
		if err := m.saveRecord(b); err != nil {
			return sandboxapi.Errorf(sandboxapi.CodeInternal, "save sandbox state: %v", err)
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
	// Not while DefenseClaw restarts or upgrades the gateway, nor beside a
	// guest contained since the run check above (lockRun).
	unlockRun, err := m.lockRun(rec.Name)
	if err != nil {
		return err
	}
	m.lifecycle(ctx, b, audit.SandboxPhaseStarting, audit.SandboxTriggerStart, false, nil, nil)
	_, err = gw.Client.StartSandbox(ctx, rec.Name)
	unlockRun()
	if err != nil {
		m.dropGateway(gw, err)
		m.restorePhase(ctx, gw, b, audit.SandboxTriggerStart, audit.SandboxPhaseStarting)
		if e := legacyBootstrapRefusal(rec.Name, gw.Version, err); e != nil {
			return e
		}
		if e := m.errorPhaseRefusal(rec.Name, rec.PhaseReason, rec.Driver, err); e != nil {
			return e
		}
		return upstream("start sandbox "+rec.Name, err)
	}
	sb, err = gw.Client.WaitReady(ctx, rec.Name)
	if err != nil {
		m.restorePhase(ctx, gw, b, audit.SandboxTriggerStart, audit.SandboxPhaseStarting)
		if e := overlayDiskRefusal(rec.Name, err); e != nil {
			m.logf("sandbox %s: %v", rec.Name, err)
			return e
		}
		return vmExitFailure(runtime.GOOS, m.managedMode(), gw.Driver, upstream("wait for sandbox "+rec.Name, err))
	}
	if restoreLegacyNetwork {
		// The old VM is gone now. Restore only its create-time network policy,
		// after the new supervisor is ready: never reopen a route while the
		// legacy supervisor can still run background work. Session approvals
		// removed above are not brought into the new session.
		if err := m.restoreOldSupervisorNetwork(ctx, gw, b, sb, eff); err != nil {
			detail := "DefenseClaw stopped the new session before it could run without its network policy"
			if stopErr := m.stopUnverified(ctx, gw, b); stopErr != nil {
				// Not stopped (a failed sync contains it instead, GAP-0902):
				// the start failed, and the VM still runs.
				detail = "DefenseClaw did not stop the new session, so it is still running: " + stopErr.Error()
			}
			return &sandboxapi.Error{Code: sandboxapi.CodeUnavailable,
				Message: "sandbox " + rec.Name + " did not restore its network on the new OpenShell supervisor: " + err.Error(),
				Detail:  detail}
		}
	}
	if rulesLeft != nil {
		if err := m.endSessionRules(ctx, gw, b, eff); err != nil {
			// Fail closed: a sandbox must not run a new session with a rule
			// approved for the last one.
			m.logf("sandbox %s: the rules approved for its last session are still in its policy: %v (before the start: %v); stopping it again",
				rec.Name, err, rulesLeft)
			return sessionRulesLeft(rec.Name, err, m.stopUnverified(ctx, gw, b), gw.Driver.StopFlushes)
		}
	}
	if err := settle(ctx, m.opts.SettleDelay); err != nil {
		return err
	}
	if err := m.verifyStarted(ctx, gw, b, rec); err != nil {
		return err
	}
	m.mu.Lock()
	b.sb = sb
	// A new session: its rule budget and approval rate start over.
	b.rulesAdded, b.autoApproved = 0, nil
	m.mu.Unlock()
	m.lifecycle(ctx, b, auditPhase(sb.Status.Phase), audit.SandboxTriggerStart, false, nil, nil)
	if restoreLegacyNetwork {
		m.syncCredential(b, eff)
	}
	m.observeNow(b)
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

// checkNewSecrets refuses to start a mounted sandbox whose project now
// holds files the secret scan would mask (by name, pattern or content)
// that its masks leave visible: they are fixed when the sandbox is
// created, so a secret file added since (a credential the user put in the
// project between sessions, a mask pattern the policy added) would be
// shared with the next session unnoticed. A scan that cannot finish fails
// closed, as it does on create.
func (m *Manager) checkNewSecrets(ctx context.Context, rec record, eff *packs.Effective, binding sandboxauth.Binding) error {
	visible, err := m.unmaskedSecrets(ctx, rec, eff, binding)
	if err != nil {
		return err
	}
	if len(visible) == 0 {
		return nil
	}
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

// unmaskedSecrets are the files of a mounted sandbox's project that the
// secret scan would mask but its create-time masks leave visible, sorted.
func (m *Manager) unmaskedSecrets(ctx context.Context, rec record, eff *packs.Effective, binding sandboxauth.Binding) ([]string, error) {
	found, err := m.ws.ScanSecrets(ctx, workspace.MountOptions{
		Project: rec.Project, Name: rec.Name, DataDir: m.opts.DataDir,
		Masks: eff.Workspace.Masks, Unmask: eff.Workspace.Unmask, Protected: eff.PolicySources(),
	})
	if err != nil {
		return nil, workspaceError(err)
	}
	have := maskedRels(binding, rec.Workdir)
	var visible []string
	for _, mk := range found {
		if !slices.ContainsFunc(have, func(h string) bool { return mk.Rel == h || strings.HasPrefix(mk.Rel, h+"/") }) {
			visible = append(visible, sandboxapi.DisplayText(mk.Rel))
		}
	}
	sort.Strings(visible)
	return visible, nil
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
	return m.deleteLocked(ctx, b, req)
}

// deleteLocked deletes b, whose operation lock the caller holds.
func (m *Manager) deleteLocked(ctx context.Context, b *box, req sandboxapi.DeleteRequest) (*sandboxapi.DeleteResponse, error) {
	m.mu.Lock()
	retained, name := b.retained, b.rec.Name
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
		_, err := gw.Client.DeleteSandbox(ctx, name)
		if err != nil && !openshell.IsNotFound(err) && transientGatewayError(err) {
			// The connection closed under the call: the delete goes again on a
			// fresh one (GAP-0601).
			if cur, ok := m.reconnect(ctx, gw, err); ok {
				gw = cur
				_, err = gw.Client.DeleteSandbox(ctx, name)
			}
		}
		if err != nil && !openshell.IsNotFound(err) {
			m.dropGateway(gw, err)
			m.deleteFailed(ctx, gw, b)
			return nil, upstream("delete sandbox "+name, err)
		}
		err = gw.Client.WaitDeleted(ctx, name)
		if err != nil && transientGatewayError(err) {
			if cur, ok := m.reconnect(ctx, gw, err); ok {
				gw = cur
				err = gw.Client.WaitDeleted(ctx, name)
			}
		}
		if err != nil {
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

// retainedPhase reports a phase delete_stopped_after counts: the sandbox
// was stopped, or completed (its main process ended), which on the MicroVM
// driver keeps its VM running until the sandbox is deleted (GAP-0012). The
// error phase is not counted: its owner decides (`delete --keep-snapshot`
// keeps the undo point).
func retainedPhase(p audit.SandboxPhase) bool {
	return p == audit.SandboxPhaseStopped || p == audit.SandboxPhaseCompleted
}

// retention is how long b may stay stopped: its floor's
// delete_stopped_after (the sandbox's resolved policy, else
// openshell.admin, which on a managed daemon is this sandbox's floor); 0
// keeps it.
func (m *Manager) retention(b *box) time.Duration {
	m.mu.Lock()
	eff := b.eff
	name := b.rec.Name
	m.mu.Unlock()
	f, ok := effectiveFloor(eff)
	if !ok {
		cfg := m.configForSandbox(name)
		if cfg == nil {
			return 0
		}
		f = cfg.OpenShell.Admin
	}
	if f.DeleteStoppedAfter == "" {
		return 0
	}
	d, err := config.ParseOpenShellFloorDuration(f.DeleteStoppedAfter)
	if err != nil {
		return 0
	}
	return max(d, config.OpenShellMinDeleteStoppedAfter)
}

// deleteExpired deletes, as delete_stopped_after asks, every sandbox that
// has been stopped or completed for longer than its floor allows: nothing
// deleted them, and a completed MicroVM held about 430 MB until then
// (GAP-0012). A sandbox busy with an operation waits for the next pass.
func (m *Manager) deleteExpired(ctx context.Context) {
	now := m.now()
	for _, b := range m.liveBoxes() {
		after := m.retention(b)
		if after <= 0 || !b.op.TryLock() {
			continue
		}
		m.mu.Lock()
		phase := b.phase
		if phase == "" {
			phase = audit.SandboxPhase(b.rec.Phase)
		}
		name, since := b.rec.Name, b.rec.StoppedAt
		expired := !b.creating && !b.deleted && !b.retained && retainedPhase(phase) && !since.IsZero() && now.Sub(since) >= after
		m.mu.Unlock()
		if expired {
			if _, err := m.deleteLocked(ctx, b, sandboxapi.DeleteRequest{}); err != nil {
				m.logf("sandbox %s: delete after %s stopped (delete_stopped_after): %v", name, after, err)
			} else {
				m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityLifecycle, Sandbox: name, Reason: "delete_stopped_after",
					Message: "sandbox " + name + " was deleted: it had not run for " + after.String() + ", the longest your policy keeps a stopped sandbox (delete_stopped_after)"})
			}
		}
		b.op.Unlock()
	}
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
	m.approved.RemoveSandbox(scopeID(rec.ID, rec.Name))
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
	// A sandbox kept for its snapshot reaches nothing any more.
	warn(m.dropDestinations(rec.Name, rec.BindingID))
	// A discovery that overlaps the release (an on-demand one) ends first,
	// and none writes the folder again.
	b.discoverMu.Lock()
	b.discoveryReleased = true
	warn(m.removeDiscovery(rec.Name))
	b.discoverMu.Unlock()
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
		owner := rec.Owner
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
	b.rec.ApprovedRules, b.rec.Approved = nil, nil
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
	name, gone := b.rec.Name, m.boxes[b.rec.Name] == b
	if gone {
		delete(m.boxes, name)
	}
	m.mu.Unlock()
	if gone {
		m.tel.forgetSandbox(name)
		// A sandbox created under the name later starts with no destinations.
		m.destMu.Lock()
		delete(m.dests, name)
		m.destMu.Unlock()
	}
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
				report := m.missingFromLocked(gw, b)
				m.mu.Unlock()
				report(ctx)
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
		m.tel.RecordSandboxWorkspace(ctx, audit.SandboxWorkspaceEvent{Sandbox: id, Operation: audit.SandboxWorkspaceUndo,
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
		m.tel.RecordSandboxWorkspace(ctx, audit.SandboxWorkspaceEvent{Sandbox: id, Operation: audit.SandboxWorkspaceUndo,
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
	// A secret file the session left in the project stops the next start
	// (checkNewSecrets): the review names it, so the end of the session can
	// say so before the keep/undo question. Best effort: a scan that cannot
	// finish leaves it to the start.
	if rec.Project != "" && eff != nil {
		if binding, err := m.opts.Bindings.Get(rec.BindingID); err == nil {
			if visible, err := m.unmaskedSecrets(ctx, rec, eff, binding); err == nil {
				resp.UnmaskedSecrets = visible
			}
		}
	}
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
	m.tel.RecordSandboxWorkspace(ctx, ev)
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
	m.tel.RecordSandboxWorkspace(ctx, ev)
}

// ReportDisk names in the activity feed the filling own disk of a running
// MicroVM that its session found (GAP-1140): the session warned in its
// terminal and summary only, so `sandbox activity` said nothing until the
// disk was full and the session over. Report only: nothing is stopped.
func (m *Manager) ReportDisk(_ context.Context, name string, r sandboxapi.DiskReport) error {
	if _, err := m.box(name); err != nil {
		return err
	}
	if r.SizeBytes <= 0 || r.FreeBytes < 0 || r.FreeBytes > r.SizeBytes {
		return sandboxapi.Errorf(sandboxapi.CodeInvalid, "size_bytes must be positive and free_bytes between 0 and size_bytes")
	}
	used := (r.SizeBytes - r.FreeBytes) * 100 / r.SizeBytes
	msg := fmt.Sprintf("its own disk is %d%% full (%s of %s free)", used, diskBytes(r.FreeBytes), diskBytes(r.SizeBytes))
	if r.Fast {
		msg += " and filling fast"
	}
	msg += ": a MicroVM stopped with its disk full cannot start again; `defenseclaw sandbox exec " + name +
		" -- df -h /` shows it, `defenseclaw sandbox pull " + name + "` brings its work back before it fills"
	m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityLifecycle, Sandbox: name, Reason: sandboxapi.ReasonDiskFilling, Message: msg})
	return nil
}

// diskBytes is n bytes in MiB, or in GiB with one decimal from 1 GiB.
func diskBytes(n int64) string {
	if n >= 1<<30 {
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	}
	return fmt.Sprintf("%d MiB", n>>20)
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
