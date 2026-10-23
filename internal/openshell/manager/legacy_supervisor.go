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
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// legacyUnprotected opens every account of a live legacy guest
// (oldSupervisorLive): the owner's words for the state.
const legacyUnprotected = "legacy sandbox running, not protected by the 1.0.4 egress policy"

// legacyContainment is what DefenseClaw does, and does not, about a live
// legacy guest. Closing its egress proxy and withdrawing the network rules
// and providers it added does not contain that supervisor's broker, which
// falls through to the native call when it cannot inspect a socket
// (GAP-0831), so the guest is never reported contained.
const legacyContainment = "DefenseClaw closed its egress proxy and withdraws the network rules it added, but that does not contain the old broker, " +
	"which passes a connection it cannot inspect straight to the host; DefenseClaw does not stop the sandbox for you, and until it is gone " +
	"it creates and starts no sandbox and runs nothing in it"

// legacyRulesKept opens the warning about a withdrawal of a live legacy
// guest's network rules that failed (the error follows).
const legacyRulesKept = "DefenseClaw could not withdraw the network rules it added to this legacy sandbox either, or confirm them withdrawn, so they may still let it out: "

// oldSupervisorLingering reports a VM with compute still held after the
// main process ended, whose session may use a broker from before 0.1.5.
// Docker's completed and error phases hold no compute, and ProcessExited
// means OpenShell has already reported the VM gone.
func oldSupervisorLingering(phase audit.SandboxPhase, rec record) bool {
	return !openshell.RunsSandboxes(rec.SessionRelease) &&
		(phase == audit.SandboxPhaseCompleted || phase == audit.SandboxPhaseError) &&
		holdsCompute(phase, rec.Driver, rec.PhaseReason)
}

// oldSupervisorLive reports a legacy guest that may still run the
// supervisor of an OpenShell release older than openshell.SupportedMin (or
// one its record does not name, a record of DefenseClaw 1.0.3 or older): a
// ready session on any driver, and a MicroVM whose workload ended but whose
// VM may still run (oldSupervisorLingering). DefenseClaw keeps it as it is
// until its user ends it, withdraws what it added to its network
// (containOldSupervisorNetwork), reports it unprotected and runs no new
// sandbox meanwhile (legacyRunRefusal).
func oldSupervisorLive(phase audit.SandboxPhase, rec record) bool {
	return phase == audit.SandboxPhaseReady && !openshell.RunsSandboxes(rec.SessionRelease) || oldSupervisorLingering(phase, rec)
}

// legacyWayOn is how the user ends the live legacy guest name in phase on
// compute driver driver ("" is docker): the stop of a ready one, which on
// a MicroVM syncs its disk first because that release's stop does not, and
// the delete of a MicroVM whose workload ended, which OpenShell does not
// stop (or, on OpenShell SupportedMin or later, its start with --end-vm).
func legacyWayOn(name string, phase audit.SandboxPhase, driver string) string {
	if phase == audit.SandboxPhaseReady {
		way := "save the work you need, then run `defenseclaw sandbox stop " + name + "`"
		if stopLosesWrites(driver) {
			way += ", which syncs the VM's disk first (that release's stop does not flush it, so what the guest writes after the sync may be lost)"
		}
		return way
	}
	return "OpenShell does not stop this VM, whose workload ended: `defenseclaw sandbox delete " + name + "` deletes it and its work, or on OpenShell " +
		openshell.SupportedMin + " or later `defenseclaw sandbox start " + name + " --end-vm` ends the VM, losing what it has not written to its disk"
}

// oldSupervisorWarning is the view's warning about the live legacy guest
// name in phase on driver (oldSupervisorLive).
func oldSupervisorWarning(name string, phase audit.SandboxPhase, driver string) string {
	what := "its session runs"
	if phase != audit.SandboxPhaseReady {
		what = "its MicroVM may still run background work on"
	}
	return legacyUnprotected + ": " + what + " the supervisor of an OpenShell release older than " + openshell.SupportedMin +
		", whose network broker can let the sandbox's connections bypass its policy (NVIDIA/OpenShell#4494). " + legacyContainment + ": " +
		legacyWayOn(name, phase, driver)
}

// oldSupervisorMessage is the feed's HIGH finding about the live legacy
// guest name (oldSupervisorLive) in phase on driver, whose session started
// on OpenShell release (a record from before DefenseClaw kept it: ""), older
// than openshell.SupportedMin. upgrade is the way on of a gateway that
// starts no sandbox (Manager.upgradeWayOn).
func oldSupervisorMessage(name, release string, phase audit.SandboxPhase, driver, upgrade string) string {
	which := "its session started on OpenShell " + release + ", whose network broker can let the sandbox's connections bypass its policy " +
		"(NVIDIA/OpenShell#4494), and it keeps that supervisor while it runs"
	if release == "" {
		which = "its session started before DefenseClaw kept the OpenShell release a session starts on, so it may run a supervisor older than " +
			openshell.SupportedMin + ", whose network broker can let the sandbox's connections bypass its policy (NVIDIA/OpenShell#4494)"
	}
	if phase != audit.SandboxPhaseReady {
		which = "its MicroVM may still run background work; " + which
	}
	msg := "⚠ " + name + ": " + legacyUnprotected + ": " + which + ". " + legacyContainment + ": " + legacyWayOn(name, phase, driver)
	switch {
	case phase != audit.SandboxPhaseReady:
		return msg
	case upgrade != "":
		return msg + "; then " + upgrade + ", and `defenseclaw sandbox start " + name + "` starts it on that release's supervisor"
	}
	return msg + "; then `defenseclaw sandbox start " + name + "` (or `connect`) starts it again on this gateway's supervisor"
}

// reconcileOldSupervisor retries the withdrawal of what DefenseClaw added
// to the network of a live legacy guest (oldSupervisorLive): the reconcile
// interval is the backoff after a failed policy update.
func (m *Manager) reconcileOldSupervisor(ctx context.Context, b *box) {
	m.mu.Lock()
	live := oldSupervisorLive(b.phase, b.rec)
	m.mu.Unlock()
	if live {
		m.containOldSupervisorNetwork(ctx, b)
	}
}

// legacyRunRefusal refuses a create or a start while a live legacy guest
// (oldSupervisorLive) other than except runs: its network cannot be
// contained (GAP-0831), so DefenseClaw runs no new sandbox until its user
// ends it. except is the sandbox a start ends that way (an ended legacy
// MicroVM started with --end-vm). The refusal names each guest with the
// command that ends it.
func (m *Manager) legacyRunRefusal(except string) error {
	m.mu.Lock()
	var live []string
	ways := map[string]string{}
	for name, b := range m.boxes {
		if name == except || b.retained || b.missing || b.deleted || b.creating || !oldSupervisorLive(b.phase, b.rec) {
			continue
		}
		live = append(live, name)
		ways[name] = name + ": " + legacyWayOn(name, b.phase, b.rec.Driver)
	}
	m.mu.Unlock()
	if len(live) == 0 {
		return nil
	}
	slices.Sort(live)
	detail := make([]string, 0, len(live))
	for _, name := range live {
		detail = append(detail, ways[name])
	}
	return &sandboxapi.Error{Code: sandboxapi.CodeConflict,
		Message: "DefenseClaw runs no new sandbox while " + strings.Join(live, ", ") + " runs (" + legacyUnprotected + "): its session runs the supervisor " +
			"of an OpenShell release older than " + openshell.SupportedMin + ", whose network broker can let connections bypass sandbox policy " +
			"(NVIDIA/OpenShell#4494), and DefenseClaw cannot contain it",
		Detail: strings.Join(detail, "; ") + "; then run again"}
}

const oldSupervisorEgressOff = legacyUnprotected + ": it may run the supervisor of an OpenShell release older than " + openshell.SupportedMin +
	", so DefenseClaw's egress proxy is closed to it until it stops"

// suspendOldSupervisorEgress closes the DefenseClaw proxy route, including
// tunnels already open. Called again on policy refresh so a legacy guest
// (oldSupervisorLive) is never registered again while it lives.
func (m *Manager) suspendOldSupervisorEgress(b *box) {
	m.mu.Lock()
	cred, rec := b.cred, b.rec
	m.mu.Unlock()
	if rec.BindingID == "" {
		return
	}
	why := egress.Decision{Category: egress.CategoryEgressOff, Source: egress.SourceDefault, Reason: oldSupervisorEgressOff}
	if cred.Username == "" || m.creds.Suspend(cred, m.principal(rec.BindingID, scopeID(rec.ID, rec.Name), rec.Name, nil, nil), why) != nil {
		m.creds.Revoke(rec.BindingID)
	}
	m.recheckEgress(rec.BindingID)
	m.noteEgressOff(b, oldSupervisorEgressOff)
}

// containOldSupervisorNetwork closes DefenseClaw's egress proxy to a live
// legacy guest (oldSupervisorLive) and withdraws every OpenShell network
// rule and provider of it. That is what DefenseClaw added to its network,
// not a containment of the old broker, which passes a socket it cannot
// inspect to the native call (GAP-0831): the guest stays reported
// unprotected, and no new sandbox runs while it lives (legacyRunRefusal).
// The proxy suspension runs first even if the gateway cannot be reached. A
// rule update is conditional on the current resource version, so a
// concurrent new session cannot have its rules stripped. Reconcile retries
// failed or not-yet-loaded updates.
func (m *Manager) containOldSupervisorNetwork(ctx context.Context, b *box) {
	m.suspendOldSupervisorEgress(b)
	if !b.op.TryLock() {
		m.scheduleOldSupervisorNetwork(b)
		return
	}
	defer b.op.Unlock()
	m.containOldSupervisorNetworkLocked(ctx, b)
}

// scheduleOldSupervisorNetwork waits for a concurrent start, stop or delete
// to finish before withdrawing rules. In particular, a start cannot read
// the old record before containment and then launch under a stripped policy.
func (m *Manager) scheduleOldSupervisorNetwork(b *box) {
	m.mu.Lock()
	if b.oldSupervisorNetworkBusy {
		m.mu.Unlock()
		return
	}
	b.oldSupervisorNetworkBusy = true
	b.oldSupervisorNetworkErr = "network containment is pending behind a sandbox operation"
	m.mu.Unlock()
	m.tamperStops.Add(1)
	go func() {
		defer m.tamperStops.Done()
		b.op.Lock()
		defer b.op.Unlock()
		defer func() {
			m.mu.Lock()
			b.oldSupervisorNetworkBusy = false
			m.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), defaultOpTimeout)
		defer cancel()
		m.containOldSupervisorNetworkLocked(ctx, b)
	}()
}

// containOldSupervisorNetworkLocked runs with the sandbox operation lock,
// so the start cannot race between closing its old rules and recording that
// it must restore the create-time rules on the new supervisor.
func (m *Manager) containOldSupervisorNetworkLocked(ctx context.Context, b *box) {
	m.mu.Lock()
	rec, phase := b.rec, b.phase
	m.mu.Unlock()
	if !oldSupervisorLive(phase, rec) {
		m.mu.Lock()
		b.oldSupervisorNetworkErr = ""
		m.mu.Unlock()
		return
	}
	err := m.withdrawOldSupervisorRules(ctx, b)
	m.mu.Lock()
	newlyClosed := err == nil && !b.rec.OldSupervisorNetworkClosed
	if newlyClosed {
		b.rec.OldSupervisorNetworkClosed = true
	}
	m.mu.Unlock()
	if newlyClosed {
		if saveErr := m.saveRecord(b); saveErr != nil {
			err = fmt.Errorf("save the closed-network state: %w", saveErr)
			m.mu.Lock()
			b.rec.OldSupervisorNetworkClosed = false
			m.mu.Unlock()
		}
	}
	m.mu.Lock()
	previous := b.oldSupervisorNetworkErr
	b.oldSupervisorNetworkErr = ""
	if err != nil {
		b.oldSupervisorNetworkErr = err.Error()
	}
	changed := previous != b.oldSupervisorNetworkErr
	m.mu.Unlock()
	if err != nil && changed {
		m.logf("old supervisor: cannot close the network of %s: %v", rec.Name, err)
		m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityFinding, Sandbox: rec.Name, Severity: "HIGH",
			Reason: sandboxapi.ReasonOldSupervisor, Message: "⚠ " + rec.Name + ": " + legacyUnprotected + ": " + legacyRulesKept + err.Error() + "; " +
				legacyWayOn(rec.Name, phase, rec.Driver)})
	}
}

func (m *Manager) withdrawOldSupervisorRules(ctx context.Context, b *box) error {
	m.mu.Lock()
	rec := b.rec
	m.mu.Unlock()
	name := rec.Name
	gw, err := m.gateway(ctx)
	if err != nil {
		return err
	}
	global, err := gw.Client.GlobalPolicy(ctx)
	if err != nil {
		return err
	}
	if global != nil {
		return fmt.Errorf("a gateway-global policy prevents changing this sandbox's network rules")
	}
	sb, err := gw.Client.GetSandbox(ctx, name)
	if err != nil {
		return err
	}
	if sb == nil || (sb.Status.Phase != openshell.PhaseReady && sb.Status.Phase != openshell.PhaseCompleted && sb.Status.Phase != openshell.PhaseError) {
		return fmt.Errorf("OpenShell no longer reports this legacy sandbox live")
	}
	// OpenShell composes attached providers' direct endpoints into the
	// effective policy. Removing their generated rule names from the base
	// policy cannot close those routes: detach first, and remember exactly
	// what this containment detached for the next safe supervisor.
	// Before the first change, the record says the next session must get
	// the create-time network back (OldSupervisorNetworkRestore), whatever
	// stops this containment later; a record that can't say so changes
	// nothing.
	active := slices.Clone(sb.Spec.Providers)
	rec.OldSupervisorProviders = slices.Clone(rec.OldSupervisorProviders)
	changed := !rec.OldSupervisorNetworkRestore
	for _, provider := range active {
		if slices.Contains(rec.Providers, provider) && !slices.Contains(rec.DetachedProviders, provider) &&
			!slices.Contains(rec.OldSupervisorProviders, provider) {
			rec.OldSupervisorProviders = append(rec.OldSupervisorProviders, provider)
			changed = true
		}
	}
	if changed {
		slices.Sort(rec.OldSupervisorProviders)
		m.mu.Lock()
		restore, providers := b.rec.OldSupervisorNetworkRestore, b.rec.OldSupervisorProviders
		b.rec.OldSupervisorNetworkRestore, b.rec.OldSupervisorProviders = true, rec.OldSupervisorProviders
		m.mu.Unlock()
		if err := m.saveRecord(b); err != nil {
			m.mu.Lock()
			b.rec.OldSupervisorNetworkRestore, b.rec.OldSupervisorProviders = restore, providers
			m.mu.Unlock()
			return fmt.Errorf("save the network to restore: %w", err)
		}
	}
	for _, provider := range active {
		if _, err := gw.Client.DetachProvider(ctx, name, provider); err != nil && !openshell.IsNotFound(err) {
			return fmt.Errorf("detach the direct network of provider %s: %w", provider, err)
		}
	}
	cfg, err := gw.Client.SandboxConfig(ctx, name)
	if err != nil {
		return err
	}
	if cfg == nil || cfg.Policy == nil {
		return fmt.Errorf("OpenShell returned no sandbox policy")
	}
	version := cfg.PolicyVersion
	if len(cfg.Policy.NetworkPolicies) > 0 {
		sb, err = gw.Client.GetSandbox(ctx, name)
		if err != nil {
			return err
		}
		if sb == nil || (sb.Status.Phase != openshell.PhaseReady && sb.Status.Phase != openshell.PhaseCompleted && sb.Status.Phase != openshell.PhaseError) {
			return fmt.Errorf("OpenShell no longer reports this legacy sandbox live")
		}
		names := make([]string, 0, len(cfg.Policy.NetworkPolicies))
		for rule := range cfg.Policy.NetworkPolicies {
			names = append(names, rule)
		}
		sort.Strings(names)
		ops := make([]openshell.PolicyMergeOperation, 0, len(names))
		for _, rule := range names {
			ops = append(ops, openshell.PolicyMergeOperation{RemoveRule: &v1.RemoveNetworkRule{RuleName: rule}})
		}
		res, err := gw.Client.MergePolicy(ctx, name, ops, openshell.PolicyUpdateOptions{
			ExpectedResourceVersion: sb.ResourceVersion,
			Annotations:             map[string]string{"source": "defenseclaw", "reason": "old-supervisor-network"},
		})
		if err != nil {
			return err
		}
		if res == nil {
			return fmt.Errorf("OpenShell returned no policy revision")
		}
		version = res.Version
	}
	if err := waitNetworkPolicy(ctx, gw, name, version); err != nil {
		return err
	}
	confirmed, err := gw.Client.SandboxConfig(ctx, name)
	if err != nil {
		return err
	}
	if confirmed == nil || confirmed.Policy == nil || len(confirmed.Policy.NetworkPolicies) != 0 {
		return fmt.Errorf("OpenShell still reports network rules after the closed policy loaded")
	}
	return nil
}

// waitNetworkPolicy waits for the supervisor to load the revision: a
// committed gateway revision alone does not close live egress.
func waitNetworkPolicy(ctx context.Context, gw *Gateway, name string, version uint32) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := gw.Client.PolicyStatus(ctx, name, 0)
		if err != nil {
			return err
		}
		if status != nil && status.ActiveVersion == status.Revision.Version && status.ActiveVersion >= version {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("OpenShell did not load network policy revision %d: %w", version, ctx.Err())
		case <-ticker.C:
		}
	}
}

// restoreOldSupervisorNetwork restores only the create-time rules after a
// new supervisor is ready. Old session approvals are not brought into it.
func (m *Manager) restoreOldSupervisorNetwork(ctx context.Context, gw *Gateway, b *box, sb *openshell.Sandbox, eff *packs.Effective) error {
	if sb == nil || sb.Spec.Policy == nil {
		return fmt.Errorf("OpenShell returned no create-time policy")
	}
	m.mu.Lock()
	rec := b.rec
	m.mu.Unlock()
	res, err := gw.Client.SetPolicy(ctx, sb.Name, sb.Spec.Policy, openshell.PolicyUpdateOptions{
		Annotations: map[string]string{"source": "defenseclaw", "reason": "new-supervisor-network"},
	})
	if err != nil {
		return err
	}
	if res == nil {
		return fmt.Errorf("OpenShell returned no policy revision")
	}
	if err := waitNetworkPolicy(ctx, gw, sb.Name, res.Version); err != nil {
		return err
	}
	attached := slices.Clone(sb.Spec.Providers)
	for _, provider := range rec.OldSupervisorProviders {
		if !slices.Contains(rec.Providers, provider) || slices.Contains(rec.DetachedProviders, provider) {
			continue
		}
		if slices.Contains(attached, provider) {
			continue
		}
		for _, ep := range rec.ProviderEndpoints {
			if ep.Provider == provider {
				if err := endpointRefusal(eff, ep); err != nil {
					return fmt.Errorf("provider %s is no longer allowed: %w", provider, err)
				}
			}
		}
		if _, err := gw.Client.AttachProvider(ctx, sb.Name, provider); err != nil {
			return fmt.Errorf("restore provider %s on the new supervisor: %w", provider, err)
		}
		attached = append(attached, provider)
	}
	if err := waitNetworkPolicy(ctx, gw, sb.Name, res.Version); err != nil {
		return err
	}
	m.mu.Lock()
	b.rec.OldSupervisorNetworkClosed = false
	b.rec.OldSupervisorProviders = nil
	b.rec.OldSupervisorNetworkRestore = false
	b.oldSupervisorNetworkErr = ""
	m.mu.Unlock()
	if err := m.saveRecord(b); err != nil {
		m.mu.Lock()
		b.rec.OldSupervisorNetworkClosed = rec.OldSupervisorNetworkClosed
		b.rec.OldSupervisorProviders = rec.OldSupervisorProviders
		b.rec.OldSupervisorNetworkRestore = rec.OldSupervisorNetworkRestore
		m.mu.Unlock()
		return err
	}
	return nil
}
