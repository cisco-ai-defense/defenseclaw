// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import (
	"context"
	"fmt"
	"sort"
	"time"
)

func isControlsFamily(f Family) bool { return f == FamilyControls || f == FamilyBurnin }

func sortedLoaded(byName map[string]LoadedPolicy) []string {
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// pass is one reconcile: read every input, decide, render, lint, and apply
// with add-before-delete calls that only ever touch names this helper
// recorded. Any failure leaves enforcing policies in monitor mode; nothing
// here ever widens a scope to recover.
func (c *Controller) pass(ctx context.Context, trigger string) {
	now := c.cfg.Now()
	intent := c.cfg.Intent
	c.st.Warnings = append([]string(nil), intent.Problems...)
	removeExpiredPause(c.cfg.Dirs, now)
	pause := ReadPause(c.cfg.Dirs, now)
	c.notePause(pause)
	if pause.Invalid != "" {
		c.st.Warnings = addUnique(c.st.Warnings, WarnPauseInvalid)
	}

	// Inputs from root-owned sources.
	if enrollment, err := c.cfg.Enrollment(); err == nil {
		c.enrollment = enrollment
	} else {
		c.cfg.Logger.Warn("guardian manifest unreadable; keeping the previous enrollment", "error", err)
		c.st.Warnings = addUnique(c.st.Warnings, "enrollment_unreadable")
	}
	c.rescan()
	c.tallyMu.Lock()
	resets := c.burn.Sync(Digest(), c.enrollment, now)
	c.tallyMu.Unlock()
	for uid, reason := range resets {
		uid := uid
		c.change(Change{Event: EventUIDBurnIn, UID: &uid, Reason: reason,
			NeededSeconds: int64(intent.BurnIn / time.Second)})
	}

	callCtx, cancel := context.WithTimeout(ctx, c.cfg.Intervals.Call)
	defer cancel()
	client, closeFn, err := c.cfg.Dial(callCtx)
	if err != nil {
		c.unreachable(err)
		return
	}
	if closeFn != nil {
		defer closeFn()
	}
	g := guard(client, intent.Mode, c.mayTouch)
	agent, err := g.Agent(callCtx)
	if err != nil {
		c.unreachable(err)
		return
	}
	listed, err := g.ListTracingPolicies(callCtx)
	if err != nil {
		c.unreachable(err)
		return
	}
	c.noteAgent(agent)
	c.detectOverrides(listed, agent)
	for _, name := range sortedKeys(c.recorded) {
		// A recorded name Tetragon no longer has (it restarted, or an
		// operator deleted it) is not loaded; the record only lists what is.
		if !hasPolicy(listed, name) {
			c.forgetLoaded(name)
		}
	}
	for _, lp := range listed {
		if IsDefenseClawName(lp.Name) && !c.recorded[lp.Name] && len(c.st.Warnings) < 64 {
			c.st.Warnings = addUnique(c.st.Warnings, WarnForeignName+":"+lp.Name)
		}
	}

	plan := MakePlan(PlanInput{
		Intent:     intent,
		Agent:      agent,
		Paused:     pause.Active(),
		Overrides:  c.st.Overrides,
		Enrollment: c.enrollment,
		Ready: func(uid int) bool {
			c.tallyMu.Lock()
			defer c.tallyMu.Unlock()
			return c.burn.Ready(uid, intent.BurnIn)
		},
	})
	if stale := contains(plan.Warnings, WarnEnforceAckStale); stale && !c.lastStale {
		c.change(Change{Event: EventAckStale, Reason: "enforce_ack does not match " + Digest()})
		c.lastStale = stale
	} else if !stale {
		c.lastStale = false
	}
	compiled, err := Compile(Input{
		Enrollment: c.enrollment, Installs: c.installs, Roots: c.roots.Roots, FS: c.cfg.FS,
		Observe: plan.Observe, Connect: plan.Connect, Controls: plan.Controls, Burnin: plan.Burnin,
		BurninDeleted: c.st.Overrides[FamilyBurnin].Kind == OverrideDeleted,
	})
	if err != nil {
		c.cfg.Logger.Error("kernel policy did not compile", "error", err)
		c.failSafe(callCtx, g, agent)
		c.st.Warnings = addUnique(c.st.Warnings, WarnReconcileFailed)
		c.persist()
		return
	}
	for _, p := range compiled.Policies {
		// Hits are attributed with the index of the policy as compiled now,
		// including policies a restarted helper found already loaded.
		if isControlsFamily(p.Family) {
			c.setIndex(p.Name, p.Paths)
		}
	}
	failed := c.apply(callCtx, g, agent, listed, compiled, plan, pause)
	c.finish(callCtx, g, agent, compiled, plan, failed, trigger)
}

func hasPolicy(list []LoadedPolicy, name string) bool {
	for _, p := range list {
		if p.Name == name {
			return true
		}
	}
	return false
}

func (c *Controller) warn(code string) { c.st.Warnings = addUnique(c.st.Warnings, code) }

func (c *Controller) unreachable(err error) {
	if c.st.Tetragon.Reachable || c.st.Tetragon.Reason == "" {
		c.change(Change{Event: EventFallback, Reason: "tetragon unreachable: " + err.Error()})
	}
	c.st.Tetragon.Reachable = false
	c.st.Tetragon.Reason = err.Error()
	c.st.InSync = false
	c.warn(WarnTetragonUnavailable)
	// What is already loaded keeps running with frozen anchors; nothing can
	// be changed from here, and nothing is guessed.
	c.persist()
	c.cfg.Logger.Warn("tetragon unreachable", "error", err)
}

func (c *Controller) noteAgent(agent Agent) {
	if old := c.st.Tetragon.PID; old != 0 && agent.PID != 0 && old != agent.PID {
		c.change(Change{Event: EventTetragonRestarted, Reason: fmt.Sprintf("pid %d -> %d", old, agent.PID)})
	}
	c.st.Tetragon = TetragonStatus{Reachable: true, Version: agent.Version, PID: agent.PID, SeenAt: c.cfg.Now().UTC()}
	if agent.LSMKnown {
		lsm := agent.LSM
		c.st.Tetragon.LSM = &lsm
	}
	if agent.KeepSensorsOnExitKnown {
		keep := agent.KeepSensorsOnExit
		c.st.Tetragon.KeepSensorsOnExit = &keep
	}
}

func (c *Controller) notePause(pause PauseState) {
	if pause.Active() == c.lastPaused {
		return
	}
	c.lastPaused = pause.Active()
	switch {
	case pause.Pause != nil:
		reason := pause.Pause.Reason
		if !pause.Pause.UntilReboot {
			reason = fmt.Sprintf("until %s %s", pause.Pause.Until.UTC().Format(time.RFC3339), reason)
		}
		c.change(Change{Event: EventPaused, Reason: reason})
	case pause.Invalid != "":
		c.change(Change{Event: EventPaused, Reason: "pause file untrusted: " + pause.Invalid})
	default:
		c.change(Change{Event: EventResumed})
	}
}

// detectOverrides tells the helper's own changes from an operator's.
//
// Every call is recorded in Applied before it is made, so a policy that is
// missing while Tetragon's pid is unchanged was deleted by someone else, and
// a policy that reports monitor where Applied says enforce was moved by
// someone else. The helper then never puts it back: the override lasts until
// the intent (mode or approval) changes. A Tetragon restart is not an
// operator action: its gRPC-added policies are simply gone, and this pass
// re-adds them. A delete outranks an earlier set-mode: an operator who
// deletes the monitor copy a set-mode override left has deleted the family,
// and it stays away too (GAP-0065).
func (c *Controller) detectOverrides(listed []LoadedPolicy, agent Agent) {
	byName := map[string]LoadedPolicy{}
	for _, lp := range listed {
		byName[lp.Name] = lp
	}
	override := func(family Family, kind OverrideKind, policy string) {
		if o, done := c.st.Overrides[family]; done && (o.Kind != OverrideMonitor || kind != OverrideDeleted) {
			return
		}
		if c.st.Overrides == nil {
			c.st.Overrides = map[Family]Override{}
		}
		c.st.Overrides[family] = Override{Kind: kind, At: c.cfg.Now().UTC()}
		c.change(Change{Event: EventOperatorOverride, Policy: policy, Family: family, Reason: string(kind)})
	}
	for _, name := range sortedApplied(c.st.Applied) {
		applied := c.st.Applied[name]
		lp, present := byName[name]
		switch {
		case applied.PID != agent.PID:
			if present {
				applied.PID = agent.PID
				c.st.Applied[name] = applied
			} else {
				delete(c.st.Applied, name)
			}
		case applied.Pending:
			// A call that may not have finished (the helper restarted in the
			// middle of it): nothing can be inferred.
			if present {
				applied.Pending = false
				if isControlsFamily(applied.Family) {
					applied.Mode = PolicyMonitor
					if lp.Mode.Enforcing() {
						applied.Mode = PolicyEnforce
					}
				}
				c.st.Applied[name] = applied
			} else {
				delete(c.st.Applied, name)
			}
		case !present:
			delete(c.st.Applied, name)
			override(applied.Family, OverrideDeleted, name)
		case isControlsFamily(applied.Family) && applied.Mode == PolicyEnforce &&
			(lp.State == StateDisabled || (lp.State == StateEnabled && !lp.Mode.Enforcing())):
			applied.Mode = PolicyMonitor
			c.st.Applied[name] = applied
			override(applied.Family, OverrideMonitor, name)
		}
	}
}

func sortedApplied(m map[string]Applied) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (c *Controller) markApplied(name string, family Family, mode PolicyMode, pid int, pending bool) {
	// A configure keeps the policy loaded, and with it the sessions Tetragon
	// marked since the load.
	loadTicks := c.st.Applied[name].LoadTicks
	c.st.Applied[name] = Applied{Family: family, Mode: mode, PID: pid, At: c.cfg.Now().UTC(), Pending: pending, LoadTicks: loadTicks}
	c.syncTally()
}

// loadTicks is the start time, in clock ticks since boot, of the newest
// process alive right after a load: every agent session that started no
// later than it may predate the load, and Tetragon marks an agent's
// processes for matchBinaries followChildren only when the agent starts, so
// such a session is not denied. 0 when the scan fails (nothing is then
// reported as predating).
func (c *Controller) loadTicks() uint64 {
	procs, err := c.cfg.Procs(c.enrollment.Has)
	if err != nil {
		return 0
	}
	var newest uint64
	for _, p := range procs {
		newest = max(newest, p.StartTicks)
	}
	return newest
}

// configure flips a loaded policy's mode in place. A flip to enforce is
// refused while a pause file exists, checked at the moment of the call.
func (c *Controller) configure(ctx context.Context, g guardedClient, agent Agent, name string, family Family, mode PolicyMode) error {
	if mode == PolicyEnforce && ReadPause(c.cfg.Dirs, c.cfg.Now()).Active() {
		return nil
	}
	c.markApplied(name, family, mode, agent.PID, true)
	c.persist()
	if err := g.ConfigureTracingPolicy(ctx, name, mode); err != nil {
		c.cfg.Logger.Warn("configure tracing policy failed", "policy", name, "mode", mode, "error", err)
		return err
	}
	c.markApplied(name, family, mode, agent.PID, false)
	c.observeMode(name, map[PolicyMode]LoadedMode{PolicyEnforce: LoadedEnforce, PolicyMonitor: LoadedMonitor}[mode])
	c.change(Change{Event: EventModeChanged, Policy: name, Family: family, Mode: mode, State: string(StateEnabled)})
	return nil
}

// load adds one policy. The name is recorded before the call, so a crash in
// the middle of it can never leave a loaded policy the retire step does not
// know; the mode travels in the YAML, so a policy that should monitor is never
// loaded enforcing.
func (c *Controller) load(ctx context.Context, g guardedClient, agent Agent, p Policy) error {
	if p.Mode == PolicyEnforce && ReadPause(c.cfg.Dirs, c.cfg.Now()).Active() {
		monitor, err := p.withMode(PolicyMonitor)
		if err != nil {
			return err
		}
		p = monitor
	}
	if err := c.recordLoaded(p.Name); err != nil {
		return err
	}
	c.markApplied(p.Name, p.Family, p.Mode, agent.PID, true)
	c.setIndex(p.Name, p.Paths)
	c.persist()
	if err := g.AddTracingPolicy(ctx, p.YAML); err != nil {
		// A lost response does not prove Tetragon rejected the Add. Keep the
		// write-ahead name and pending call so the next List can resolve it,
		// and so cleanup can always retire a policy that did load.
		c.cfg.Logger.Warn("add tracing policy failed", "policy", p.Name, "error", err)
		return err
	}
	c.markApplied(p.Name, p.Family, p.Mode, agent.PID, false)
	if isControlsFamily(p.Family) {
		applied := c.st.Applied[p.Name]
		applied.LoadTicks = c.loadTicks()
		c.st.Applied[p.Name] = applied
	}
	writePolicyCopy(c.cfg.Dirs, p.Name, p.YAML)
	mode := p.Mode
	c.change(Change{Event: EventLoaded, Policy: p.Name, Family: p.Family, Mode: mode, State: string(StateEnabled)})
	return nil
}

// remove deletes a recorded policy. The record of the call is dropped first,
// so its disappearance is this helper's own doing.
func (c *Controller) remove(ctx context.Context, g guardedClient, name string, present bool) error {
	family, _ := FamilyOfName(name)
	delete(c.st.Applied, name)
	c.syncTally()
	if present {
		c.persist()
		if err := g.DeleteTracingPolicy(ctx, name); err != nil {
			c.cfg.Logger.Warn("delete tracing policy failed", "policy", name, "error", err)
			return err
		}
	}
	c.forgetLoaded(name)
	c.change(Change{Event: EventRemoved, Policy: name, Family: family})
	return nil
}

// apply makes Tetragon match the plan. Order matters:
//
//	A. demote: every enforcing policy that should not enforce goes to
//	   monitor first (a pause, a missing approval, a mode change);
//	B. add: new names, observe first, controls last; add-before-delete makes
//	   an overlap briefly stricter, never looser;
//	C. promote: a loaded monitor policy that should enforce, unless paused;
//	D. delete: recorded names the plan no longer wants, only if A-C worked.
//
// A failed step leaves enforcing policies in monitor mode (failSafe).
func (c *Controller) apply(ctx context.Context, g guardedClient, agent Agent, listed []LoadedPolicy,
	compiled Compiled, plan Plan, pause PauseState) (failed bool) {
	byName := map[string]LoadedPolicy{}
	for _, lp := range listed {
		byName[lp.Name] = lp
	}
	desired := map[string]Policy{}
	wantEnforce := false
	for _, p := range compiled.Policies {
		desired[p.Name] = p
		if p.Mode == PolicyEnforce {
			wantEnforce = true
		}
	}
	if pause.Active() {
		wantEnforce = false
	}
	now := c.cfg.Now()

	// A. demote.
	for _, name := range sortedLoaded(byName) {
		lp := byName[name]
		if !c.recorded[name] || !lp.Mode.Enforcing() {
			continue
		}
		family, _ := FamilyOfName(name)
		if !isControlsFamily(family) {
			continue
		}
		d, want := desired[name]
		stale := !want
		if wantEnforce && ((want && d.Mode == PolicyEnforce) || stale) {
			continue // stays; a stale policy is replaced below, then deleted
		}
		if err := c.configure(ctx, g, agent, name, family, PolicyMonitor); err != nil {
			failed = true
		}
	}

	// B. add.
	for _, family := range []Family{FamilyObserve, FamilyConnect, FamilyBurnin, FamilyControls} {
		for _, p := range compiled.Policies {
			if p.Family != family {
				continue
			}
			lp, present := byName[p.Name]
			if present && !c.recorded[p.Name] {
				c.warn(WarnForeignName + ":" + p.Name)
				continue
			}
			if present && (lp.State == StateLoadError || lp.State == StateError) {
				if now.Before(c.retryAt[p.Name]) {
					c.warn(WarnPolicyLoadError + ":" + p.Name)
					continue
				}
				c.retryAt[p.Name] = now.Add(c.cfg.Intervals.RetryBackoff)
				if err := c.remove(ctx, g, p.Name, true); err != nil {
					failed = true
					continue
				}
				present = false
			}
			if present {
				continue
			}
			if err := c.load(ctx, g, agent, p); err != nil {
				failed = true
			}
		}
	}

	// C. promote.
	for _, name := range sortedKeys(c.recorded) {
		p, want := desired[name]
		lp, present := byName[name]
		if !want || !present || p.Mode != PolicyEnforce || lp.Mode.Enforcing() || lp.State != StateEnabled {
			continue
		}
		if err := c.configure(ctx, g, agent, name, p.Family, PolicyEnforce); err != nil {
			failed = true
		}
	}

	// D. delete.
	if !failed {
		for _, name := range sortedKeys(c.recorded) {
			if _, want := desired[name]; want {
				continue
			}
			_, present := byName[name]
			if err := c.remove(ctx, g, name, present); err != nil {
				failed = true
			}
		}
	}
	return failed
}

// failSafe moves every enforcing policy the helper loaded to monitor mode.
func (c *Controller) failSafe(ctx context.Context, g guardedClient, agent Agent) {
	listed, err := g.ListTracingPolicies(ctx)
	if err != nil {
		return
	}
	for _, lp := range listed {
		family, _ := FamilyOfName(lp.Name)
		if c.recorded[lp.Name] && isControlsFamily(family) && lp.Mode.Enforcing() {
			_ = c.configure(ctx, g, agent, lp.Name, family, PolicyMonitor)
		}
	}
}

// finish refreshes the published state after a pass.
func (c *Controller) finish(ctx context.Context, g guardedClient, agent Agent, compiled Compiled, plan Plan, failed bool, trigger string) {
	if failed {
		c.failSafe(ctx, g, agent)
		c.warn(WarnReconcileFailed)
		c.change(Change{Event: EventReconcileFailed, Reason: "trigger " + trigger})
	}
	final, err := g.ListTracingPolicies(ctx)
	if err != nil {
		final = nil
	}
	byName := map[string]LoadedPolicy{}
	for _, lp := range final {
		byName[lp.Name] = lp
	}
	desired := map[string]Policy{}
	c.lastPIDs = map[int]bool{}
	c.enabled = map[int]bool{}
	for _, p := range compiled.Policies {
		desired[p.Name] = p
		if !isControlsFamily(p.Family) {
			continue
		}
		for _, pid := range p.PIDs {
			c.lastPIDs[pid] = true
		}
		if lp, ok := byName[p.Name]; ok && lp.State == StateEnabled {
			for _, uid := range p.UIDs {
				c.enabled[uid] = true
			}
		}
	}
	// A recorded policy that is loaded but has no record of a call (the helper
	// died mid-call) is adopted as it stands, so hits are attributed and later
	// changes to it are noticed.
	for name := range c.recorded {
		if lp, ok := byName[name]; ok {
			if _, has := c.st.Applied[name]; !has {
				family, _ := FamilyOfName(name)
				mode := PolicyMonitor
				if lp.Mode.Enforcing() {
					mode = PolicyEnforce
				}
				if !isControlsFamily(family) {
					mode = ""
				}
				c.markApplied(name, family, mode, agent.PID, false)
			}
		}
	}
	previous := map[string]PolicyStatus{}
	for _, s := range c.st.Policies {
		previous[s.Name] = s
	}
	c.st.Policies = nil
	for _, name := range sortedKeys(c.recorded) {
		status := PolicyStatus{Name: name}
		status.Family, _ = FamilyOfName(name)
		if p, ok := desired[name]; ok {
			status.DesiredMode = p.Mode
			if plan.Paused && p.Mode == PolicyEnforce {
				status.DesiredMode = PolicyMonitor // held there by the pause
			}
		}
		if lp, ok := byName[name]; ok {
			status.ObservedMode, status.State, status.Error = lp.Mode, lp.State, lp.Error
			c.observeMode(name, lp.Mode)
			if lp.State == StateLoadError || lp.State == StateError {
				c.warn(WarnPolicyLoadError + ":" + name)
			}
		} else {
			status.Error = "not loaded"
		}
		status.ChangedAt = c.cfg.Now().UTC()
		if old, ok := previous[name]; ok && old.ObservedMode == status.ObservedMode && old.State == status.State &&
			old.DesiredMode == status.DesiredMode {
			status.ChangedAt = old.ChangedAt
		}
		c.st.Policies = append(c.st.Policies, status)
	}

	// Roots and users.
	c.rescanFromPolicies()
	c.st.Roots = RootsStatus{OverLimit: compiled.OverLimit, Observed: append([]Observed(nil), c.roots.Observed...)}
	for _, n := range compiled.Anchored {
		c.st.Roots.Anchored += n
	}
	allowed := func(connector string) bool {
		return (plan.Controls != nil && plan.Controls.allows(connector)) || (plan.Burnin != nil && plan.Burnin.allows(connector))
	}
	notAnchored := map[Observed]int{}
	for _, root := range c.roots.Roots {
		if !allowed(root.Connector) {
			notAnchored[Observed{UID: root.UID, Reason: ReasonGuardrailObserve, Connector: root.Connector}]++
		}
	}
	for key, n := range notAnchored {
		key.Count = n
		c.st.Roots.Observed = append(c.st.Roots.Observed, key)
	}
	if compiled.OverLimit > 0 {
		c.warn(fmt.Sprintf("%s:%d", WarnRootsOverLimit, compiled.OverLimit))
	}
	c.fillUIDs(plan, compiled)
	c.notePredating(compiled)
	for _, note := range compiled.Notes {
		if len(c.st.Warnings) < 64 {
			c.warn(note)
		}
	}
	for _, warning := range plan.Warnings {
		c.warn(warning)
	}
	if plan.Effective == ModeEnforce && len(compiledFamily(compiled, FamilyControls)) == 0 {
		// Approved and measured, but nothing to anchor to: no install and no
		// live session. The controls load when one appears.
		c.warn(WarnEnforceInactive)
	}
	c.st.Effective = string(plan.Effective)
	c.st.InSync = !failed && !(c.cfg.Intent.Mode.LoadsPolicies() && plan.Effective == ModeConsume)
	for _, p := range compiled.Policies {
		lp, ok := byName[p.Name]
		if !ok || lp.State != StateEnabled || (p.Mode == PolicyEnforce && !plan.Paused && !lp.Mode.Enforcing()) {
			c.st.InSync = false
		}
	}
	sort.Strings(c.st.Warnings)
	c.syncTally()
	c.persist()
}

// notePredating reports the native agent sessions of enforced users that
// started before the enforcing controls policy loaded. The binaries anchor
// follows the children of an agent Tetragon saw start; a session that was
// already running when the policy loaded (enforce turned on, or Tetragon
// restarted and the helper loaded it again) is not marked, so it is not
// denied until it restarts, while its user shows as enforcing (GAP-0053).
// Each such session is an observed-only root, and the warning counts them.
func (c *Controller) notePredating(compiled Compiled) {
	var loadTicks uint64
	binaryUID := -1
	for _, status := range c.st.Policies {
		if status.Family != FamilyControls || status.State != StateEnabled || !status.ObservedMode.Enforcing() {
			continue
		}
		for _, p := range compiled.Policies {
			if p.Name == status.Name && p.BinaryUID > 0 {
				loadTicks, binaryUID = c.st.Applied[p.Name].LoadTicks, p.BinaryUID
			}
		}
	}
	if loadTicks == 0 {
		return
	}
	enforced := false
	for _, user := range c.st.UIDs {
		if user.UID == binaryUID && user.State == UIDEnforcing {
			enforced = true
		}
	}
	if !enforced {
		return
	}
	counts := map[Observed]int{}
	total := 0
	for _, root := range c.roots.Roots {
		if root.Native && root.UID == binaryUID && root.StartTicks <= loadTicks {
			counts[Observed{UID: root.UID, Reason: ReasonPredatesControls, Connector: root.Connector}]++
			total++
		}
	}
	keys := make([]Observed, 0, len(counts))
	for key, n := range counts {
		key.Count = n
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Connector < keys[j].Connector })
	c.st.Roots.Observed = append(c.st.Roots.Observed, keys...)
	if total > 0 {
		c.warn(fmt.Sprintf("%s:%d", WarnSessionsPredateControls, total))
	}
}

func compiledFamily(compiled Compiled, family Family) []Policy {
	var out []Policy
	for _, p := range compiled.Policies {
		if p.Family == family {
			out = append(out, p)
		}
	}
	return out
}

// rescanFromPolicies refreshes the live-root count per user against the pids
// the policies anchor.
func (c *Controller) rescanFromPolicies() {
	alive := map[int]int{}
	for _, root := range c.roots.Roots {
		if c.lastPIDs[root.PID] {
			alive[root.UID]++
		}
	}
	c.alive = alive
}

// hasAnchor reports whether uid has a native binary anchor in an enforcing
// control. Numeric PID anchors remain monitor-only because PIDs can be reused.
func (c *Controller) hasAnchor(uid int, plan Plan, compiled Compiled) bool {
	if plan.Controls == nil {
		return false
	}
	for _, policy := range compiled.Policies {
		if policy.Family == FamilyControls && policy.BinaryUID == uid && len(policy.Binaries) > 0 {
			return true
		}
	}
	return false
}

// hasMonitorAnchor reports a ready user's still-active monitor coverage when
// no safe native binary anchor exists for enforcement.
func hasMonitorAnchor(uid int, compiled Compiled) bool {
	if compiled.Anchored[uid] > 0 {
		return true
	}
	for _, policy := range compiled.Policies {
		if policy.Family == FamilyBurnin && policy.BinaryUID == uid && len(policy.Binaries) > 0 {
			return true
		}
	}
	return false
}

// hasNativeAgent reports a native command-line agent binary of uid: an
// install, or a verified live root.
func (c *Controller) hasNativeAgent(uid int) bool {
	for _, install := range c.installs {
		if install.UID == uid && IsCLIConnector(install.Connector) && len(install.Native) > 0 {
			return true
		}
	}
	for _, root := range c.roots.Roots {
		if root.UID == uid && root.Native {
			return true
		}
	}
	return false
}

// fillUIDs publishes each enrolled user's place in the rollout and emits a
// change when it moved.
func (c *Controller) fillUIDs(plan Plan, compiled Compiled) {
	old := map[int]string{}
	for _, u := range c.st.UIDs {
		old[u.UID] = u.State
	}
	notEnforcing := c.controlsNotEnforcing()
	c.tallyMu.Lock()
	defer c.tallyMu.Unlock()
	c.st.UIDs = nil
	for _, uid := range c.enrollment.UIDs() {
		status, ok := plan.UIDs[uid]
		if !ok {
			status = UIDStatus{UID: uid, User: c.enrollment.UserOf(uid), Connectors: c.enrollment.Connectors(uid),
				State: UIDMonitor, Reason: "mode " + string(plan.Effective)}
		}
		status.AnchoredRoots = c.alive[uid]
		if status.State == UIDEnforcing && !c.hasAnchor(uid, plan, compiled) {
			// Ready, but the enforcing policy cannot deny for this user: it
			// stays measured in monitor mode, and the reason names which
			// limit applies. A native install means another user holds the
			// controls policy's one binary uid; otherwise the agent is matched
			// only by a pid, which may be reused and so never denies.
			switch {
			case !hasMonitorAnchor(uid, compiled):
				status.State, status.Reason = UIDInactive, ReasonNoAnchors
			case c.hasNativeAgent(uid):
				status.State, status.Reason = UIDMonitor, WarnBinaryScopeLimited
			default:
				status.State, status.Reason = UIDMonitor, WarnPIDMonitorOnly
			}
		}
		if status.State == UIDEnforcing && notEnforcing != "" {
			// The plan enforces this user, but Tetragon holds no controls
			// policy enabled in enforce mode: it failed to load, or no pass
			// applied it yet. Nothing is denied, so the user is not called
			// enforcing (GAP-0042).
			status.State, status.Reason = UIDMonitor, notEnforcing
		}
		status.CoveredSeconds = int64(c.burn.Covered(uid) / time.Second)
		status.NeededSeconds = int64(c.cfg.Intent.BurnIn / time.Second)
		status.WouldBlock = c.burn.Hits(uid)
		c.st.UIDs = append(c.st.UIDs, status)
		uid := uid
		progress := Change{UID: &uid, CoveredSeconds: status.CoveredSeconds, NeededSeconds: status.NeededSeconds}
		if prev, had := old[uid]; had && prev != status.State {
			switch {
			case status.State == UIDEnforcing:
				progress.Event, progress.State = EventUIDReady, status.State
				c.change(progress)
			case prev == UIDEnforcing:
				progress.Event, progress.State, progress.Reason = EventUIDBurnIn, status.State, status.Reason
				c.change(progress)
			}
		}
		c.noteProgress(uid, status, progress)
	}
}

// controlsNotEnforcing is why no controls policy denies after this pass:
// WarnPolicyLoadError when the one this pass wanted failed to load (or is in
// error), WarnPolicyNotApplied when none is enabled in enforce mode; "" when
// one is.
func (c *Controller) controlsNotEnforcing() string {
	why := WarnPolicyNotApplied
	for _, policy := range c.st.Policies {
		if policy.Family != FamilyControls {
			continue
		}
		if policy.State == StateEnabled && policy.ObservedMode.Enforcing() {
			return ""
		}
		if policy.DesiredMode == PolicyEnforce && (policy.State == StateLoadError || policy.State == StateError) {
			why = WarnPolicyLoadError
		}
	}
	return why
}

// noteProgress emits a user's burn-in progress (uid_progress) every
// progressInterval while the user is not ready, so a dashboard can show
// covered and needed hours, and an ETA, without polling the host.
func (c *Controller) noteProgress(uid int, status UIDStatus, progress Change) {
	ready := status.NeededSeconds == 0 || status.CoveredSeconds >= status.NeededSeconds
	if ready || status.State == UIDInactive {
		delete(c.progressAt, uid)
		return
	}
	now := c.cfg.Now()
	if last, ok := c.progressAt[uid]; ok && now.Sub(last) < progressInterval {
		return
	}
	c.progressAt[uid] = now
	progress.Event, progress.State = EventUIDProgress, status.State
	c.change(progress)
}
