// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/sensor/kernelpolicy"
)

// Tetragon on managed Linux, from the lifecycle's side. The sensor helper
// owns everything that talks to Tetragon (internal/sensor/kernelpolicy);
// the lifecycle only
//
//   - renders enterprise.tetragon into the helper's drop-in, the one input
//     the helper reads (it never reads config.yaml);
//   - runs the helper's --tetragon-cleanup on every path that stops a helper
//     for good (uninstall, purge, rollback), before binaries or state go;
//   - reports the caps, the helper's published state and the problems verify
//     fails on;
//   - is the root CLI: `enterprise linux tetragon status|pause|resume`, which
//     reads the helper's state files and writes only the pause file.

// codeKernelPolicyOrphaned names DefenseClaw policies that may still be
// loaded in Tetragon with nothing reconciling them. verify fails on it; an
// uninstall or rollback that could not remove them warns with it.
const codeKernelPolicyOrphaned = "kernel_policy_orphaned"

// codeKernelStateUnreadable says the helper's state files could not be read.
const codeKernelStateUnreadable = "kernel_state_unreadable"

// codeKernelPolicyNotApplied says the sensor helper runs another control set
// or intent than this deployment renders: it did not restart into it.
const codeKernelPolicyNotApplied = "kernel_policy_not_applied"

// codeTetragonTCPAPI is the helper's reason for never dialling a Tetragon
// that serves its API on TCP.
const codeTetragonTCPAPI = "tetragon_tcp_api"

// tetragonInfoPath is the world-readable file Tetragon describes itself in.
const tetragonInfoPath = "/var/run/tetragon/tetragon-info.json"

// guardrailActionMode is the guardrail mode whose hooks block.
const guardrailActionMode = "action"

// tetragonIntent is enterprise.tetragon as the sensor helper's drop-in
// carries it: the mode with the caps config alone decides applied (the OS,
// Plane C), the canonical burn-in and approval, and the enrolled connectors
// that may be anchored for a deny.
type tetragonIntent struct {
	// Written is false for an absent block, or one that spells out the
	// defaults: the helper then runs on its own defaults and no drop-in is
	// rendered.
	Written bool
	// Configured is the mode the administrator wrote (consume when unset);
	// Mode is the one the helper runs, after the caps.
	Configured string
	Mode       string
	// Reason is the status code of a cap that overrides Configured.
	Reason string
	BurnIn string
	// EnforceAck are the approved digests, canonical (nil for none).
	EnforceAck []string
	// CustomerEvents is agent or off.
	CustomerEvents string
	// EnforceConnectors are the enrolled connectors whose effective
	// guardrail mode is action; GuardrailObserve the other enrolled ones.
	// Both are set only in enforce mode.
	EnforceConnectors []string
	GuardrailObserve  []string
}

// tetragonIntentOf reads the intent from a validated config. connectors are
// the enrolled (enabled) connectors.
func tetragonIntentOf(cfg *config.Config, goos string, connectors []string) tetragonIntent {
	if cfg == nil {
		defaults := config.EnterpriseTetragonConfig{}.Effective()
		return tetragonIntent{Configured: config.TetragonModeConsume, Mode: config.TetragonModeConsume,
			BurnIn: defaults.BurnIn, CustomerEvents: defaults.CustomerEvents}
	}
	block := cfg.Enterprise.Tetragon
	effective := block.Effective()
	mode, reason := cfg.TetragonMode(goos)
	intent := tetragonIntent{
		Written: !block.IsDefault(), Configured: effective.Mode, Mode: mode, Reason: reason,
		BurnIn: effective.BurnIn, EnforceAck: effective.EnforceAck, CustomerEvents: effective.CustomerEvents,
	}
	if mode != config.TetragonModeEnforce {
		return intent
	}
	for _, connector := range connectors {
		if cfg.Guardrail.Enabled && strings.EqualFold(strings.TrimSpace(cfg.EffectiveGuardrailModeForConnector(connector)), guardrailActionMode) {
			intent.EnforceConnectors = append(intent.EnforceConnectors, connector)
		} else {
			intent.GuardrailObserve = append(intent.GuardrailObserve, connector)
		}
	}
	sort.Strings(intent.EnforceConnectors)
	sort.Strings(intent.GuardrailObserve)
	return intent
}

// helperMode is the mode the helper runs with this intent: its own default
// when no drop-in is rendered.
func (t tetragonIntent) helperMode() string {
	if !t.Written {
		return string(kernelpolicy.ModeConsume)
	}
	return t.Mode
}

// envTetragonCustomerEvents carries enterprise.tetragon.customer_events to the
// sensor helper, only when it is not the default (agent). The helper's
// kernelpolicy.IntentFromLookup reads it with the other four.
const envTetragonCustomerEvents = "DEFENSECLAW_SENSOR_TETRAGON_CUSTOMER_EVENTS"

// approves reports whether the intent's enforce_ack approves digest.
func (t tetragonIntent) approves(digest string) bool {
	return config.TetragonEnforceAcks(t.EnforceAck).Approves(digest)
}

// ack is enforce_ack as the drop-in carries it: the canonical comma list.
func (t tetragonIntent) ack() string { return strings.Join(t.EnforceAck, ",") }

// dropin renders 30-defenseclaw-tetragon.conf, or nil when the helper's own
// defaults say the same (an absent block, or one that spells out the
// defaults). The header names the control-set digest this build ships, the
// value enforce_ack approves. ENFORCE_ACK is a comma list (one digest, or
// several while a ring upgrade runs two builds); CUSTOMER_EVENTS appears only
// when it is not the default.
func (t tetragonIntent) dropin() []byte {
	if !t.Written {
		return nil
	}
	var b strings.Builder
	b.WriteString("# Written by the DefenseClaw enterprise lifecycle. Do not edit.\n")
	fmt.Fprintf(&b, "# defenseclaw-derived: enterprise.tetragon kernel_policy=%s\n", kernelpolicy.Digest())
	b.WriteString("[Service]\n")
	lines := [][2]string{
		{kernelpolicy.EnvMode, t.Mode},
		{kernelpolicy.EnvBurnIn, t.BurnIn},
		{kernelpolicy.EnvEnforceAck, t.ack()},
		{kernelpolicy.EnvEnforceConnectors, strings.Join(t.EnforceConnectors, ",")},
	}
	if t.CustomerEvents != "" && t.CustomerEvents != config.TetragonCustomerEventsAgent {
		lines = append(lines, [2]string{envTetragonCustomerEvents, t.CustomerEvents})
	}
	for _, line := range lines {
		fmt.Fprintf(&b, "Environment=%s\n", systemdQuote(line[0]+"="+line[1]))
	}
	return []byte(b.String())
}

// sensorDirs are the helper's state and runtime directories on this host.
func (e *Env) sensorDirs() kernelpolicy.Dirs {
	return kernelpolicy.Dirs{State: e.P(kernelpolicy.DefaultStateDir), Run: e.P(kernelpolicy.DefaultRunDir)}
}

// recordedKernelPolicies are the names the helper recorded loading.
func (e *Env) recordedKernelPolicies() ([]string, error) {
	if e.GOOS != "linux" {
		return nil, nil
	}
	return kernelpolicy.Recorded(e.sensorDirs())
}

// kernelPolicyAdvice is how an administrator removes policies by hand.
const kernelPolicyAdvice = "delete each with `tetra tracingpolicy delete <name>`, or run `systemctl restart tetragon`, which drops every policy added over its API"

// retireKernelPolicies runs the installed helper's --tetragon-cleanup: the
// policies it loaded into Tetragon outlive it, so every path that stops it
// for good removes them first, with the binary that loaded them and before
// binaries or state go away. It does nothing (and runs nothing) when the
// helper recorded no policy. What it could not remove stays recorded, so a
// helper installed later retires it, and is reported as a warning: a
// customer Tetragon outage must not fail an uninstall or a rollback.
func (l *lifecycle) retireKernelPolicies(ctx context.Context) []string {
	env, r := l.env, l.result
	if env.GOOS != "linux" {
		return nil
	}
	recorded, err := env.recordedKernelPolicies()
	if err != nil {
		r.AddWarning(codeKernelPolicyOrphaned, "could not read the sensor helper's record of the Tetragon policies it loaded: "+err.Error())
		return nil
	}
	if len(recorded) == 0 {
		return nil
	}
	helper := filepath.Join(env.P(env.Layout.BinDir), binSensorHelper)
	left := func(why string) {
		names, _ := env.recordedKernelPolicies()
		if len(names) == 0 {
			return
		}
		r.AddWarning(codeKernelPolicyOrphaned, fmt.Sprintf("%s; DefenseClaw's Tetragon policies %s may still be loaded with no sensor helper to manage them: %s. Their names stay in %s, so a sensor helper installed later removes them",
			why, strings.Join(names, ", "), kernelPolicyAdvice, filepath.Join(kernelpolicy.DefaultStateDir, "tetragon-loaded")))
	}
	if !exists(helper) {
		left("the sensor helper binary is gone")
		return nil
	}
	if res, err := env.Runner.Run(ctx, helper, "--tetragon-cleanup", "--check"); err != nil || res.ExitCode != 0 {
		left("the installed sensor helper cannot remove Tetragon policies")
		return nil
	}
	res, err := env.Runner.Run(ctx, helper, "--tetragon-cleanup")
	removed := cleanupRemoved(res.Stdout)
	switch {
	case err == nil:
		left("the sensor helper could not remove every policy")
	case res.ExitCode == tetragonCleanupUnreachable:
		left("Tetragon did not answer the sensor helper")
	default:
		left("the sensor helper's Tetragon cleanup failed: " + err.Error())
	}
	return removed
}

// tetragonCleanupUnreachable is --tetragon-cleanup's exit code when Tetragon
// did not answer.
const tetragonCleanupUnreachable = 3

// cleanupRemoved lists the names a --tetragon-cleanup run says it removed.
func cleanupRemoved(stdout []byte) []string {
	var out []string
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	for scanner.Scan() {
		if name, ok := strings.CutPrefix(strings.TrimSpace(scanner.Text()), "removed "); ok && kernelpolicy.IsDefenseClawName(name) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// stopHelperHoldingKernelPolicies stops the sensor helper so the policies it
// recorded can be retired while the rest of the deployment keeps running (the
// rollback of an interrupted transaction puts the files back before it
// touches any service). It stops nothing when no policy is recorded or the
// helper is not running. safe is false when the helper could not be stopped:
// its policies must not be retired under it.
func (l *lifecycle) stopHelperHoldingKernelPolicies(ctx context.Context) (helper Unit, stopped, safe bool) {
	if names, err := l.env.recordedKernelPolicies(); err != nil || len(names) == 0 {
		return Unit{}, false, true
	}
	unit, ok := l.helperUnit()
	if !ok || !l.env.Services.Active(ctx, unit) {
		return unit, false, true
	}
	if err := l.env.Services.Stop(ctx, unit); err != nil {
		return unit, false, false
	}
	return unit, true, true
}

// retireRolledBackKernelPolicies is the rollback's cleanup: the change line
// says the restored helper loads its own policies again.
func (l *lifecycle) retireRolledBackKernelPolicies(ctx context.Context) {
	if removed := l.retireKernelPolicies(ctx); len(removed) > 0 {
		l.result.Changes = append(l.result.Changes, kernelPolicyChange(removed)+"; the restored sensor helper loads its own again if it manages any")
	}
}

// kernelPolicyChange is the change line for the policies a cleanup removed.
func kernelPolicyChange(removed []string) string {
	return "removed DefenseClaw's kernel policies from Tetragon: " + strings.Join(removed, ", ")
}

// removeSensorState removes the helper's state directory with the rest of
// the machine state, unless it still records policies that may be loaded:
// those names are what lets a later helper remove them. Its runtime
// directory goes in either case: the unit keeps it across stops
// (RuntimeDirectoryPreserve, for the until-reboot pause), so with the unit
// gone it would otherwise hold a stale socket and the pause until the next
// reboot, and a reinstall in the same boot would start paused.
func (e *Env) removeSensorState() error {
	if e.GOOS != "linux" {
		return nil
	}
	runErr := os.RemoveAll(e.P(kernelpolicy.DefaultRunDir))
	if names, err := e.recordedKernelPolicies(); err != nil || len(names) > 0 {
		return runErr
	}
	return errors.Join(runErr, os.RemoveAll(e.P(kernelpolicy.DefaultStateDir)))
}

// helperUnit is the sensor helper's unit, if this platform has one.
func (l *lifecycle) helperUnit() (Unit, bool) {
	for _, unit := range l.env.Services.Units() {
		if unit.Kind == "sensor_helper" {
			return unit, true
		}
	}
	return Unit{}, false
}

// helperRunning reports whether the sensor helper is running, or back
// within restartSettle from a planned restart (it exits on purpose when the
// guardian manifest changes).
func (l *lifecycle) helperRunning(ctx context.Context) bool {
	unit, ok := l.helperUnit()
	if !ok {
		return false
	}
	return l.env.Services.Active(ctx, unit) || l.backFromRestart(ctx, unit)
}

// installedTetragonIntent reads enterprise.tetragon from the installed
// config. ok is false when the config does not validate (status reports
// that elsewhere).
func (e *Env) installedTetragonIntent() (tetragonIntent, bool) {
	raw, err := readBounded(e.P(e.Layout.ConfigPath), maxInputBytes)
	if err != nil {
		return tetragonIntent{}, false
	}
	validated, err := e.validateConfig(raw)
	if err != nil {
		return tetragonIntent{}, false
	}
	return validated.Tetragon, true
}

// tetragonFinding is one status warning or verify problem.
type tetragonFinding struct {
	Code    string
	Message string
	Problem bool
}

// tetragonFindings derives the warnings and problems of enterprise.tetragon
// from the intent, the helper's published state and whether the helper runs.
// A customer Tetragon outage is a warning, never a problem; problems are
// only DefenseClaw-owned state: policies that may be loaded with nothing
// reconciling them, or a policy of DefenseClaw's that failed to load.
func tetragonFindings(goos string, intent tetragonIntent, haveIntent bool, state kernelpolicy.State, running bool, host tetragonHost) []tetragonFinding {
	var out []tetragonFinding
	seen := map[string]bool{}
	add := func(problem bool, code, format string, args ...any) {
		if seen[code] {
			return
		}
		seen[code] = true
		out = append(out, tetragonFinding{Code: code, Message: fmt.Sprintf(format, args...), Problem: problem})
	}
	if goos != "linux" {
		if haveIntent && intent.Reason == config.TetragonReasonNotApplicable {
			add(false, config.TetragonReasonNotApplicable, "enterprise.tetragon is set, but Tetragon runs only on Linux; this host ignores the block")
		}
		return out
	}
	digest := kernelpolicy.Digest()
	if haveIntent {
		if intent.Reason == config.TetragonReasonPlaneCOff {
			add(false, config.TetragonReasonPlaneCOff, "enterprise.tetragon.mode is %s, but AI Discovery Plane C is off (ai_discovery.runtime.enabled and enable_host_plane), so the sensor helper runs with Tetragon off: kernel controls whose events nobody records are not loaded", intent.Configured)
		}
		if intent.Mode == config.TetragonModeEnforce {
			switch {
			case len(intent.EnforceAck) == 0:
				add(false, kernelpolicy.WarnEnforceAckMissing, "enterprise.tetragon.mode is enforce, but enforce_ack is empty, so the kernel controls stay in monitor mode; review `enterprise linux tetragon status` and approve with `enforce_ack: %s`", digest)
			case !intent.approves(digest):
				add(false, kernelpolicy.WarnEnforceAckStale, "enforce_ack %s approves another control set than the %s this build ships, so the kernel controls stay in monitor mode; review `enterprise linux tetragon status` and approve the new digest", intent.ack(), digest)
			}
			if intent.BurnIn == "0" {
				add(false, kernelpolicy.WarnBurnInSkipped, "enterprise.tetragon.burn_in is 0: users are enforced without a measured burn-in")
			}
			for _, connector := range intent.GuardrailObserve {
				add(false, kernelpolicy.WarnGuardrailObserve+":"+connector, "the %s guardrail is not in action mode, so its agents are observed, not enforced, by the kernel controls", connector)
			}
		}
	}
	if host.TCP {
		add(false, codeTetragonTCPAPI, "Tetragon serves its API on %s, which any local account can use to load kernel policies; the sensor helper never dials it, so it uses cn_proc and fanotify and refuses observe and enforce. Set Tetragon's server-address to a unix socket", host.Address)
	}
	mode := intent.helperMode()
	loadsPolicies := mode == config.TetragonModeObserve || mode == config.TetragonModeEnforce
	if state.Pause != nil {
		switch {
		case state.Pause.Pause != nil && state.Pause.Pause.UntilReboot:
			add(false, kernelpolicy.WarnEnforcePaused, "kernel enforcement is paused until the next reboot (set by uid %d at %s%s); resume with `enterprise linux tetragon resume`",
				state.Pause.Pause.SetByUID, state.Pause.Pause.SetAt.UTC().Format(time.RFC3339), pauseReason(state.Pause.Pause))
		case state.Pause.Pause != nil:
			add(false, kernelpolicy.WarnEnforcePaused, "kernel enforcement is paused until %s (set by uid %d at %s%s); resume with `enterprise linux tetragon resume`",
				state.Pause.Pause.Until.UTC().Format(time.RFC3339), state.Pause.Pause.SetByUID, state.Pause.Pause.SetAt.UTC().Format(time.RFC3339), pauseReason(state.Pause.Pause))
		default:
			add(false, kernelpolicy.WarnPauseInvalid, "a pause file is present but not trusted or not readable (%s), so kernel enforcement stays paused; remove it with `enterprise linux tetragon resume`", state.Pause.Invalid)
		}
	}
	for _, family := range sortedFamilies(state.Overrides) {
		override := state.Overrides[family]
		add(false, kernelpolicy.WarnOperatorOverride+":"+string(family), "an operator %s the %s policy in Tetragon at %s; the sensor helper does not undo it until enterprise.tetragon.mode or enforce_ack changes",
			overrideVerb(override.Kind), family, override.At.UTC().Format(time.RFC3339))
	}
	updated := !state.UpdatedAt.IsZero()
	if running && updated {
		switch {
		case state.KernelPolicy != "" && state.KernelPolicy != digest:
			add(false, codeKernelPolicyNotApplied, "the sensor helper applies control set %s, but this build ships %s; restart it with `%s` or `systemctl restart defenseclaw-sensor-helper`", state.KernelPolicy, digest, "enterprise linux ensure")
		case haveIntent && state.Intent.Mode != "" && string(state.Intent.Mode) != mode:
			add(false, codeKernelPolicyNotApplied, "the sensor helper runs Tetragon mode %s, but the deployment renders %s; run `enterprise linux ensure` so it restarts with the current drop-in", state.Intent.Mode, mode)
		case loadsPolicies && state.Tetragon.Reachable && !state.InSync:
			add(false, codeKernelPolicyNotApplied, "the sensor helper's last pass did not leave Tetragon with the policies enterprise.tetragon calls for; they stay in or move to monitor mode until a pass succeeds (see `enterprise linux tetragon status`)")
		}
	}
	for _, warning := range state.Warnings {
		code, detail, _ := strings.Cut(warning, ":")
		switch code {
		case kernelpolicy.WarnTetragonUnavailable:
			// The helper names a refused endpoint (tetragon_tcp_api,
			// tetragon_untrusted_endpoint, tetragon_unsupported_version) in
			// its reason; that code is the warning.
			if reasonCode, _, ok := strings.Cut(state.Tetragon.Reason, ":"); ok && strings.HasPrefix(reasonCode, "tetragon_") && reasonCode != code {
				add(false, reasonCode, "%s (sensor helper); Plane C uses cn_proc and fanotify, and no kernel control is enforced", state.Tetragon.Reason)
				continue
			}
			if !loadsPolicies && !host.Installed {
				continue // consume on a host without Tetragon: native Plane C, nothing to say
			}
			add(false, code, "Tetragon is not reachable from the sensor helper (%s); Plane C uses cn_proc and fanotify, and no kernel control is enforced", defaultReason(state.Tetragon.Reason))
		case kernelpolicy.WarnPolicyLoadError:
			if loadsPolicies && running {
				add(true, warning, "DefenseClaw's Tetragon policy %s did not load; see `enterprise linux tetragon status`", detail)
			}
		case kernelpolicy.WarnForeignName:
			add(false, warning, "Tetragon has a policy named %s in DefenseClaw's name pattern that the sensor helper did not load; it is left alone", detail)
		case kernelpolicy.WarnRootsOverLimit:
			add(false, code, "%s live agent processes are over the %d-pid anchor limit, so they are observed, not enforced", detail, kernelpolicy.MaxPIDs)
		case kernelpolicy.WarnConfigInvalid:
			add(false, warning, "the sensor helper ignored a malformed %s in its drop-in and used the safe default; run `enterprise linux repair`", detail)
		case "":
		default:
			if detail != "" {
				add(false, warning, "%s (sensor helper)", warning)
			} else {
				add(false, code, "%s (sensor helper)", tetragonWarningText(code))
			}
		}
	}
	if len(state.Loaded) > 0 {
		names := strings.Join(state.Loaded, ", ")
		switch {
		case !running:
			add(true, codeKernelPolicyOrphaned, "the sensor helper is not running, so DefenseClaw's Tetragon policies %s may be loaded with frozen anchors and nothing reconciling them; start it with `systemctl start defenseclaw-sensor-helper`, or remove them with `%s --tetragon-cleanup`",
				names, filepath.Join("/opt/defenseclaw/bin", binSensorHelper))
		case !loadsPolicies && updated && state.Tetragon.Reachable && !state.Intent.Mode.LoadsPolicies():
			add(true, codeKernelPolicyOrphaned, "enterprise.tetragon.mode is %s, but DefenseClaw's Tetragon policies %s are still recorded as loaded after the sensor helper's retire step; run `%s --tetragon-cleanup`",
				mode, names, filepath.Join("/opt/defenseclaw/bin", binSensorHelper))
		}
	}
	if loadsPolicies && running {
		for _, policy := range state.Policies {
			if policy.State == kernelpolicy.StateLoadError || policy.State == kernelpolicy.StateError {
				add(true, kernelpolicy.WarnPolicyLoadError+":"+policy.Name, "DefenseClaw's Tetragon policy %s is in state %s: %s", policy.Name, policy.State, defaultReason(policy.Error))
			}
		}
	}
	return out
}

func sortedFamilies(overrides map[kernelpolicy.Family]kernelpolicy.Override) []kernelpolicy.Family {
	out := make([]kernelpolicy.Family, 0, len(overrides))
	for family := range overrides {
		out = append(out, family)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func overrideVerb(kind kernelpolicy.OverrideKind) string {
	if kind == kernelpolicy.OverrideDeleted {
		return "deleted"
	}
	return "moved to monitor mode"
}

func pauseReason(p *kernelpolicy.Pause) string {
	if p == nil || p.Reason == "" {
		return ""
	}
	return ": " + p.Reason
}

func defaultReason(reason string) string {
	if strings.TrimSpace(reason) == "" {
		return "no detail"
	}
	return reason
}

// tetragonWarningText says what a helper warning code means.
func tetragonWarningText(code string) string {
	switch code {
	case codeTetragonTCPAPI:
		return "tetragon_tcp_api: Tetragon serves its API on TCP, which any local account can use to load kernel policies; the helper never dials it, so observe and enforce are refused. Set server-address to a unix socket"
	case kernelpolicy.WarnUnsupportedVersion:
		return "tetragon_unsupported_version: this Tetragon release is outside the supported window (observe and enforce need 1.7)"
	case kernelpolicy.WarnPersistentSensors:
		return "tetragon_persistent_sensors: Tetragon runs with keep-sensors-on-exit (or its configuration is unreadable), so enforcement is refused and the controls stay in monitor mode"
	case kernelpolicy.WarnLSMUnavailable:
		return "kernel_lsm_unavailable: Tetragon reports no BPF LSM support, so the controls cannot deny and stay in monitor mode"
	case kernelpolicy.WarnEnforceInactive:
		return "kernel_enforce_inactive: no enrolled agent could be anchored, so no kernel control is loaded for enforcement"
	case kernelpolicy.WarnReconcileFailed:
		return "kernel_reconcile_failed: the last reconcile pass failed; the policies stay in or moved to monitor mode"
	}
	return code
}

// describeTetragon adds enterprise.tetragon's warnings to a status or verify
// result and returns its problems.
func (l *lifecycle) describeTetragon(ctx context.Context) []string {
	env, r := l.env, l.result
	intent, haveIntent := env.installedTetragonIntent()
	var state kernelpolicy.State
	running := false
	if env.GOOS == "linux" {
		var err error
		state, err = kernelpolicy.ReadState(env.sensorDirs())
		if err != nil {
			r.AddWarning(codeKernelStateUnreadable, "could not read the sensor helper's Tetragon state: "+err.Error())
			return nil
		}
		running = l.helperRunning(ctx)
	}
	var problems []string
	for _, finding := range tetragonFindings(env.GOOS, intent, haveIntent, state, running, env.tetragonHost()) {
		switch {
		case finding.Problem:
			problems = append(problems, finding.Code+": "+finding.Message)
		case finding.Code == codeKernelPolicyNotApplied && hasWarningCode(r, finding.Code):
			// describePolicy already compared the gateway's report.
		default:
			r.AddWarning(finding.Code, finding.Message)
		}
	}
	return problems
}

func hasWarningCode(r *enterprisestatus.Result, code string) bool {
	for _, warning := range r.Warnings {
		if warning.Code == code {
			return true
		}
	}
	return false
}

// ---- enterprise linux tetragon status|pause|resume ----

// Tetragon CLI actions.
const (
	TetragonActionStatus = "status"
	TetragonActionPause  = "pause"
	TetragonActionResume = "resume"
)

// TetragonStatusSchemaVersion versions TetragonReport
// (testdata/tetragon_status.schema.json).
const TetragonStatusSchemaVersion = 1

// TetragonOptions are the inputs of `enterprise linux tetragon <action>`.
type TetragonOptions struct {
	Action      string
	For         time.Duration
	UntilReboot bool
	Reason      string
}

// TetragonReport is the result of `enterprise linux tetragon <action>`, and
// with --json its exact output.
type TetragonReport struct {
	SchemaVersion int    `json:"schema_version"`
	Action        string `json:"action"`
	OK            bool   `json:"ok"`
	ExitCode      int    `json:"exit_code"`
	// KernelPolicy is the control-set digest this build ships; ApproveWith
	// the enforce_ack line that approves it.
	KernelPolicy string             `json:"kernel_policy"`
	ApproveWith  string             `json:"approve_with"`
	Intent       TetragonIntentView `json:"intent"`
	Helper       TetragonHelperView `json:"helper"`
	Tetragon     TetragonAgentView  `json:"tetragon"`
	Policies     []TetragonPolicy   `json:"policies"`
	Users        []TetragonUser     `json:"users"`
	Roots        TetragonRoots      `json:"roots"`
	Pause        *TetragonPauseView `json:"pause,omitempty"`
	Overrides    []TetragonOverride `json:"overrides"`
	// Recorded are the names the helper recorded loading; Orphaned those of
	// them that may be loaded with nothing reconciling them; Foreign loaded
	// names in DefenseClaw's pattern that the helper never loaded.
	Recorded []string                   `json:"recorded"`
	Orphaned []string                   `json:"orphaned"`
	Foreign  []string                   `json:"foreign"`
	Changes  []string                   `json:"changes,omitempty"`
	Warnings []enterprisestatus.Message `json:"warnings"`
	Errors   []enterprisestatus.Message `json:"errors"`
}

// TetragonIntentView is enterprise.tetragon as the deployment renders it.
type TetragonIntentView struct {
	// Valid is false when the installed config could not be read or does
	// not validate; the other fields are then the defaults.
	Valid      bool   `json:"valid"`
	Configured string `json:"configured_mode"`
	Mode       string `json:"mode"`
	CapReason  string `json:"cap_reason,omitempty"`
	BurnIn     string `json:"burn_in"`
	// EnforceAck is the approved digests as the drop-in carries them: one,
	// or a comma list while a ring upgrade runs two builds.
	EnforceAck        string   `json:"enforce_ack"`
	CustomerEvents    string   `json:"customer_events"`
	Approval          string   `json:"approval"`
	EnforceConnectors []string `json:"enforce_connectors"`
	GuardrailObserve  []string `json:"guardrail_observe"`
	Dropin            bool     `json:"dropin"`
}

// TetragonHelperView is the sensor helper as its unit and state say.
type TetragonHelperView struct {
	Unit          string `json:"unit"`
	Running       bool   `json:"running"`
	StateUpdated  string `json:"state_updated_at,omitempty"`
	PID           int    `json:"pid,omitempty"`
	Mode          string `json:"mode,omitempty"`
	EffectiveMode string `json:"effective_mode,omitempty"`
	KernelPolicy  string `json:"kernel_policy,omitempty"`
}

// TetragonAgentView is the host's Tetragon: what the helper last saw, and
// what Tetragon's own info file says (the CLI never connects).
type TetragonAgentView struct {
	Installed         bool   `json:"installed"`
	ServerAddress     string `json:"server_address,omitempty"`
	Socket            string `json:"socket"`
	Reachable         bool   `json:"reachable"`
	Version           string `json:"version,omitempty"`
	PID               int    `json:"pid,omitempty"`
	LSM               *bool  `json:"lsm,omitempty"`
	KeepSensorsOnExit *bool  `json:"keep_sensors_on_exit,omitempty"`
	SeenAt            string `json:"seen_at,omitempty"`
	Reason            string `json:"reason,omitempty"`
}

// TetragonPolicy is one DefenseClaw policy as the helper's last pass saw it.
type TetragonPolicy struct {
	Name        string `json:"name"`
	Family      string `json:"family"`
	DesiredMode string `json:"desired_mode,omitempty"`
	Mode        string `json:"mode,omitempty"`
	State       string `json:"state,omitempty"`
	Error       string `json:"error,omitempty"`
	ChangedAt   string `json:"changed_at,omitempty"`
}

// TetragonUser is one enrolled user's place in the rollout.
type TetragonUser struct {
	UID           int            `json:"uid"`
	User          string         `json:"user,omitempty"`
	Connectors    []string       `json:"connectors"`
	State         string         `json:"state"`
	Reason        string         `json:"reason,omitempty"`
	AnchoredRoots int            `json:"anchored_roots"`
	CoveredHours  float64        `json:"covered_hours"`
	NeededHours   float64        `json:"needed_hours"`
	WouldBlock    []TetragonHits `json:"would_block"`
	Blocked       []TetragonHits `json:"blocked"`
}

// TetragonHits are one control's hits for a user, with the top paths and
// binaries.
type TetragonHits struct {
	Control  string          `json:"control"`
	Count    int             `json:"count"`
	First    string          `json:"first,omitempty"`
	Last     string          `json:"last,omitempty"`
	Paths    []TetragonCount `json:"paths"`
	Binaries []TetragonCount `json:"binaries"`
}

// TetragonCount is a value and how often it was seen.
type TetragonCount struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

// TetragonRoots are the live agent processes.
type TetragonRoots struct {
	Anchored     int                `json:"anchored"`
	OverLimit    int                `json:"over_limit"`
	ObservedOnly []TetragonObserved `json:"observed_only"`
}

// TetragonObserved are agent sessions observed but not enforced, and why.
type TetragonObserved struct {
	UID       int    `json:"uid"`
	Reason    string `json:"reason"`
	Identity  string `json:"identity,omitempty"`
	Connector string `json:"connector,omitempty"`
	Count     int    `json:"count"`
}

// TetragonPauseView is the break-glass pause.
type TetragonPauseView struct {
	Until       string `json:"until,omitempty"`
	UntilReboot bool   `json:"until_reboot"`
	SetByUID    int    `json:"set_by_uid"`
	SetAt       string `json:"set_at,omitempty"`
	Reason      string `json:"reason,omitempty"`
	// Invalid says why a pause file present is not trusted; it still
	// counts as a pause.
	Invalid string `json:"invalid,omitempty"`
}

// TetragonOverride is a policy family an operator moved to monitor mode or
// deleted.
type TetragonOverride struct {
	Family string `json:"family"`
	Kind   string `json:"kind"`
	At     string `json:"at,omitempty"`
}

func (rep *TetragonReport) addError(code, message string) {
	rep.Errors = append(rep.Errors, enterprisestatus.Message{Code: code, Message: message})
}

func (rep *TetragonReport) addWarning(code, message string) {
	rep.Warnings = append(rep.Warnings, enterprisestatus.Message{Code: code, Message: message})
}

// tetragonLoginUID is the audit login uid of the caller (who a pause names
// under sudo); replaceable in tests.
var tetragonLoginUID = func() int {
	if data, err := os.ReadFile("/proc/self/loginuid"); err == nil {
		if uid, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 32); err == nil && uid != 4294967295 {
			return int(uid)
		}
	}
	return os.Getuid()
}

// RunTetragon runs `enterprise linux tetragon <action>`.
func RunTetragon(ctx context.Context, env *Env, opts TetragonOptions) *TetragonReport {
	rep := &TetragonReport{
		SchemaVersion: TetragonStatusSchemaVersion, Action: opts.Action,
		KernelPolicy: kernelpolicy.Digest(), ApproveWith: "enforce_ack: " + kernelpolicy.Digest(),
		Policies: []TetragonPolicy{}, Users: []TetragonUser{}, Overrides: []TetragonOverride{},
		Recorded: []string{}, Orphaned: []string{}, Foreign: []string{},
		Roots:    TetragonRoots{ObservedOnly: []TetragonObserved{}},
		Warnings: []enterprisestatus.Message{}, Errors: []enterprisestatus.Message{},
	}
	finish := func(code int) *TetragonReport {
		if code == 0 && len(rep.Errors) > 0 {
			code = enterprisestatus.UnixExitFailure
		}
		rep.ExitCode, rep.OK = code, code == 0
		return rep
	}
	switch {
	case env.GOOS != "linux":
		rep.addError(codeUnsupportedPlatform, "Tetragon is a Linux sensor; `enterprise linux tetragon` runs on Linux hosts")
		return finish(enterprisestatus.UnixExitInvalidArgs)
	case env.Geteuid() != 0:
		rep.addError(codeNotRoot, "run this command as root (sudo or the MDM agent): the sensor helper's state is root-only")
		return finish(enterprisestatus.UnixExitFailure)
	}
	dirs := env.sensorDirs()
	switch opts.Action {
	case TetragonActionStatus:
	case TetragonActionPause:
		if opts.UntilReboot && opts.For != 0 {
			rep.addError(codeInvalidArguments, "--for and --until-reboot cannot be combined")
			return finish(enterprisestatus.UnixExitInvalidArgs)
		}
		pause, err := kernelpolicy.NewPause(env.Now(), opts.For, opts.UntilReboot, tetragonLoginUID(), opts.Reason)
		if err != nil {
			rep.addError(codeInvalidArguments, err.Error())
			return finish(enterprisestatus.UnixExitInvalidArgs)
		}
		if err := kernelpolicy.WritePause(dirs, pause); err != nil {
			rep.addError(codeChange, "write the pause: "+err.Error())
			return finish(enterprisestatus.UnixExitFailure)
		}
		if pause.UntilReboot {
			rep.Changes = append(rep.Changes, "paused kernel enforcement until the next reboot; the sensor helper moves enforcing controls to monitor mode within seconds and keeps them visible")
		} else {
			rep.Changes = append(rep.Changes, "paused kernel enforcement until "+pause.Until.UTC().Format(time.RFC3339)+"; the sensor helper moves enforcing controls to monitor mode within seconds and keeps them visible")
		}
	case TetragonActionResume:
		had := kernelpolicy.ReadPause(dirs, env.Now()).Active()
		if err := kernelpolicy.ClearPause(dirs); err != nil {
			rep.addError(codeChange, "remove the pause: "+err.Error())
			return finish(enterprisestatus.UnixExitFailure)
		}
		if had {
			rep.Changes = append(rep.Changes, "resumed kernel enforcement; the sensor helper re-applies enterprise.tetragon on its next pass")
		} else {
			rep.Changes = append(rep.Changes, "no pause was in force")
		}
	default:
		rep.addError(codeInvalidArguments, fmt.Sprintf("unknown tetragon action %q", opts.Action))
		return finish(enterprisestatus.UnixExitInvalidArgs)
	}
	l := &lifecycle{env: env, opts: Options{Action: ActionStatus}, result: enterprisestatus.New(ActionStatus, "standalone", env.GOOS, env.ProductVersion)}
	state, err := kernelpolicy.ReadState(dirs)
	if err != nil {
		rep.addError(codeKernelStateUnreadable, "read the sensor helper's state: "+err.Error())
		return finish(0)
	}
	intent, haveIntent := env.installedTetragonIntent()
	running := l.helperRunning(ctx)
	host := env.tetragonHost()
	rep.fill(env, intent, haveIntent, state, running, host)
	for _, finding := range tetragonFindings(env.GOOS, intent, haveIntent, state, running, host) {
		if finding.Problem {
			rep.addError(finding.Code, finding.Message)
			if finding.Code == codeKernelPolicyOrphaned {
				rep.Orphaned = append(rep.Orphaned, state.Loaded...)
			}
			continue
		}
		rep.addWarning(finding.Code, finding.Message)
	}
	if !haveIntent {
		rep.addWarning(codeConfig, "the installed config could not be read or does not validate; showing the helper's state against the defaults (run `enterprise linux status`)")
	}
	return finish(0)
}

// fill copies the intent and the helper's state into the report.
func (rep *TetragonReport) fill(env *Env, intent tetragonIntent, haveIntent bool, state kernelpolicy.State, running bool, host tetragonHost) {
	if !haveIntent {
		intent = tetragonIntentOf(nil, env.GOOS, nil)
	}
	rep.Intent = TetragonIntentView{
		Valid: haveIntent, Configured: intent.Configured, Mode: intent.helperMode(), CapReason: intent.Reason,
		BurnIn: intent.BurnIn, EnforceAck: intent.ack(), CustomerEvents: defaultStr(intent.CustomerEvents, config.TetragonCustomerEventsAgent),
		Approval:          approvalOf(intent),
		EnforceConnectors: nonNil(intent.EnforceConnectors), GuardrailObserve: nonNil(intent.GuardrailObserve),
		Dropin: intent.Written,
	}
	rep.Helper = TetragonHelperView{
		Unit: unitSensorHelper, Running: running, PID: state.HelperPID, Mode: string(state.Intent.Mode),
		EffectiveMode: state.Effective, KernelPolicy: state.KernelPolicy, StateUpdated: formatTime(state.UpdatedAt),
	}
	agent := state.Tetragon
	rep.Tetragon = TetragonAgentView{
		Reachable: agent.Reachable, Version: agent.Version, PID: agent.PID, LSM: agent.LSM,
		KeepSensorsOnExit: agent.KeepSensorsOnExit, SeenAt: formatTime(agent.SeenAt), Reason: agent.Reason,
	}
	rep.Tetragon.Installed, rep.Tetragon.ServerAddress, rep.Tetragon.Socket = host.Installed, host.Address, host.Verdict
	for _, policy := range state.Policies {
		rep.Policies = append(rep.Policies, TetragonPolicy{
			Name: policy.Name, Family: string(policy.Family), DesiredMode: string(policy.DesiredMode),
			Mode: string(policy.ObservedMode), State: string(policy.State), Error: policy.Error, ChangedAt: formatTime(policy.ChangedAt),
		})
	}
	sort.Slice(rep.Policies, func(i, j int) bool { return rep.Policies[i].Name < rep.Policies[j].Name })
	for _, user := range state.UIDs {
		view := TetragonUser{
			UID: user.UID, User: user.User, Connectors: nonNil(user.Connectors), State: user.State, Reason: user.Reason,
			AnchoredRoots: user.AnchoredRoots, CoveredHours: hours(user.CoveredSeconds), NeededHours: hours(user.NeededSeconds),
			WouldBlock: []TetragonHits{}, Blocked: []TetragonHits{},
		}
		if record := state.BurnIn.UIDs[strconv.Itoa(user.UID)]; record != nil {
			view.WouldBlock = hitsOf(record.WouldBlock)
			view.Blocked = hitsOf(record.Blocked)
		}
		rep.Users = append(rep.Users, view)
	}
	sort.Slice(rep.Users, func(i, j int) bool { return rep.Users[i].UID < rep.Users[j].UID })
	rep.Roots.Anchored, rep.Roots.OverLimit = state.Roots.Anchored, state.Roots.OverLimit
	for _, observed := range state.Roots.Observed {
		rep.Roots.ObservedOnly = append(rep.Roots.ObservedOnly, TetragonObserved{
			UID: observed.UID, Reason: observed.Reason, Identity: observed.Identity, Connector: observed.Connector, Count: observed.Count,
		})
	}
	if state.Pause != nil {
		view := &TetragonPauseView{Invalid: state.Pause.Invalid}
		if p := state.Pause.Pause; p != nil {
			view.UntilReboot, view.SetByUID, view.SetAt, view.Reason = p.UntilReboot, p.SetByUID, formatTime(p.SetAt), p.Reason
			if !p.UntilReboot {
				view.Until = formatTime(p.Until)
			}
		}
		rep.Pause = view
	}
	for _, family := range sortedFamilies(state.Overrides) {
		override := state.Overrides[family]
		rep.Overrides = append(rep.Overrides, TetragonOverride{Family: string(family), Kind: string(override.Kind), At: formatTime(override.At)})
	}
	rep.Recorded = append(rep.Recorded, state.Loaded...)
	for _, warning := range state.Warnings {
		if name, ok := strings.CutPrefix(warning, kernelpolicy.WarnForeignName+":"); ok {
			rep.Foreign = append(rep.Foreign, name)
		}
	}
	sort.Strings(rep.Foreign)
}

// approvalOf says where the approval stands: not_needed (not enforce),
// missing, stale or approved.
func approvalOf(intent tetragonIntent) string {
	switch {
	case intent.Mode != config.TetragonModeEnforce:
		return "not_needed"
	case len(intent.EnforceAck) == 0:
		return "missing"
	case !intent.approves(kernelpolicy.Digest()):
		return "stale"
	}
	return "approved"
}

func hitsOf(byControl map[string]*kernelpolicy.HitStats) []TetragonHits {
	out := []TetragonHits{}
	for control, stats := range byControl {
		if stats == nil {
			continue
		}
		hits := TetragonHits{Control: control, Count: stats.Count, First: formatTime(stats.First), Last: formatTime(stats.Last),
			Paths: []TetragonCount{}, Binaries: []TetragonCount{}}
		for _, path := range stats.Paths {
			hits.Paths = append(hits.Paths, TetragonCount{Value: path.Value, Count: path.Count})
		}
		for _, binary := range stats.Binaries {
			hits.Binaries = append(hits.Binaries, TetragonCount{Value: binary.Value, Count: binary.Count})
		}
		out = append(out, hits)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Control < out[j].Control })
	return out
}

func hours(seconds int64) float64 {
	return float64(seconds/36) / 100
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return append([]string{}, values...)
}

// tetragonHost is what Tetragon's own info file says about its API.
type tetragonHost struct {
	Installed bool
	// Address is the API address; Verdict the socket check.
	Address, Verdict string
	// TCP is set when the API is served on TCP, which the helper never dials.
	TCP bool
}

// tetragonHost reads Tetragon's info file (never its socket) and says
// whether its API endpoint is one the helper may use: a unix socket whose
// file and directory are root-owned and not world-writable.
func (e *Env) tetragonHost() tetragonHost {
	data, err := readBounded(e.P(tetragonInfoPath), 64<<10)
	if errors.Is(err, os.ErrNotExist) {
		return tetragonHost{Verdict: "not installed (no " + tetragonInfoPath + ")"}
	}
	if err != nil {
		return tetragonHost{Installed: true, Verdict: "unreadable: " + err.Error()}
	}
	var info struct {
		ServerAddress string `json:"server_address"`
	}
	if err := json.Unmarshal(data, &info); err != nil {
		return tetragonHost{Installed: true, Verdict: "unreadable: " + err.Error()}
	}
	host := tetragonHost{Installed: true, Address: strings.TrimSpace(info.ServerAddress)}
	path, ok := strings.CutPrefix(host.Address, "unix://")
	switch {
	case host.Address == "":
		host.Verdict = "unreadable: no server_address"
		return host
	case !ok || !filepath.IsAbs(path):
		host.TCP, host.Verdict = true, "refused: "+codeTetragonTCPAPI+" (the helper never dials a TCP API)"
		return host
	}
	for _, candidate := range []string{path, filepath.Dir(path)} {
		info, err := os.Stat(e.P(candidate))
		if err != nil {
			host.Verdict = "unavailable: " + err.Error()
			return host
		}
		uid, _, err := e.OwnerOf(e.P(candidate))
		if err != nil || uid != 0 || info.Mode().Perm()&0o002 != 0 {
			host.Verdict = "refused: " + candidate + " is not root-owned or is world-writable"
			return host
		}
	}
	host.Verdict = "trusted (root-owned unix socket)"
	return host
}

// WriteTetragonReport prints a report: JSON, or the text summary.
func WriteTetragonReport(w io.Writer, rep *TetragonReport, asJSON bool) error {
	if asJSON {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(rep)
	}
	for _, change := range rep.Changes {
		fmt.Fprintf(w, "✓ %s\n", change)
	}
	if rep.Helper.Unit == "" {
		// The command stopped before it read the helper's state.
		for _, e := range rep.Errors {
			fmt.Fprintf(w, "✗ %s: %s\n", e.Code, e.Message)
		}
		return nil
	}
	fmt.Fprintln(w, "Tetragon (managed Linux)")
	agent := rep.Tetragon
	tetragon := "not installed"
	if agent.Installed {
		tetragon = defaultStr(agent.Version, "version unknown")
		if agent.PID > 0 {
			tetragon += fmt.Sprintf(", pid %d", agent.PID)
		}
		if agent.Reachable {
			tetragon += ", reachable"
		} else {
			tetragon += ", not reachable" + parenthesized(agent.Reason)
		}
		if agent.KeepSensorsOnExit != nil {
			tetragon += fmt.Sprintf(", keep-sensors-on-exit %t", *agent.KeepSensorsOnExit)
		}
		if agent.LSM != nil {
			tetragon += fmt.Sprintf(", BPF LSM %t", *agent.LSM)
		}
	}
	fmt.Fprintf(w, "  Tetragon:       %s\n", tetragon)
	fmt.Fprintf(w, "  API socket:     %s%s\n", agent.Socket, prefixed(" at ", agent.ServerAddress))
	helper := "not running"
	if rep.Helper.Running {
		helper = "running"
	}
	if rep.Helper.StateUpdated != "" {
		helper += ", state updated " + rep.Helper.StateUpdated
	} else {
		helper += ", no state published yet"
	}
	fmt.Fprintf(w, "  Sensor helper:  %s\n", helper)
	mode := rep.Intent.Mode
	if rep.Intent.CapReason != "" {
		mode += fmt.Sprintf(" (configured %s, capped: %s)", rep.Intent.Configured, rep.Intent.CapReason)
	}
	if rep.Helper.EffectiveMode != "" && rep.Helper.EffectiveMode != rep.Intent.Mode {
		mode += ", running as " + rep.Helper.EffectiveMode
	}
	fmt.Fprintf(w, "  Mode:           %s, burn-in %s\n", mode, rep.Intent.BurnIn)
	fmt.Fprintf(w, "  Kernel policy:  %s (approve with `%s`)", rep.KernelPolicy, rep.ApproveWith)
	switch rep.Intent.Approval {
	case "approved":
		fmt.Fprint(w, ", approved")
	case "stale":
		fmt.Fprintf(w, ", enforce_ack %s is stale", rep.Intent.EnforceAck)
	case "missing":
		fmt.Fprint(w, ", not approved yet")
	}
	fmt.Fprintln(w)
	if rep.Helper.KernelPolicy != "" && rep.Helper.KernelPolicy != rep.KernelPolicy {
		fmt.Fprintf(w, "  Helper applies: %s\n", rep.Helper.KernelPolicy)
	}
	if rep.Pause != nil {
		switch {
		case rep.Pause.Invalid != "":
			fmt.Fprintf(w, "  Pause:          in force (untrusted pause file: %s)\n", rep.Pause.Invalid)
		case rep.Pause.UntilReboot:
			fmt.Fprintf(w, "  Pause:          until the next reboot, set by uid %d at %s%s\n", rep.Pause.SetByUID, rep.Pause.SetAt, prefixed(": ", rep.Pause.Reason))
		default:
			fmt.Fprintf(w, "  Pause:          until %s, set by uid %d at %s%s\n", rep.Pause.Until, rep.Pause.SetByUID, rep.Pause.SetAt, prefixed(": ", rep.Pause.Reason))
		}
	}
	for _, override := range rep.Overrides {
		fmt.Fprintf(w, "  Override:       %s %s by an operator at %s\n", override.Family, override.Kind, override.At)
	}
	if len(rep.Policies) > 0 {
		fmt.Fprintln(w, "  Policies:")
		table := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(table, "    NAME\tFAMILY\tMODE\tWANTED\tSTATE\tERROR")
		for _, policy := range rep.Policies {
			fmt.Fprintf(table, "    %s\t%s\t%s\t%s\t%s\t%s\n", policy.Name, policy.Family, defaultStr(policy.Mode, "-"),
				defaultStr(policy.DesiredMode, "-"), defaultStr(policy.State, "-"), defaultStr(policy.Error, "-"))
		}
		_ = table.Flush()
	}
	if len(rep.Users) > 0 {
		fmt.Fprintln(w, "  Users:")
		table := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(table, "    USER\tSTATE\tCONNECTORS\tBURN-IN\tWOULD-BLOCK\tBLOCKED")
		for _, user := range rep.Users {
			name := fmt.Sprintf("uid %d", user.UID)
			if user.User != "" {
				name = fmt.Sprintf("%s (%d)", user.User, user.UID)
			}
			state := user.State
			if user.Reason != "" {
				state += " (" + user.Reason + ")"
			}
			fmt.Fprintf(table, "    %s\t%s\t%s\t%.1fh of %.1fh\t%s\t%s\n", name, state, defaultStr(strings.Join(user.Connectors, ","), "-"),
				user.CoveredHours, user.NeededHours, hitsSummary(user.WouldBlock), hitsSummary(user.Blocked))
		}
		_ = table.Flush()
	}
	if len(rep.Roots.ObservedOnly) > 0 {
		count := 0
		for _, observed := range rep.Roots.ObservedOnly {
			count += observed.Count
		}
		fmt.Fprintf(w, "  Observed, not enforced: %d session(s)\n", count)
		for _, observed := range rep.Roots.ObservedOnly {
			fmt.Fprintf(w, "    uid %d: %d %s%s\n", observed.UID, observed.Count, observed.Reason,
				parenthesized(strings.TrimSpace(observed.Connector+" "+observed.Identity)))
		}
	}
	if rep.Roots.OverLimit > 0 {
		fmt.Fprintf(w, "  Over the pid limit: %d live root(s) observed only\n", rep.Roots.OverLimit)
	}
	for _, warning := range rep.Warnings {
		fmt.Fprintf(w, "  ! %s: %s\n", warning.Code, warning.Message)
	}
	for _, e := range rep.Errors {
		fmt.Fprintf(w, "  ✗ %s: %s\n", e.Code, e.Message)
	}
	return nil
}

func hitsSummary(hits []TetragonHits) string {
	if len(hits) == 0 {
		return "0"
	}
	parts := make([]string, 0, len(hits))
	for _, hit := range hits {
		part := fmt.Sprintf("%s %d", strings.TrimPrefix(hit.Control, "kernel."), hit.Count)
		if len(hit.Paths) > 0 {
			part += " " + hit.Paths[0].Value
		}
		if len(hit.Binaries) > 0 {
			part += " by " + hit.Binaries[0].Value
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, "; ")
}

func defaultStr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func parenthesized(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return " (" + value + ")"
}

func prefixed(prefix, value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return prefix + value
}
