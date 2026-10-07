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
	"os/user"
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

// The warning and problem codes and their words are in tetragon_codes.go.

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
	// Both are set only in enforce mode (the drop-in carries them).
	EnforceConnectors []string
	GuardrailObserve  []string
	// MachinePolicy are the enrolled command-line connectors on vendor
	// machine policy that the enumerator gives no per-user rows
	// (enrollment.unenrolled_users is not deny, enrollment.mode is not
	// manifest): the helper enrolls them for every eligible account. Set only
	// in observe and enforce, the modes that anchor agents.
	MachinePolicy []string
	// ActionCLI and ObserveCLI split the enrolled command-line connectors
	// (the only ones a kernel control can anchor) by guardrail mode in every
	// mode, for the readiness checks of a mode the host does not run yet.
	ActionCLI, ObserveCLI []string
	// PlaneC is whether AI Discovery Plane C runs.
	PlaneC bool
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
		PlaneC: cfg.PlaneCSelected(),
	}
	var action, observe []string
	for _, connector := range connectors {
		if cfg.Guardrail.Enabled && strings.EqualFold(strings.TrimSpace(cfg.EffectiveGuardrailModeForConnector(connector)), guardrailActionMode) {
			action = append(action, connector)
		} else {
			observe = append(observe, connector)
		}
	}
	sort.Strings(action)
	sort.Strings(observe)
	for _, connector := range action {
		if kernelpolicy.IsCLIConnector(connector) {
			intent.ActionCLI = append(intent.ActionCLI, connector)
		}
	}
	for _, connector := range observe {
		if kernelpolicy.IsCLIConnector(connector) {
			intent.ObserveCLI = append(intent.ObserveCLI, connector)
		}
	}
	if mode == config.TetragonModeEnforce {
		intent.EnforceConnectors, intent.GuardrailObserve = action, observe
	}
	if mode == config.TetragonModeObserve || mode == config.TetragonModeEnforce {
		intent.MachinePolicy = machinePolicyAnchors(cfg, goos, connectors)
	}
	return intent
}

// machinePolicyAnchors are the enrolled command-line connectors whose hooks
// reach every eligible account through vendor machine policy, while the
// enumerator writes no per-user rows for them: the same rule as the
// enumerator's (enterprisehooks.EnumerateUnix), from the same config.
func machinePolicyAnchors(cfg *config.Config, goos string, connectors []string) []string {
	enrollment := cfg.Enterprise.Enrollment
	if strings.EqualFold(strings.TrimSpace(enrollment.UnenrolledUsers), config.EnterpriseUnenrolledDeny) ||
		strings.EqualFold(strings.TrimSpace(enrollment.Mode), config.EnterpriseEnrollmentManifest) {
		return nil
	}
	var owned []string
	for _, connector := range connectors {
		if cfg.Enterprise.MachinePolicy.PolicyFor(connector).Ownership != config.MachinePolicyOwnershipOff {
			owned = append(owned, connector)
		}
	}
	var out []string
	for _, connector := range MachinePolicyConnectors(goos, owned) {
		if kernelpolicy.IsCLIConnector(connector) {
			out = append(out, connector)
		}
	}
	return out
}

// helperMode is the mode the helper runs with this intent: its own default
// when no drop-in is rendered.
func (t tetragonIntent) helperMode() string {
	if !t.Written {
		return string(kernelpolicy.ModeConsume)
	}
	return t.Mode
}

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
// when it is not the default, MACHINE_POLICY_CONNECTORS only when it names
// one.
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
		lines = append(lines, [2]string{kernelpolicy.EnvCustomerEvents, t.CustomerEvents})
	}
	if len(t.MachinePolicy) > 0 {
		lines = append(lines, [2]string{kernelpolicy.EnvMachinePolicyConnectors, strings.Join(t.MachinePolicy, ",")})
	}
	for _, line := range lines {
		fmt.Fprintf(&b, "Environment=%s\n", systemdQuote(line[0]+"="+line[1]))
	}
	return []byte(b.String())
}

// noteTetragonRestart says, when a run rewrote or removed the helper's
// Tetragon drop-in, that the sensor helper restarted into the new mode: the
// one thing an administrator pushing enterprise.tetragon wants to read back.
func (l *lifecycle) noteTetragonRestart(ctx context.Context, p *plan, changed map[string]bool) {
	if l.env.GOOS != "linux" || p == nil || p.config == nil || !changed[filepath.Join("/etc/systemd/system", unitSensorHelper+".d", dropinTetragon)] {
		return
	}
	if unit, ok := l.helperUnit(); ok && l.env.Services.Active(ctx, unit) {
		l.noteChange("the sensor helper restarted into enterprise.tetragon mode %s", p.config.Tetragon.helperMode())
	}
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
		r.AddWarning(codeKernelPolicyOrphaned, tetragonMessage(codeKernelPolicyOrphaned, tetragonFacts{Variant: variantUnreadable, Error: err.Error()}))
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
		r.AddWarning(codeKernelPolicyOrphaned, tetragonMessage(codeKernelPolicyOrphaned, tetragonFacts{Variant: variantLeft, Why: why, Names: names}))
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

// perInstanceCodes keep their ":detail" suffix as part of the code: one
// warning per connector, family, policy or variable.
var perInstanceCodes = map[string]bool{
	kernelpolicy.WarnForeignName:      true,
	kernelpolicy.WarnConfigInvalid:    true,
	kernelpolicy.WarnGuardrailObserve: true,
	kernelpolicy.WarnOperatorOverride: true,
	kernelpolicy.WarnPolicyLoadError:  true,
	codeCustomerEventsCapped:          true,
}

// tetragonFindings derives the warnings and problems of enterprise.tetragon
// from the intent, the helper's published state and whether the helper runs.
// A customer Tetragon outage is a warning, never a problem; problems are
// only DefenseClaw-owned state: policies that may be loaded with nothing
// reconciling them, or a policy of DefenseClaw's that failed to load. The
// words come from the code table (tetragon_codes.go).
func tetragonFindings(in tetragonInputs) []tetragonFinding {
	goos, intent, haveIntent, state, running, host := in.GOOS, in.Intent, in.HaveIntent, in.State, in.Running, in.Host
	var out []tetragonFinding
	seen := map[string]bool{}
	add := func(problem bool, code string, facts tetragonFacts) {
		if seen[code] {
			return
		}
		seen[code] = true
		out = append(out, tetragonFinding{Code: code, Message: tetragonMessage(code, facts), Problem: problem})
	}
	if goos != "linux" {
		if haveIntent && intent.Reason == config.TetragonReasonNotApplicable {
			add(false, config.TetragonReasonNotApplicable, tetragonFacts{})
		}
		return out
	}
	digest := kernelpolicy.Digest()
	if haveIntent {
		if intent.Reason == config.TetragonReasonPlaneCOff {
			add(false, config.TetragonReasonPlaneCOff, tetragonFacts{Mode: intent.Configured})
		}
		if intent.Mode == config.TetragonModeEnforce {
			switch {
			case len(intent.EnforceAck) == 0:
				add(false, kernelpolicy.WarnEnforceAckMissing, tetragonFacts{Digest: digest})
			case !intent.approves(digest):
				add(false, kernelpolicy.WarnEnforceAckStale, tetragonFacts{Digest: digest, Ack: intent.ack()})
			}
			if intent.BurnIn == "0" {
				add(false, kernelpolicy.WarnBurnInSkipped, tetragonFacts{})
			}
			for _, connector := range intent.GuardrailObserve {
				add(false, kernelpolicy.WarnGuardrailObserve+":"+connector, tetragonFacts{})
			}
		}
	}
	if host.TCP {
		add(false, codeTetragonTCPAPI, tetragonFacts{Address: host.Address})
	}
	mode := intent.helperMode()
	loadsPolicies := mode == config.TetragonModeObserve || mode == config.TetragonModeEnforce
	if state.Pause != nil {
		if p := state.Pause.Pause; p != nil {
			add(false, kernelpolicy.WarnEnforcePaused, tetragonFacts{Pause: p, SetBy: userLabel(p.SetByUID)})
		} else {
			add(false, kernelpolicy.WarnPauseInvalid, tetragonFacts{PauseInvalid: state.Pause.Invalid})
		}
	}
	for _, family := range sortedFamilies(state.Overrides) {
		override := state.Overrides[family]
		add(false, kernelpolicy.WarnOperatorOverride+":"+string(family), tetragonFacts{Verb: overrideVerb(override.Kind), At: override.At})
	}
	updated := !state.UpdatedAt.IsZero()
	if running && updated {
		switch {
		case state.KernelPolicy != "" && state.KernelPolicy != digest:
			add(false, codeKernelPolicyNotApplied, tetragonFacts{Variant: variantDigest, Applied: state.KernelPolicy, Digest: digest})
		case haveIntent && state.Intent.Mode != "" && string(state.Intent.Mode) != mode:
			add(false, codeKernelPolicyNotApplied, tetragonFacts{Variant: variantMode, Applied: string(state.Intent.Mode), Mode: mode})
		case loadsPolicies && state.Tetragon.Reachable && !state.InSync:
			add(false, codeKernelPolicyNotApplied, tetragonFacts{Variant: variantNotInSync})
		}
	}
	for _, warning := range state.Warnings {
		code, detail, _ := strings.Cut(warning, ":")
		detail = strings.TrimSpace(detail)
		switch {
		case code == kernelpolicy.WarnTetragonUnavailable:
			// The helper names a refused endpoint (tetragon_tcp_api,
			// tetragon_untrusted_endpoint, tetragon_unsupported_version) in
			// its reason; that code is the warning.
			if reasonCode, reasonDetail, ok := strings.Cut(state.Tetragon.Reason, ":"); ok && strings.HasPrefix(reasonCode, "tetragon_") && reasonCode != code {
				add(false, reasonCode, refusedEndpointFacts(reasonCode, strings.TrimSpace(reasonDetail), state, host, mode))
				continue
			}
			if !loadsPolicies && !host.Installed {
				continue // consume on a host without Tetragon: native Plane C, nothing to say
			}
			add(false, code, tetragonFacts{Detail: strings.TrimSpace(state.Tetragon.Reason)})
		case code == kernelpolicy.WarnPolicyLoadError:
			if loadsPolicies && running {
				add(true, warning, tetragonFacts{})
			}
		case code == kernelpolicy.WarnEnforceInactive:
			add(false, code, inactiveFacts(detail, in))
		case code == kernelpolicy.WarnUnsupportedVersion:
			add(false, code, tetragonFacts{Version: state.Tetragon.Version, Mode: mode})
		case code == "":
		case perInstanceCodes[code]:
			add(false, warning, tetragonFacts{Count: cappedLastHour(state, detail)})
		default:
			add(false, code, tetragonFacts{Detail: detail, Digest: digest, Ack: intent.ack()})
		}
	}
	if len(state.Loaded) > 0 {
		switch {
		case !running:
			add(true, codeKernelPolicyOrphaned, tetragonFacts{Variant: variantNotRunning, Names: state.Loaded})
		case !loadsPolicies && updated && state.Tetragon.Reachable && !state.Intent.Mode.LoadsPolicies():
			add(true, codeKernelPolicyOrphaned, tetragonFacts{Variant: variantRetired, Mode: mode, Names: state.Loaded})
		}
	}
	if loadsPolicies && running {
		for _, policy := range state.Policies {
			if policy.State == kernelpolicy.StateLoadError || policy.State == kernelpolicy.StateError {
				add(true, kernelpolicy.WarnPolicyLoadError+":"+policy.Name, tetragonFacts{Variant: variantState, State: string(policy.State), Error: policy.Error})
			}
		}
	}
	return out
}

// refusedEndpointFacts are the facts of an endpoint the helper refused, with
// what the CLI's own look at Tetragon's info file adds.
func refusedEndpointFacts(code, detail string, state kernelpolicy.State, host tetragonHost, mode string) tetragonFacts {
	facts := tetragonFacts{Detail: detail, Mode: mode}
	switch code {
	case codeTetragonTCPAPI:
		facts.Address = defaultStr(host.Address, detail)
	case codeTetragonUntrusted:
		facts.Path, facts.Owner, facts.Perm = host.UntrustedPath, host.UntrustedOwner, host.UntrustedPerm
	case kernelpolicy.WarnUnsupportedVersion:
		facts.Variant, facts.Version = variantFallback, defaultStr(state.Tetragon.Version, detail)
	}
	return facts
}

// inactiveFacts say why no control can be enforced: no anchor at all (the
// users without an agent, and enrolled connectors no user has a row for), or
// no user that finished burn-in yet (and when the next one is ready).
func inactiveFacts(detail string, in tetragonInputs) tetragonFacts {
	intent, state := in.Intent, in.State
	if strings.Contains(detail, "burn-in") {
		facts := tetragonFacts{Variant: variantNoReadyUser}
		if eta, ok := nextReady(in, state.UpdatedAt); ok {
			facts.ETA = humanDuration(eta)
		}
		return facts
	}
	facts := tetragonFacts{Variant: variantNoAnchors}
	rows := map[string]bool{}
	for _, user := range state.UIDs {
		for _, connector := range user.Connectors {
			rows[connector] = true
		}
		if user.State == kernelpolicy.UIDInactive && user.Reason == kernelpolicy.ReasonNoAnchors {
			facts.Users = append(facts.Users, userName(user))
		}
	}
	for _, connector := range append(append([]string{}, intent.EnforceConnectors...), intent.GuardrailObserve...) {
		if !rows[connector] {
			facts.Connectors = append(facts.Connectors, connector)
		}
	}
	sort.Strings(facts.Connectors)
	return facts
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
			r.AddWarning(codeKernelStateUnreadable, tetragonMessage(codeKernelStateUnreadable, tetragonFacts{Error: err.Error()}))
			return nil
		}
		running = l.helperRunning(ctx)
	}
	var problems []string
	in := tetragonInputs{GOOS: env.GOOS, Intent: intent, HaveIntent: haveIntent, State: state, Running: running, Host: env.tetragonHost()}
	for _, finding := range tetragonFindings(in) {
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
	// User narrows status to one enrolled user, by name or uid.
	User string
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
	Recorded []string `json:"recorded"`
	Orphaned []string `json:"orphaned"`
	Foreign  []string `json:"foreign"`
	// CustomerPolicies are your own Tetragon policies: DefenseClaw reads
	// their events and never changes them.
	CustomerPolicies []TetragonCustomerPolicy   `json:"customer_policies"`
	Changes          []string                   `json:"changes,omitempty"`
	Warnings         []enterprisestatus.Message `json:"warnings"`
	Errors           []enterprisestatus.Message `json:"errors"`

	// progress is each user's burn-in and next the Next: footer, for the
	// text view only.
	progress map[int]burnInProgress
	next     []string
}

// TetragonCustomerPolicy is one of the customer's own Tetragon policies as
// the sensor helper last listed it.
type TetragonCustomerPolicy struct {
	Name  string `json:"name"`
	Mode  string `json:"mode,omitempty"`
	State string `json:"state,omitempty"`
	Error string `json:"error,omitempty"`
	// Events, Forwarded and Dropped count what the helper saw of the
	// policy, forwarded to the gateway (which records those below an AI
	// agent) and did not forward (DefenseClaw's own processes, over the
	// budget, or customer_events off); Blocked counts its events that say
	// Tetragon denied the call or killed the process, the same outcome the
	// forwarded records carry.
	Events    uint64 `json:"events"`
	Forwarded uint64 `json:"forwarded"`
	Dropped   uint64 `json:"dropped"`
	Blocked   uint64 `json:"blocked"`
	LastEvent string `json:"last_event_at,omitempty"`
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
	// MachinePolicyConnectors are the connectors the helper enrolls for
	// every eligible account (vendor machine policy, no targets.yaml row).
	MachinePolicyConnectors []string `json:"machine_policy_connectors"`
	Dropin                  bool     `json:"dropin"`
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
	UID        int      `json:"uid"`
	User       string   `json:"user,omitempty"`
	Connectors []string `json:"connectors"`
	// MachinePolicy are the connectors of Connectors the user is enrolled
	// for through vendor machine policy (an eligible account, no row in
	// targets.yaml).
	MachinePolicy []string       `json:"machine_policy"`
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
		Recorded: []string{}, Orphaned: []string{}, Foreign: []string{}, CustomerPolicies: []TetragonCustomerPolicy{},
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
		rep.addError(codeUnsupportedPlatform, "Tetragon is a Linux sensor; enterprise linux tetragon runs on Linux hosts only")
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
		until := "until the next reboot"
		if !pause.UntilReboot {
			until = "until " + pause.Until.UTC().Format(time.RFC3339)
		}
		rep.Changes = append(rep.Changes, "paused kernel enforcement for every user on this host "+until+
			"; the sensor helper moves enforcing controls to monitor mode within seconds and keeps them visible")
	case TetragonActionResume:
		had := kernelpolicy.ReadPause(dirs, env.Now()).Active()
		if err := kernelpolicy.ClearPause(dirs); err != nil {
			rep.addError(codeChange, "remove the pause: "+err.Error())
			return finish(enterprisestatus.UnixExitFailure)
		}
		if had {
			rep.Changes = append(rep.Changes, "resumed kernel enforcement for every user on this host; the sensor helper re-applies enterprise.tetragon on its next pass")
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
		rep.addError(codeKernelStateUnreadable, tetragonMessage(codeKernelStateUnreadable, tetragonFacts{Error: err.Error()}))
		return finish(0)
	}
	intent, haveIntent := env.installedTetragonIntent()
	running := l.helperRunning(ctx)
	host := env.tetragonHost()
	rep.fill(env, intent, haveIntent, state, running, host)
	rep.fillCustomer(state)
	in := tetragonInputs{GOOS: env.GOOS, Intent: intent, HaveIntent: haveIntent, State: state, Running: running, Host: host}
	if !haveIntent {
		in.Intent = tetragonIntentOf(nil, env.GOOS, nil)
	}
	now := env.Now()
	rep.progress = map[int]burnInProgress{}
	for _, user := range state.UIDs {
		rep.progress[user.UID] = progressFor(user, state.BurnIn.UIDs[strconv.Itoa(user.UID)], in, now)
	}
	if opts.Action == TetragonActionStatus {
		rep.next = statusNext(in, env.tetragonProbes(ctx), now)
		if opts.User != "" && !rep.onlyUser(opts.User) {
			rep.addError(codeInvalidArguments, "--user "+opts.User+" matches no enrolled user on this host"+parenthesized(enrolledNames(rep.Users)))
			return finish(enterprisestatus.UnixExitInvalidArgs)
		}
	}
	for _, finding := range tetragonFindings(in) {
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
		rep.addWarning(codeConfig, "the installed config could not be read or does not validate (this shows the helper's state against the defaults); see "+
			literal(adminCommand("enterprise", "linux", "status")))
	}
	return finish(0)
}

// fill copies the intent and the helper's state into the report.
func (rep *TetragonReport) fill(env *Env, intent tetragonIntent, haveIntent bool, state kernelpolicy.State, running bool, host tetragonHost) {
	if !haveIntent {
		intent = tetragonIntentOf(nil, env.GOOS, nil)
	}
	if rep.CustomerPolicies == nil {
		rep.CustomerPolicies = []TetragonCustomerPolicy{}
	}
	rep.Intent = TetragonIntentView{
		Valid: haveIntent, Configured: intent.Configured, Mode: intent.helperMode(), CapReason: intent.Reason,
		BurnIn: intent.BurnIn, EnforceAck: intent.ack(), CustomerEvents: defaultStr(intent.CustomerEvents, config.TetragonCustomerEventsAgent),
		Approval:          approvalOf(intent),
		EnforceConnectors: nonNil(intent.EnforceConnectors), GuardrailObserve: nonNil(intent.GuardrailObserve),
		MachinePolicyConnectors: nonNil(intent.MachinePolicy), Dropin: intent.Written,
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
			UID: user.UID, User: user.User, Connectors: nonNil(user.Connectors), MachinePolicy: nonNil(user.MachinePolicy),
			State: user.State, Reason: user.Reason,
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

// tetragonInputs are what the findings and the readiness checks read: the
// intent the deployment renders, the helper's published state (customer
// policies included), whether the helper runs, and Tetragon's info file.
type tetragonInputs struct {
	GOOS       string
	Intent     tetragonIntent
	HaveIntent bool
	State      kernelpolicy.State
	Running    bool
	Host       tetragonHost
}

// maxCustomerPolicies bounds the customer policies the CLI shows.
const maxCustomerPolicies = 64

// customerPolicies are the customer's own Tetragon policies the helper
// published in tetragon-state.json (item 1; the helper never changes them),
// by name, at most maxCustomerPolicies.
func customerPolicies(state kernelpolicy.State) []kernelpolicy.CustomerPolicy {
	policies := append([]kernelpolicy.CustomerPolicy(nil), state.CustomerPolicies...)
	sort.Slice(policies, func(i, j int) bool { return policies[i].Name < policies[j].Name })
	if len(policies) > maxCustomerPolicies {
		policies = policies[:maxCustomerPolicies]
	}
	return policies
}

// cappedLastHour is how many events of the customer policy name the helper
// did not forward in the last hour (over the budget).
func cappedLastHour(state kernelpolicy.State, name string) int {
	for _, policy := range state.CustomerPolicies {
		if policy.Name == name {
			return int(policy.CappedLastHour)
		}
	}
	return 0
}

// tetragonAccount resolves a uid to its account name and home directory
// through NSS; both are "" when the uid is unknown. Replaceable in tests.
var tetragonAccount = func(uid int) (name, home string) {
	account, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return "", ""
	}
	return account.Username, account.HomeDir
}

// userLabel is "alice (uid 1001)", or "uid 1001" for an unknown uid.
func userLabel(uid int) string {
	if name, _ := tetragonAccount(uid); name != "" {
		return fmt.Sprintf("%s (uid %d)", name, uid)
	}
	return fmt.Sprintf("uid %d", uid)
}

// userName labels an enrolled user, preferring the name the helper's
// enrollment carries.
func userName(user kernelpolicy.UIDStatus) string {
	if user.User != "" {
		return fmt.Sprintf("%s (uid %d)", user.User, user.UID)
	}
	return userLabel(user.UID)
}

// homeRelative shows a path under the user's home as ~/...: the root view
// names the user's own files on this host, and nothing leaves the host.
func homeRelative(path string, uid int) string {
	_, home := tetragonAccount(uid)
	home = strings.TrimSuffix(home, "/")
	if home != "" && strings.HasPrefix(path, home+"/") {
		return "~/" + strings.TrimPrefix(path, home+"/")
	}
	return path
}

// tetragonHost is what Tetragon's own info file says about its API.
type tetragonHost struct {
	Installed bool
	// Address is the API address; Verdict the socket check.
	Address, Verdict string
	// TCP is set when the API is served on TCP, which the helper never dials.
	TCP bool
	// Path is the socket; Untrusted* name the file or directory that failed
	// the ownership check, its owner and its mode.
	Path                                         string
	UntrustedPath, UntrustedOwner, UntrustedPerm string
	// MetricsAddress is the info file's metrics_address; MetricsKnown is
	// false when the file does not carry it (Tetragon 1.6).
	MetricsAddress string
	MetricsKnown   bool
	// HealthAddress is the health-server-address Tetragon's drop-in
	// directory sets, when it sets one.
	HealthAddress string
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
		ServerAddress  string  `json:"server_address"`
		MetricsAddress *string `json:"metrics_address"`
	}
	if err := json.Unmarshal(data, &info); err != nil {
		return tetragonHost{Installed: true, Verdict: "unreadable: " + err.Error()}
	}
	host := tetragonHost{Installed: true, Address: strings.TrimSpace(info.ServerAddress)}
	if info.MetricsAddress != nil {
		host.MetricsAddress, host.MetricsKnown = strings.TrimSpace(*info.MetricsAddress), true
	}
	if setting, err := readBounded(e.P(tetragonConfDir+"/health-server-address"), 4096); err == nil {
		host.HealthAddress = strings.TrimSpace(string(setting))
	}
	path, ok := strings.CutPrefix(host.Address, "unix://")
	switch {
	case host.Address == "":
		host.Verdict = "unreadable: no server_address"
		return host
	case !ok || !filepath.IsAbs(path):
		host.TCP, host.Verdict = true, "refused: "+codeTetragonTCPAPI+" (the helper never dials a TCP API)"
		return host
	}
	host.Path = path
	for _, candidate := range []string{path, filepath.Dir(path)} {
		info, err := os.Stat(e.P(candidate))
		if err != nil {
			host.Verdict = "unavailable: " + err.Error()
			return host
		}
		uid, _, err := e.OwnerOf(e.P(candidate))
		if err != nil || uid != 0 || info.Mode().Perm()&0o002 != 0 {
			host.Verdict = "refused: " + candidate + " is not root-owned or is world-writable"
			host.UntrustedPath, host.UntrustedPerm = candidate, fmt.Sprintf("%04o", info.Mode().Perm())
			host.UntrustedOwner = "unknown"
			if err == nil {
				host.UntrustedOwner = userLabel(uid)
			}
			return host
		}
	}
	host.Verdict = "trusted (root-owned unix socket)"
	return host
}

// fillCustomer copies the customer's own Tetragon policies into the report.
// A policy Tetragon no longer lists (kept for the events it had) reads
// "not listed" in the STATE column.
func (rep *TetragonReport) fillCustomer(state kernelpolicy.State) {
	for _, policy := range customerPolicies(state) {
		row := TetragonCustomerPolicy{
			Name: policy.Name, Mode: policy.Mode, State: policy.State, Error: policy.Error, Events: counted(policy.Seen),
			Forwarded: counted(policy.Forwarded), Dropped: counted(policy.Dropped), Blocked: counted(policy.Blocked),
			LastEvent: formatTime(policy.LastEventAt),
		}
		if !policy.Listed {
			row.State = "not listed"
		}
		rep.CustomerPolicies = append(rep.CustomerPolicies, row)
	}
}

// counted is a helper counter as the report's unsigned count.
func counted(n int64) uint64 { return uint64(max(n, 0)) }

// onlyUser narrows the report to one enrolled user, by name or uid: its
// row, its observed sessions and its burn-in. It reports whether one
// matched.
func (rep *TetragonReport) onlyUser(who string) bool {
	who = strings.TrimSpace(who)
	uid, err := strconv.Atoi(who)
	match := func(u TetragonUser) bool { return u.User == who || (err == nil && u.UID == uid) }
	var kept []TetragonUser
	for _, user := range rep.Users {
		if match(user) {
			kept = append(kept, user)
		}
	}
	if len(kept) == 0 {
		return false
	}
	rep.Users = kept
	observed := []TetragonObserved{}
	for _, o := range rep.Roots.ObservedOnly {
		if o.UID == kept[0].UID {
			observed = append(observed, o)
		}
	}
	rep.Roots.ObservedOnly = observed
	return true
}

// enrolledNames lists the enrolled users for a refusal.
func enrolledNames(users []TetragonUser) string {
	if len(users) == 0 {
		return "no user is enrolled"
	}
	names := make([]string, 0, len(users))
	for _, user := range users {
		names = append(names, defaultStr(user.User, strconv.Itoa(user.UID)))
	}
	return "enrolled: " + strings.Join(names, ", ")
}

// statusNext is the Next: footer of status, from the readiness engine: what
// fails for the mode this host runs, or how far it is from the next mode.
func statusNext(in tetragonInputs, probes tetragonProbes, now time.Time) []string {
	mode := in.Intent.helperMode()
	if in.Intent.Reason == config.TetragonReasonPlaneCOff {
		mode = in.Intent.Configured
	}
	if modeRank(mode) == 0 {
		return nil
	}
	verify := func(args ...string) string {
		return "  " + adminCommand(append([]string{"enterprise", "linux", "tetragon", "verify"}, args...)...)
	}
	current := tetragonReadiness(in, mode, probes, now)
	if !current.Ready {
		failed := 0
		for _, check := range current.Checks {
			if check.Status == checkFail {
				failed++
			}
		}
		return []string{fmt.Sprintf("Next: %d %s for %s. See:", failed, plural(failed, "check fails", "checks fail"), mode), verify()}
	}
	switch mode {
	case config.TetragonModeConsume:
		target := tetragonReadiness(in, config.TetragonModeObserve, probes, now)
		if target.Ready {
			return []string{"Next: this host is ready for observe. Check with:", verify("--ready-for", "observe")}
		}
		return []string{"Next: observe needs fixes first. See:", verify("--ready-for", "observe")}
	case config.TetragonModeObserve, config.TetragonModeEnforce:
		target := tetragonReadiness(in, config.TetragonModeEnforce, probes, now)
		a := target.Approve
		switch {
		case !target.Ready:
			return []string{"Next: enforce needs fixes first. See:", verify("--ready-for", "enforce")}
		case mode == config.TetragonModeEnforce && a.State != "approved":
			return []string{"Next: approve this build's kernel controls (enforce_ack). See:", verify("--ready-for", "enforce")}
		case a.Users == 0:
			return []string{"Next: no user is enrolled for the kernel controls yet. See:", verify("--ready-for", "enforce")}
		}
		sentence := fmt.Sprintf("Next: %d of %d %s %s ready", a.ReadyUsers, a.Users, plural(a.Users, "user", "users"), plural(a.ReadyUsers, "is", "are"))
		if a.ReadyUsers < a.Users {
			if eta, ok := nextReady(in, now); ok {
				sentence += "; the next is ready in " + humanDuration(eta) + " at the current rate"
			}
		}
		return []string{sentence + ". Check with:", verify("--ready-for", "enforce")}
	}
	return nil
}

// userStateWords is a user's place in the rollout in words, and for a
// monitor-only user why (status prints it under the table, which keeps the
// table within 100 columns).
func userStateWords(user TetragonUser, progress burnInProgress) (state, why string) {
	switch user.State {
	case kernelpolicy.UIDEnforcing:
		return "enforcing", ""
	case kernelpolicy.UIDBurnIn:
		if progress.Reset {
			return "reset by a hit", ""
		}
		return "in burn-in", ""
	case kernelpolicy.UIDInactive:
		if user.Reason == kernelpolicy.ReasonNoAnchors {
			return "no agent installed", ""
		}
	case kernelpolicy.UIDMonitor:
		// In observe every user's burn-in accrues toward enforce, but
		// enforce never denies for a user without a connector in action mode.
		if user.Reason == "observe mode" {
			switch {
			case progress.MonitorOnly:
				return "monitor only", monitorReasonWords[kernelpolicy.ReasonGuardrailObserve]
			case progress.Ready:
				return "ready for enforce", ""
			case progress.Reset:
				return "reset by a hit", ""
			}
			return "in burn-in", ""
		}
	}
	reason := user.Reason
	if words, ok := monitorReasonWords[reason]; ok {
		reason = words
	} else if words, ok := observedReasonWords[reason]; ok {
		reason = words
	}
	return "monitor only", reason
}

// burnInWords is "40.5h of 168h (24%), ~9 days".
func burnInWords(user TetragonUser, progress burnInProgress) string {
	text := fmt.Sprintf("%.1fh of %sh", user.CoveredHours, trimHours(user.NeededHours))
	switch {
	case progress.NoAgent, progress.MonitorOnly:
		return text
	case progress.Ready:
		return text + ", ready"
	}
	text += fmt.Sprintf(" (%d%%)", progress.Percent)
	switch {
	case progress.Measuring:
		text += ", measuring"
	case progress.HasETA:
		text += ", " + humanDuration(progress.ETA)
	}
	return text
}

// kernelControlsLine says where the approval of this build's controls
// stands; it names the approval only in observe and enforce.
func kernelControlsLine(rep *TetragonReport) string {
	mode := rep.Intent.Mode
	switch {
	case mode != config.TetragonModeObserve && mode != config.TetragonModeEnforce:
		return "not loaded (mode " + defaultStr(mode, config.TetragonModeConsume) + ")"
	case mode == config.TetragonModeObserve:
		return rep.KernelPolicy + ", in monitor mode; enforce_ack approves this digest"
	}
	switch rep.Intent.Approval {
	case "approved":
		return rep.KernelPolicy + ", approved"
	case "stale":
		return rep.KernelPolicy + ", enforce_ack is for another build (" + rep.Intent.EnforceAck + ")"
	}
	return rep.KernelPolicy + ", not approved yet (set enterprise.tetragon.enforce_ack to it)"
}

// WriteTetragonReport prints a report: JSON, or the text summary (lines
// within 100 columns, except a copy-paste command).
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
	label := func(name, value string) { fmt.Fprintf(w, "  %-17s%s\n", name+":", value) }
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
	label("Tetragon", tetragon)
	label("API socket", agent.Socket+prefixed(" at ", agent.ServerAddress))
	helper := "not running"
	if rep.Helper.Running {
		helper = "running"
	}
	if rep.Helper.StateUpdated != "" {
		helper += ", state updated " + rep.Helper.StateUpdated
	} else {
		helper += ", no state published yet"
	}
	label("Sensor helper", helper)
	mode := rep.Intent.Mode
	if rep.Intent.CapReason != "" {
		mode += fmt.Sprintf(" (configured %s, capped: %s)", rep.Intent.Configured, rep.Intent.CapReason)
	}
	if rep.Helper.EffectiveMode != "" && rep.Helper.EffectiveMode != rep.Intent.Mode {
		mode += ", running as " + rep.Helper.EffectiveMode
	}
	mode += ", burn-in " + rep.Intent.BurnIn
	if rep.Intent.CustomerEvents == config.TetragonCustomerEventsOff {
		mode += ", your policies' events: off"
	}
	label("Mode", mode)
	label("Kernel controls", kernelControlsLine(rep))
	if rep.Helper.KernelPolicy != "" && rep.Helper.KernelPolicy != rep.KernelPolicy {
		label("Helper applies", rep.Helper.KernelPolicy)
	}
	if p := rep.Pause; p != nil {
		switch {
		case p.Invalid != "":
			label("Pause", "in force for every user on this host (untrusted pause file: "+p.Invalid+")")
		case p.UntilReboot:
			label("Pause", "until the next reboot, set by "+userLabel(p.SetByUID)+" at "+p.SetAt+prefixed(": ", p.Reason)+" (every user on this host)")
		default:
			label("Pause", "until "+p.Until+", set by "+userLabel(p.SetByUID)+" at "+p.SetAt+prefixed(": ", p.Reason)+" (every user on this host)")
		}
	}
	for _, override := range rep.Overrides {
		label("Override", override.Family+" "+override.Kind+" by an operator at "+override.At)
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
		writeStatusUsers(w, rep)
	}
	if len(rep.Roots.ObservedOnly) > 0 {
		count := 0
		for _, observed := range rep.Roots.ObservedOnly {
			count += observed.Count
		}
		fmt.Fprintf(w, "  Observed, not enforced: %d session(s)\n", count)
		for _, observed := range rep.Roots.ObservedOnly {
			fmt.Fprintf(w, "    %s: %d, %s%s\n", userLabel(observed.UID), observed.Count, observedReason(observed.Reason),
				parenthesized(strings.TrimSpace(observed.Connector+" "+observed.Identity)))
		}
	}
	if rep.Roots.OverLimit > 0 {
		fmt.Fprintf(w, "  Over the pid limit: %d live root(s) observed only\n", rep.Roots.OverLimit)
	}
	if len(rep.CustomerPolicies) > 0 {
		fmt.Fprintln(w, "  Your Tetragon policies (DefenseClaw reads their events and never changes them):")
		table := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(table, "    NAME\tMODE\tSTATE\tEVENTS\tFORWARDED\tBLOCKED\tLAST")
		for _, policy := range rep.CustomerPolicies {
			fmt.Fprintf(table, "    %s\t%s\t%s\t%d\t%d\t%d\t%s\n", policy.Name, defaultStr(policy.Mode, "-"), defaultStr(policy.State, "-"),
				policy.Events, policy.Forwarded, policy.Blocked, defaultStr(policy.LastEvent, "-"))
		}
		_ = table.Flush()
	}
	for _, warning := range rep.Warnings {
		fmt.Fprintf(w, "  ! %s: %s\n", warning.Code, warning.Message)
	}
	for _, e := range rep.Errors {
		fmt.Fprintf(w, "  ✗ %s: %s\n", e.Code, e.Message)
	}
	for _, line := range rep.next {
		fmt.Fprintln(w, line)
	}
	return nil
}

// writeStatusUsers prints the users table and, under it, why a user stays
// monitor-only and up to three hit details per user (the JSON keeps all).
func writeStatusUsers(w io.Writer, rep *TetragonReport) {
	fmt.Fprintln(w, "  Users:")
	table := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "    USER\tSTATE\tCONNECTORS\tBURN-IN\tHITS")
	viaPolicy := false
	for _, user := range rep.Users {
		hits := 0
		for _, hit := range append(append([]TetragonHits{}, user.WouldBlock...), user.Blocked...) {
			hits += hit.Count
		}
		progress := rep.progress[user.UID]
		state, _ := userStateWords(user, progress)
		fmt.Fprintf(table, "    %s\t%s\t%s\t%s\t%d\n", statusUserLabel(user), state, connectorsWords(user), burnInWords(user, progress), hits)
		viaPolicy = viaPolicy || len(user.MachinePolicy) > 0
	}
	_ = table.Flush()
	if viaPolicy {
		fmt.Fprintln(w, "    * through vendor machine policy: an eligible account without a targets.yaml row")
	}
	for _, user := range rep.Users {
		var details [][2]string
		if _, why := userStateWords(user, rep.progress[user.UID]); why != "" {
			details = append(details, [2]string{"monitor only: " + why, ""})
		}
		details = append(details, hitLines("would block", user.WouldBlock, user.UID)...)
		details = append(details, hitLines("blocked", user.Blocked, user.UID)...)
		for i, lines := range details {
			if i == 3 {
				fmt.Fprintf(w, "      %s: and %d more (see --json)\n", statusUserLabel(user), len(details)-3)
				break
			}
			fmt.Fprintf(w, "      %s: %s\n", statusUserLabel(user), lines[0])
			if lines[1] != "" {
				fmt.Fprintf(w, "        %s\n", lines[1])
			}
		}
	}
}

// connectorsWords is the CONNECTORS column: a connector the user is
// enrolled for through vendor machine policy carries a "*" ("claudecode*,
// opencode"), which a line under the table explains.
func connectorsWords(user TetragonUser) string {
	machine := map[string]bool{}
	for _, connector := range user.MachinePolicy {
		machine[connector] = true
	}
	words := make([]string, 0, len(user.Connectors))
	for _, connector := range user.Connectors {
		if machine[connector] {
			connector += "*"
		}
		words = append(words, connector)
	}
	return defaultStr(strings.Join(words, ","), "-")
}

func statusUserLabel(user TetragonUser) string {
	if user.User != "" {
		return fmt.Sprintf("%s (%d)", user.User, user.UID)
	}
	return fmt.Sprintf("uid %d", user.UID)
}

// hitLines are, per control, "would block ssh_private_key_read 1x, last <t>"
// and "~/.ssh/id_ed25519 by /usr/bin/cat" (the most frequent path and
// binary).
func hitLines(kind string, hits []TetragonHits, uid int) [][2]string {
	var out [][2]string
	for _, hit := range hits {
		line := fmt.Sprintf("%s %s %dx", kind, strings.TrimPrefix(hit.Control, "kernel."), hit.Count)
		if hit.Last != "" {
			line += ", last " + hit.Last
		}
		where := ""
		if len(hit.Paths) > 0 {
			where = homeRelative(hit.Paths[0].Value, uid)
		}
		if len(hit.Binaries) > 0 {
			where = strings.TrimSpace(where + " by " + hit.Binaries[0].Value)
		}
		out = append(out, [2]string{line, where})
	}
	return out
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
