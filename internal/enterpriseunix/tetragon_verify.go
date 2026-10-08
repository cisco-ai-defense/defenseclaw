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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/sensor/kernelpolicy"
)

// `enterprise linux tetragon verify [--ready-for MODE]`: the one-command
// readiness check (SPEC-TETRAGON-UX 5.2, 5.3). Without --ready-for it checks
// the mode this host's config asks for; with it, what moving to that mode
// needs. It changes nothing and never connects to Tetragon: it reads the
// installed config, the sensor helper's published state, Tetragon's info file,
// /sys/kernel/security/lsm, the unit states and, for Plane C, the gateway's
// /health over its hook socket. Exit 0 when no check fails, 1
// when one does, 2 for bad arguments; warnings never fail it, so config
// management can gate on the exit code. tetragon status prints its Next:
// footer from the same engine.

// TetragonActionVerify is `enterprise linux tetragon verify`.
const TetragonActionVerify = "verify"

// TetragonVerifySchemaVersion versions TetragonReadiness
// (testdata/tetragon_verify.schema.json).
const TetragonVerifySchemaVersion = 1

// Check statuses: fail makes the host not ready; warn and info never do;
// skip is a check that does not apply (no Tetragon installed, or a mode that
// does not need it).
const (
	checkPass = "pass"
	checkFail = "fail"
	checkWarn = "warn"
	checkInfo = "info"
	checkSkip = "skip"
)

// Readiness check ids.
const (
	checkTetragonInstalled  = "tetragon.installed"
	checkTetragonRunning    = "tetragon.running"
	checkTetragonAPI        = "tetragon.api"
	checkTetragonSocket     = "tetragon.socket"
	checkTetragonVersion    = "tetragon.version"
	checkTetragonStream     = "tetragon.stream"
	checkKeepSensorsOnExit  = "tetragon.keep_sensors_on_exit"
	checkBPFLSM             = "kernel.bpf_lsm"
	checkMetricsLoopback    = "tetragon.metrics_loopback"
	checkHealthLoopback     = "tetragon.health_loopback"
	checkPlaneC             = "defenseclaw.plane_c"
	checkAgents             = "defenseclaw.agents"
	checkConnectorsAction   = "defenseclaw.connectors_action"
	checkApproval           = "defenseclaw.approval"
	checkBurnIn             = "defenseclaw.burn_in"
	checkPause              = "defenseclaw.pause"
	checkOverrides          = "defenseclaw.overrides"
	checkPolicies           = "defenseclaw.policies"
	checkOrphans            = "defenseclaw.orphans"
	checkTetragonYourPolicy = "tetragon.your_policies"
)

// tetragonCheckIDs lists every check in the order it prints.
var tetragonCheckIDs = []string{
	checkTetragonInstalled, checkTetragonRunning, checkTetragonAPI, checkTetragonSocket, checkTetragonVersion,
	checkTetragonStream, checkKeepSensorsOnExit, checkBPFLSM, checkMetricsLoopback, checkHealthLoopback,
	checkPlaneC, checkAgents, checkConnectorsAction, checkApproval, checkBurnIn, checkPause, checkOverrides,
	checkPolicies, checkOrphans, checkTetragonYourPolicy,
}

// lsmListPath lists the kernel's active security modules.
const lsmListPath = "/sys/kernel/security/lsm"

// streamFresh is how recent the helper's report of a reachable Tetragon
// must be to count as running now.
const streamFresh = 2 * time.Minute

// TetragonReadiness is the result of `enterprise linux tetragon verify`, and
// with --json its exact output.
type TetragonReadiness struct {
	SchemaVersion int    `json:"schema_version"`
	Action        string `json:"action"`
	OK            bool   `json:"ok"`
	ExitCode      int    `json:"exit_code"`
	// Mode is the mode this host runs as its config renders it; ReadyFor
	// the mode checked; Ready whether no check failed.
	Mode         string          `json:"mode"`
	ReadyFor     string          `json:"ready_for"`
	Ready        bool            `json:"ready"`
	KernelPolicy string          `json:"kernel_policy"`
	Checks       []TetragonCheck `json:"checks"`
	// Users are the enrolled users' burn-in toward enforce, once the helper
	// runs observe or enforce and checks for observe or enforce.
	Users   []TetragonUserReadiness `json:"users"`
	Approve *TetragonApproval       `json:"approve,omitempty"`
	// Next are the lines of the next step: sentences, which the text view
	// wraps at 80 columns, and copy-paste lines indented by two spaces.
	Next   []string                   `json:"next"`
	Errors []enterprisestatus.Message `json:"errors"`
}

// TetragonCheck is one readiness check.
type TetragonCheck struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message"`
	// Fix are copy-paste lines: commands as root runs them, or YAML for the
	// admin config.
	Fix []string `json:"fix"`
}

// TetragonUserReadiness is one enrolled user's burn-in, as the promotion
// guide shows it.
type TetragonUserReadiness struct {
	UID          int     `json:"uid"`
	User         string  `json:"user,omitempty"`
	State        string  `json:"state"`
	Reason       string  `json:"reason,omitempty"`
	CoveredHours float64 `json:"covered_hours"`
	NeededHours  float64 `json:"needed_hours"`
	Percent      int     `json:"percent"`
	// Ready is whether enforce would deny for the user now: burn-in
	// finished (or enforcing) and a connector of the user in action mode.
	Ready     bool `json:"ready"`
	Reset     bool `json:"reset"`
	Measuring bool `json:"measuring"`
	// MonitorOnly is set when no connector of the user is in action mode:
	// enforce never denies for them (guardrail_observe), whatever the
	// burn-in says.
	MonitorOnly bool `json:"monitor_only"`
	// ETAHours is the calendar time until ready at the user's rate so far;
	// absent while measuring, without agent use, and once ready.
	ETAHours *float64            `json:"eta_hours,omitempty"`
	Hits     []TetragonHitDetail `json:"hits"`
	// Phase is the one word a fleet summary counts the user by: enforcing,
	// ready, burn_in, reset, monitor_only, no_agent or held (finished
	// burn-in or limited, and not denied: a deny-anchor limit, a pause, an
	// operator's change). Counting by state, ready, reset and monitor_only
	// called a user without an agent, or one held by the one-deny-anchor
	// rule, "in burn-in" (GAP-0056).
	Phase string `json:"phase"`
}

// Fleet phases of a user (TetragonUserReadiness.Phase).
const (
	phaseEnforcing   = "enforcing"
	phaseReady       = "ready"
	phaseBurnIn      = "burn_in"
	phaseReset       = "reset"
	phaseMonitorOnly = "monitor_only"
	phaseNoAgent     = "no_agent"
	phaseHeld        = "held"
)

// userPhase is a user's fleet phase. runsEnforce: the host runs enforce, so a
// ready user that is not enforcing is held, not waiting to be.
func userPhase(user TetragonUserReadiness, runsEnforce bool) string {
	switch {
	case user.State == kernelpolicy.UIDEnforcing:
		return phaseEnforcing
	case user.MonitorOnly:
		return phaseMonitorOnly
	case user.Ready && runsEnforce:
		return phaseHeld
	case user.Ready:
		return phaseReady
	case user.State == kernelpolicy.UIDInactive && user.Reason == kernelpolicy.ReasonNoAnchors:
		return phaseNoAgent
	case user.Reset:
		return phaseReset
	case user.State == kernelpolicy.UIDBurnIn || (user.State == kernelpolicy.UIDMonitor && user.Reason == "observe mode"):
		return phaseBurnIn
	}
	return phaseHeld
}

// TetragonHitDetail is one control's would-block hits for a user: the most
// frequent path (home-relative) and binary, and the last time.
type TetragonHitDetail struct {
	Control string `json:"control"`
	Count   int    `json:"count"`
	Path    string `json:"path,omitempty"`
	Binary  string `json:"binary,omitempty"`
	Last    string `json:"last,omitempty"`
}

// TetragonApproval is the approve step of the enforce promotion.
type TetragonApproval struct {
	// State is not_needed, missing, stale or approved.
	State string `json:"state"`
	// Digest is this build's kernel_policy: the same on every host of it.
	Digest     string `json:"digest"`
	EnforceAck string `json:"enforce_ack"`
	// ReadyUsers would be enforced now; Users are all enrolled ones.
	ReadyUsers int `json:"ready_users"`
	Users      int `json:"users"`
}

// tetragonProbes are the host facts outside the helper's state.
type tetragonProbes struct {
	// TetragonActive is whether tetragon.service is active.
	TetragonActive bool
	// LSM is /sys/kernel/security/lsm; LSMKnown whether it could be read.
	LSM      string
	LSMKnown bool
}

// modeRank orders the modes by what they need.
func modeRank(mode string) int {
	switch mode {
	case config.TetragonModeConsume:
		return 1
	case config.TetragonModeObserve:
		return 2
	case config.TetragonModeEnforce:
		return 3
	}
	return 0
}

// tetragonReadiness runs the checks of readyFor at now.
func tetragonReadiness(in tetragonInputs, readyFor string, probes tetragonProbes, now time.Time) *TetragonReadiness {
	state, host, intent := in.State, in.Host, in.Intent
	hostMode := intent.helperMode()
	rep := &TetragonReadiness{
		SchemaVersion: TetragonVerifySchemaVersion, Action: TetragonActionVerify, Mode: hostMode, ReadyFor: readyFor,
		KernelPolicy: kernelpolicy.Digest(), Checks: []TetragonCheck{}, Users: []TetragonUserReadiness{}, Next: []string{},
		Errors: []enterprisestatus.Message{},
	}
	rank := modeRank(readyFor)
	checks := map[string]TetragonCheck{}
	set := func(id, status, message string, fix ...string) {
		checks[id] = TetragonCheck{ID: id, Status: status, Message: message, Fix: append([]string{}, fix...)}
	}
	skip := func(id, why string) { set(id, checkSkip, why) }
	restart := "sudo systemctl restart tetragon   # " + tetragonRestartNote
	if rank == 0 {
		// Mode off: nothing of Tetragon's is needed; only DefenseClaw's own
		// leftovers matter.
		for _, id := range tetragonCheckIDs {
			skip(id, "mode off: DefenseClaw does not use Tetragon on this host")
		}
		setOrphansCheck(set, in)
		return finishReadiness(rep, checks)
	}

	// Tetragon itself.
	fresh := in.Running && state.Tetragon.Reachable && !state.UpdatedAt.IsZero() && now.Sub(state.UpdatedAt) <= streamFresh
	if !host.Installed {
		set(checkTetragonInstalled, checkFail, "Tetragon is not installed (no "+tetragonInfoPath+"); install Tetragon 1.7.x (see the Tetragon guide)",
			"sudo systemctl enable --now tetragon")
		for _, id := range []string{checkTetragonRunning, checkTetragonAPI, checkTetragonSocket, checkTetragonVersion, checkTetragonStream,
			checkKeepSensorsOnExit, checkBPFLSM, checkMetricsLoopback, checkHealthLoopback} {
			skip(id, "Tetragon is not installed")
		}
	} else {
		set(checkTetragonInstalled, checkPass, "Tetragon is installed ("+tetragonInfoPath+")")
		pid := ""
		if state.Tetragon.PID > 0 {
			pid = fmt.Sprintf(" (pid %d)", state.Tetragon.PID)
		}
		if probes.TetragonActive || fresh {
			set(checkTetragonRunning, checkPass, "Tetragon is running"+pid)
		} else {
			set(checkTetragonRunning, checkFail, "Tetragon is not running (no event reaches the sensor helper)",
				"sudo systemctl start tetragon", "sudo journalctl -u tetragon -n 50")
		}
		setTetragonEndpointChecks(set, host, restart)
		setVersionCheck(set, state, readyFor, rank)
		switch {
		case hostMode == config.TetragonModeOff:
			skip(checkTetragonStream, "the sensor helper runs with Tetragon off (mode off); it connects once the new mode is applied")
		case !in.Running:
			set(checkTetragonStream, checkFail, "the sensor helper is not running (Plane C records nothing)",
				"sudo systemctl start defenseclaw-sensor-helper", "sudo journalctl -u defenseclaw-sensor-helper -n 50")
		case fresh:
			set(checkTetragonStream, checkPass, "the sensor helper reads Tetragon's events")
		default:
			why := defaultStr(state.Tetragon.Reason, "no report from the sensor helper in the last 2 minutes")
			set(checkTetragonStream, checkFail, "the sensor helper does not read Tetragon's events ("+why+"; "+nativePlaneC+")",
				"sudo systemctl restart defenseclaw-sensor-helper", "sudo journalctl -u defenseclaw-sensor-helper -n 50")
		}
		if rank >= modeRank(config.TetragonModeEnforce) {
			setEnforceKernelChecks(set, state, probes, restart, intent.helperModeLoadsPolicies())
		} else {
			skip(checkKeepSensorsOnExit, "only enforce needs it")
			skip(checkBPFLSM, "only enforce needs it")
		}
		setLoopbackCheck(set, checkMetricsLoopback, "metrics", host.MetricsAddress, host.MetricsKnown, "127.0.0.1:2112", "metrics-server", restart,
			" (without metrics, events lost reads unknown)")
		setLoopbackCheck(set, checkHealthLoopback, "health", host.HealthAddress, host.HealthAddress != "", "127.0.0.1:6789", "health-server-address", restart, "")
	}

	// DefenseClaw.
	if intent.PlaneC {
		setPlaneCDelivery(set, in.Gateway)
	} else {
		set(checkPlaneC, checkFail, "AI Discovery Plane C is off (the sensor helper runs with Tetragon off); set these in the admin config and apply it",
			"ai_discovery:", "  runtime:", "    enabled: true", "    enable_host_plane: true")
	}
	if rank >= modeRank(config.TetragonModeObserve) {
		setAgentsCheck(set, in, readyFor)
		switch {
		case state.Pause == nil:
			set(checkPause, checkPass, "kernel enforcement is not paused")
		case state.Pause.Pause != nil:
			set(checkPause, checkWarn, withoutNextStep(tetragonMessage(kernelpolicy.WarnEnforcePaused,
				tetragonFacts{Pause: state.Pause.Pause, SetBy: userLabel(state.Pause.Pause.SetByUID)}))+"; resume with:",
				adminCommand("enterprise", "linux", "tetragon", "resume"))
		default:
			set(checkPause, checkWarn, withoutNextStep(tetragonMessage(kernelpolicy.WarnPauseInvalid,
				tetragonFacts{PauseInvalid: state.Pause.Invalid}))+"; remove it with:",
				adminCommand("enterprise", "linux", "tetragon", "resume"))
		}
		if len(state.Overrides) > 0 {
			var parts []string
			for _, family := range sortedFamilies(state.Overrides) {
				parts = append(parts, string(family)+" "+overrideVerb(state.Overrides[family].Kind))
			}
			set(checkOverrides, checkWarn, "an operator changed DefenseClaw's policies in Tetragon ("+strings.Join(parts, ", ")+
				"; the sensor helper does not undo it); to hand them back, change enterprise.tetragon.enforce_ack or mode in the admin config and apply it")
		} else {
			set(checkOverrides, checkPass, "no operator override")
		}
		setPoliciesCheck(set, state, intent)
	} else {
		skip(checkAgents, "only observe and enforce need it")
		skip(checkPause, "only observe and enforce need it")
		skip(checkOverrides, "only observe and enforce need it")
		skip(checkPolicies, "only observe and enforce need it")
	}
	if rank >= modeRank(config.TetragonModeObserve) {
		rep.Users = readinessUsers(in, now)
	}
	if rank >= modeRank(config.TetragonModeEnforce) {
		setConnectorsCheck(set, intent, rep.Users)
		rep.Approve = approvalFor(intent, rep.Users)
		switch {
		case !intent.helperModeLoadsPolicies():
			// Burn-in is measured only while observe or enforce runs: from
			// consume, the guide's next ring is observe.
			set(checkApproval, checkInfo, "approve this build's kernel controls once the observe ring measured the burn-in")
			set(checkBurnIn, checkFail, "no burn-in is measured on this host yet (it runs "+hostMode+"); run mode observe first, where every enrolled user's burn-in accrues")
		default:
			switch rep.Approve.State {
			case "approved":
				set(checkApproval, checkPass, "enforce_ack approves this build's kernel controls ("+rep.KernelPolicy+")")
			case "stale":
				set(checkApproval, checkInfo, "The approval (enforce_ack "+intent.ack()+") does not include this build's "+rep.KernelPolicy+"; approve it (below)")
			default:
				set(checkApproval, checkInfo, "this build's kernel controls are not approved yet; approve them (below)")
			}
			set(checkBurnIn, checkInfo, fmt.Sprintf("%d of %d enrolled users finished burn-in on this host", finishedBurnIn(rep.Users), len(rep.Users)))
		}
	} else {
		for _, id := range []string{checkConnectorsAction, checkApproval, checkBurnIn} {
			skip(id, "only enforce needs it")
		}
	}
	setOrphansCheck(set, in)
	setYourPoliciesCheck(set, in)
	return finishReadiness(rep, checks)
}

// setPlaneCDelivery checks that the gateway records Plane C, not only that
// the config turns it on. A helper restart ended the gateway's subscription
// and Plane C recorded nothing while every check passed (GAP-0051). The
// gateway now re-attaches on its own, and its /health says Plane C is down
// until the next poll after that, so this warns rather than fails: a ring
// gate right after a push that restarted the helper must not fail on it.
func setPlaneCDelivery(set func(id, status, message string, fix ...string), gateway *gatewayPlaneC) {
	switch {
	case gateway == nil:
		set(checkPlaneC, checkPass, "AI Discovery Plane C is on")
	case !gateway.Read:
		set(checkPlaneC, checkWarn, "AI Discovery Plane C is on; whether the gateway records it is not known ("+gateway.Err+")",
			adminCommand("enterprise", "linux", "verify"))
	case !gateway.Running:
		set(checkPlaneC, checkWarn, "AI Discovery Plane C is on, but the gateway records nothing from it ("+
			defaultStr(gateway.Reason, "not running")+"); the gateway re-attaches to a restarted sensor helper within a minute; if this stays:",
			"sudo systemctl restart defenseclaw-gateway", "sudo journalctl -u defenseclaw-gateway -n 50")
	default:
		set(checkPlaneC, checkPass, "AI Discovery Plane C is on and the gateway records it")
	}
}

// gatewayPlaneC is Plane C as the gateway's /health reports it.
type gatewayPlaneC struct {
	// Read is false when /health could not be read or names no Plane C;
	// Err says why.
	Read    bool
	Err     string
	Running bool
	Reason  string
}

// planeCFromHealth reads ai_runtime.details.planes.c from a /health body.
func planeCFromHealth(body []byte) gatewayPlaneC {
	var document struct {
		AIRuntime *struct {
			Details struct {
				Planes map[string]struct {
					Running bool   `json:"running"`
					Reason  string `json:"reason"`
				} `json:"planes"`
			} `json:"details"`
		} `json:"ai_runtime"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		return gatewayPlaneC{Err: "the gateway's /health does not parse: " + err.Error()}
	}
	if document.AIRuntime == nil {
		return gatewayPlaneC{Err: "the gateway's /health has no ai_runtime section"}
	}
	c, ok := document.AIRuntime.Details.Planes["c"]
	if !ok {
		return gatewayPlaneC{Err: "the gateway has not reported Plane C yet; it does after its first poll"}
	}
	return gatewayPlaneC{Read: true, Running: c.Running, Reason: c.Reason}
}

// gatewayPlaneC reads Plane C from the gateway's /health over its hook
// socket, after checking that the gateway serves that socket.
func (l *lifecycle) gatewayPlaneC(ctx context.Context) *gatewayPlaneC {
	env := l.env
	if env.HealthGet == nil || env.HookSocketPeer == nil {
		return nil
	}
	for _, unit := range env.Services.Units() {
		if unit.Kind != "gateway" {
			continue
		}
		if !env.Services.Active(ctx, unit) {
			return &gatewayPlaneC{Err: unit.Name + " is not active"}
		}
		serviceUID := l.serviceUID
		if record, err := env.loadDeployment(); err == nil && record != nil {
			serviceUID = record.ServiceUID
		}
		body, err := l.gatewayHealth(ctx, unit, serviceUID)
		if err != nil {
			return &gatewayPlaneC{Err: err.Error()}
		}
		planeC := planeCFromHealth(body)
		return &planeC
	}
	return nil
}

// withoutNextStep is a code-table message up to its impact: a check row
// prints the next step as its fix lines instead.
func withoutNextStep(message string) string {
	if i := strings.LastIndex(message, "); "); i > 0 {
		return message[:i+1]
	}
	return message
}

// finishReadiness lists the checks in their order and says what is next.
func finishReadiness(rep *TetragonReadiness, checks map[string]TetragonCheck) *TetragonReadiness {
	var failed []string
	for _, id := range tetragonCheckIDs {
		check := checks[id]
		rep.Checks = append(rep.Checks, check)
		if check.Status == checkFail {
			failed = append(failed, id)
		}
	}
	rep.Ready = len(failed) == 0
	rep.Next = readinessNext(rep, failed)
	return rep
}

// setOrphansCheck fails on DefenseClaw policies left without a sensor
// helper to reconcile them (the same rule as verify's problem).
// setPoliciesCheck fails while DefenseClaw's own policies are not in
// Tetragon as the mode calls for: one Tetragon refused to load (load_error),
// one missing, or a last pass that did not apply them. Without it the
// readiness gate, and detect.sh --require-tetragon, passed on a host whose
// controls never loaded (GAP-0045). On a host whose mode loads none
// (consume, off) there is nothing to check yet.
func setPoliciesCheck(set func(id, status, message string, fix ...string), state kernelpolicy.State, intent tetragonIntent) {
	status := adminCommand("enterprise", "linux", "tetragon", "status")
	if !intent.helperModeLoadsPolicies() {
		set(checkPolicies, checkInfo, "the sensor helper loads DefenseClaw's policies once mode observe runs; check again then")
		return
	}
	var failed, missing []string
	for _, policy := range state.Policies {
		switch policy.State {
		case kernelpolicy.StateLoadError, kernelpolicy.StateError:
			failed = append(failed, policy.Name)
		case "":
			missing = append(missing, policy.Name)
		}
	}
	switch {
	case len(failed) > 0:
		set(checkPolicies, checkFail, "Tetragon did not load DefenseClaw's "+andList(failed)+
			" (what they hold is neither observed nor denied); see why with:", "sudo journalctl -u tetragon -n 50", status)
	case len(missing) > 0, state.Tetragon.Reachable && !state.InSync:
		set(checkPolicies, checkFail, "the sensor helper's last pass did not leave Tetragon with the policies the mode calls for; see why with:",
			"sudo journalctl -u defenseclaw-sensor-helper -n 50", status)
	case len(state.Policies) == 0:
		set(checkPolicies, checkWarn, "the sensor helper has not loaded DefenseClaw's policies yet; check again in a minute")
	default:
		set(checkPolicies, checkPass, fmt.Sprintf("DefenseClaw's %d %s loaded in Tetragon", len(state.Policies), plural(len(state.Policies), "policy is", "policies are")))
	}
}

func setOrphansCheck(set func(id, status, message string, fix ...string), in tetragonInputs) {
	for _, finding := range tetragonFindings(in) {
		if finding.Code == codeKernelPolicyOrphaned {
			set(checkOrphans, checkFail, withoutNextStep(finding.Message)+"; start the sensor helper, or remove them with:",
				helperCommand("--tetragon-cleanup"))
			return
		}
	}
	set(checkOrphans, checkPass, "no DefenseClaw policy is left without a sensor helper")
}

func setTetragonEndpointChecks(set func(id, status, message string, fix ...string), host tetragonHost, restart string) {
	switch {
	case host.TCP:
		set(checkTetragonAPI, checkFail, "Tetragon serves its API on "+host.Address+" (any local account can load kernel policies through it; the sensor helper never dials it)",
			tetragonSetting("server-address", "unix:///var/run/tetragon/tetragon.sock"), restart)
		set(checkTetragonSocket, checkSkip, "Tetragon's API is not a unix socket")
	case host.Path == "":
		set(checkTetragonAPI, checkFail, "Tetragon's info file names no usable API address ("+host.Verdict+")",
			tetragonSetting("server-address", "unix:///var/run/tetragon/tetragon.sock"), restart)
		set(checkTetragonSocket, checkSkip, "Tetragon's API address is not known")
	default:
		set(checkTetragonAPI, checkPass, "API: unix socket "+host.Path)
		switch {
		case strings.HasPrefix(host.Verdict, "trusted"):
			set(checkTetragonSocket, checkPass, "the info file, socket and their directories pass the helper's trust check")
		case host.UntrustedPath != "":
			set(checkTetragonSocket, checkFail, host.UntrustedPath+" must be owned by root and "+defaultStr(host.UntrustedRule, "not writable by others")+
				" (found owner "+host.UntrustedOwner+", mode "+host.UntrustedPerm+"); restore its owner and mode, or restart Tetragon so it recreates it", restart)
		default:
			set(checkTetragonSocket, checkFail, "the socket "+host.Path+" is not usable ("+host.Verdict+"); restart Tetragon so it recreates it", restart)
		}
	}
}

func setVersionCheck(set func(id, status, message string, fix ...string), state kernelpolicy.State, readyFor string, rank int) {
	version := strings.TrimSpace(state.Tetragon.Version)
	if version == "" {
		set(checkTetragonVersion, checkWarn, "Tetragon's version is not known yet (the sensor helper has not reached it)")
		return
	}
	minor := tetragonMinor(version)
	supported := minor == "1.7" || (minor == "1.6" && rank < modeRank(config.TetragonModeObserve))
	label := "Tetragon " + version
	if !strings.HasPrefix(version, "v") {
		label = "Tetragon v" + version
	}
	if supported {
		set(checkTetragonVersion, checkPass, label+" is supported for "+readyFor)
		return
	}
	set(checkTetragonVersion, checkFail, label+" is not supported for "+readyFor+" (consume: 1.6 and 1.7; observe and enforce: 1.7); install Tetragon 1.7.x, or keep mode consume on 1.6")
}

// tetragonMinor is "1.7" for v1.7.1.
func tetragonMinor(version string) string {
	parts := strings.SplitN(strings.TrimPrefix(strings.TrimSpace(version), "v"), ".", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "." + parts[1]
}

// setEnforceKernelChecks checks the two Tetragon facts enforce needs. The
// sensor helper reads them only in observe and enforce (measured); on a host
// that runs consume or off an unknown fact is information, not a failure
// with a fix: the setting may well be right, and the printed restart would
// drop the policies added with tetra for nothing (GAP-0038).
func setEnforceKernelChecks(set func(id, status, message string, fix ...string), state kernelpolicy.State, probes tetragonProbes, restart string, measured bool) {
	switch keep := state.Tetragon.KeepSensorsOnExit; {
	case keep != nil && !*keep:
		set(checkKeepSensorsOnExit, checkPass, "Tetragon does not keep sensors on exit")
	case keep == nil && !measured:
		set(checkKeepSensorsOnExit, checkInfo, "the sensor helper reads Tetragon's keep-sensors-on-exit once mode observe runs; check again then (enforce needs it false)")
	case keep == nil:
		set(checkKeepSensorsOnExit, checkFail, "Tetragon's keep-sensors-on-exit is not known (the sensor helper has not read it; enforce stays in monitor mode); set it to false, restart Tetragon, then remove leftover pins under /sys/fs/bpf/tetragon",
			tetragonSetting("keep-sensors-on-exit", "false"), restart)
	default:
		set(checkKeepSensorsOnExit, checkFail, "Tetragon keeps sensors on exit (enforce stays in monitor mode: stopping Tetragon would leave programs enforcing with nobody updating them); set it to false, restart Tetragon, then remove leftover pins under /sys/fs/bpf/tetragon",
			tetragonSetting("keep-sensors-on-exit", "false"), restart)
	}
	listed := probes.LSMKnown && lsmLists(probes.LSM, "bpf")
	probe := state.Tetragon.LSM
	switch {
	case probe != nil && *probe && (listed || !probes.LSMKnown):
		set(checkBPFLSM, checkPass, "BPF LSM is enabled")
	case probe == nil && listed && !measured:
		set(checkBPFLSM, checkInfo, "the kernel lists bpf as a security module; the sensor helper reads Tetragon's BPF LSM probe once mode observe runs")
	case probe == nil && listed:
		set(checkBPFLSM, checkWarn, "the kernel lists bpf as a security module, but Tetragon has not reported its BPF LSM probe yet")
	default:
		list := strings.TrimSpace(probes.LSM)
		if !probes.LSMKnown {
			list = "unreadable"
		}
		set(checkBPFLSM, checkFail, "BPF LSM is not enabled (the controls cannot deny; "+lsmListPath+": "+list+
			"); add bpf to the kernel's lsm= boot parameter and reboot (see the Tetragon guide)")
	}
}

// andList joins names as a sentence does: "a", "a and b", "a, b and c".
func andList(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// lsmLists reports whether the comma list of security modules names module.
func lsmLists(list, module string) bool {
	for _, item := range strings.Split(strings.TrimSpace(list), ",") {
		if strings.TrimSpace(item) == module {
			return true
		}
	}
	return false
}

func setLoopbackCheck(set func(id, status, message string, fix ...string), id, what, address string, known bool, want, flag, restart, note string) {
	address = strings.TrimSpace(address)
	switch {
	case !known:
		set(id, checkSkip, "Tetragon's "+what+" listener is not known (this Tetragon does not report it)")
	case address == "":
		set(id, checkWarn, "Tetragon serves no "+what+" endpoint"+note, tetragonSetting(flag, want), restart)
	case loopbackAddress(address):
		set(id, checkPass, "Tetragon's "+what+" endpoint listens on loopback ("+address+")")
	default:
		set(id, checkWarn, "Tetragon's "+what+" endpoint listens on every interface ("+address+")", tetragonSetting(flag, want), restart)
	}
}

// loopbackAddress reports whether a listen address binds only loopback.
func loopbackAddress(address string) bool {
	hostPart, _, err := net.SplitHostPort(address)
	if err != nil {
		hostPart = address
	}
	if strings.EqualFold(hostPart, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(hostPart, "[]"))
	return ip != nil && ip.IsLoopback()
}

// setAgentsCheck: at least one enrolled user has an anchored command-line
// agent. The helper publishes users in observe and enforce; before that it
// is not known.
func setAgentsCheck(set func(id, status, message string, fix ...string), in tetragonInputs, readyFor string) {
	failing := checkWarn
	if readyFor == config.TetragonModeEnforce {
		failing = checkFail
	}
	users := in.State.UIDs
	switch {
	case !in.Intent.helperModeLoadsPolicies():
		set(checkAgents, checkInfo, "the sensor helper checks enrolled users' agents once mode observe runs; check again then")
		return
	case !in.Running || in.State.UpdatedAt.IsZero():
		set(checkAgents, checkInfo, "the sensor helper has not published the enrolled users yet; check again once it runs")
		return
	}
	if len(users) == 0 {
		set(checkAgents, failing, "no user is enrolled on this host (nothing can be anchored); enroll users in the admin config and apply it")
		return
	}
	var pending, over []string
	for _, user := range users {
		name := user.User
		if name == "" {
			name = fmt.Sprintf("uid %d", user.UID)
		}
		switch user.Reason {
		case kernelpolicy.WarnSessionPolicyPending:
			pending = append(pending, name)
		case kernelpolicy.WarnRootsOverLimit:
			over = append(over, name)
		}
	}
	if len(pending) > 0 {
		set(checkAgents, failing, "the controls policy has not loaded for an agent session of "+strings.Join(pending, ", ")+
			"; covered time is paused until its process id is in an enabled policy")
		return
	}
	if len(over) > 0 {
		set(checkAgents, failing, fmt.Sprintf("%s run more than %d agent sessions at once; the monitor controls measure %d,"+
			" so covered time is paused until fewer run", strings.Join(over, ", "), kernelpolicy.MaxPIDs, kernelpolicy.MaxPIDs))
		return
	}
	var with, without []string
	for _, user := range users {
		name := user.User
		if name == "" {
			name = fmt.Sprintf("uid %d", user.UID)
		}
		if hasAnchoredAgent(user, in.State.BurnIn.UIDs[strconv.Itoa(user.UID)]) {
			with = append(with, name)
		} else {
			without = append(without, name)
		}
	}
	missing := missingConnectorRows(in.Intent, users)
	if len(with) == 0 {
		detail := "no agent seen for " + strings.Join(without, ", ")
		if len(missing) > 0 {
			detail += "; no enrolled user has a row for " + strings.Join(missing, ", ")
		}
		set(checkAgents, failing, "no enrolled user has an anchored command-line agent ("+detail+"); install a command-line agent for an enrolled user, or enroll a user who runs one")
		return
	}
	message := fmt.Sprintf("%d enrolled %s an agent (%s)", len(with), plural(len(with), "user has", "users have"), strings.Join(with, ", "))
	if len(without) > 0 {
		message += "; none seen yet for " + strings.Join(without, ", ")
	}
	if len(missing) > 0 {
		message += "; no row for " + strings.Join(missing, ", ")
	}
	if predating, names := predatingSessions(in.State); predating > 0 {
		// GAP-0053: Tetragon marks an agent's processes when the agent
		// starts; a session that was running when the controls loaded is
		// not denied until it restarts.
		set(checkAgents, checkWarn, message+fmt.Sprintf("; %d agent %s of %s started before the kernel controls loaded and %s not denied until restarted",
			predating, plural(predating, "session", "sessions"), strings.Join(names, ", "), plural(predating, "is", "are")))
		return
	}
	set(checkAgents, checkPass, message)
}

// predatingSessions counts the agent sessions the helper reports as started
// before the enforcing controls loaded, and names their users.
func predatingSessions(state kernelpolicy.State) (int, []string) {
	count := 0
	seen := map[int]bool{}
	var names []string
	for _, observed := range state.Roots.Observed {
		if observed.Reason != kernelpolicy.ReasonPredatesControls {
			continue
		}
		count += observed.Count
		if !seen[observed.UID] {
			seen[observed.UID] = true
			names = append(names, userLabel(observed.UID))
		}
	}
	return count, names
}

// helperModeLoadsPolicies reports whether the helper runs observe or enforce.
func (t tetragonIntent) helperModeLoadsPolicies() bool {
	mode := t.helperMode()
	return mode == config.TetragonModeObserve || mode == config.TetragonModeEnforce
}

// hasAnchoredAgent reports whether a user's agent was anchored: a live root
// now, covered burn-in time, a hit, or enforcement.
func hasAnchoredAgent(user kernelpolicy.UIDStatus, record *kernelpolicy.UIDRecord) bool {
	if user.State == kernelpolicy.UIDInactive && user.Reason == kernelpolicy.ReasonNoAnchors {
		return false
	}
	if user.State == kernelpolicy.UIDEnforcing || user.AnchoredRoots > 0 || user.CoveredSeconds > 0 {
		return true
	}
	return record != nil && (len(record.WouldBlock) > 0 || len(record.Blocked) > 0)
}

// missingConnectorRows are the enrolled command-line connectors no user has
// a row for.
func missingConnectorRows(intent tetragonIntent, users []kernelpolicy.UIDStatus) []string {
	rows := map[string]bool{}
	for _, user := range users {
		for _, connector := range user.Connectors {
			rows[connector] = true
		}
	}
	var out []string
	for _, connector := range append(append([]string{}, intent.ActionCLI...), intent.ObserveCLI...) {
		if !rows[connector] {
			out = append(out, connector)
		}
	}
	sort.Strings(out)
	return out
}

// setConnectorsCheck: a kernel control denies only for a command-line
// connector in action mode. It fails when enforce would deny for nobody (no
// such connector, or no enrolled user runs one) and warns while some users
// stay monitor-only.
func setConnectorsCheck(set func(id, status, message string, fix ...string), intent tetragonIntent, users []TetragonUserReadiness) {
	fix := make([]string, 0, len(intent.ObserveCLI))
	for _, connector := range intent.ObserveCLI {
		fix = append(fix, "guardrail.connectors."+connector+".mode: action")
	}
	monitorOnly := 0
	for _, user := range users {
		if user.MonitorOnly {
			monitorOnly++
		}
	}
	// The line starts with a word, not a connector name, so the sentence
	// case of the output never capitalizes one name of a list.
	observe := plural(len(intent.ObserveCLI), "the connector ", "the connectors ") + andList(intent.ObserveCLI) + " " +
		plural(len(intent.ObserveCLI), "is", "are") + " in observe mode"
	switch {
	case len(intent.ActionCLI)+len(intent.ObserveCLI) == 0:
		set(checkConnectorsAction, checkFail, "no command-line connector is enrolled (a kernel control anchors only command-line agents, so enforce would deny nothing)")
	case len(intent.ActionCLI) == 0:
		set(checkConnectorsAction, checkFail, observe+", so enforce would deny nothing (every user stays monitor-only); set the mode in the admin config and apply it", fix...)
	case len(users) > 0 && monitorOnly == len(users):
		set(checkConnectorsAction, checkFail, "no enrolled user runs a connector in action mode ("+strings.Join(intent.ActionCLI, ", ")+"), so enforce would deny nothing; set the mode of the connectors they run in the admin config and apply it", fix...)
	case len(intent.ObserveCLI) > 0:
		stay := "their agents stay monitor-only"
		if monitorOnly > 0 {
			stay = fmt.Sprintf("%d %s monitor-only", monitorOnly, plural(monitorOnly, "user stays", "users stay"))
		}
		set(checkConnectorsAction, checkWarn, observe+" ("+stay+"); set the mode in the admin config and apply it, or accept monitor-only", fix...)
	default:
		set(checkConnectorsAction, checkPass, "every enrolled command-line connector is in action mode ("+strings.Join(intent.ActionCLI, ", ")+")")
	}
}

func setYourPoliciesCheck(set func(id, status, message string, fix ...string), in tetragonInputs) {
	var foreign []string
	for _, warning := range in.State.Warnings {
		if name, ok := strings.CutPrefix(warning, kernelpolicy.WarnForeignName+":"); ok {
			foreign = append(foreign, name)
		}
	}
	sort.Strings(foreign)
	// Loaded are the ones Tetragon lists now; the helper also keeps a
	// policy that left the list for the events it had.
	loaded, enforcing := 0, 0
	for _, policy := range in.State.CustomerPolicies {
		if !policy.Listed {
			continue
		}
		loaded++
		if strings.EqualFold(policy.Mode, "enforce") {
			enforcing++
		}
	}
	message := "DefenseClaw never changes your own Tetragon policies; it reads their events"
	if loaded > 0 {
		message = fmt.Sprintf("%d of your Tetragon policies %s loaded (%d enforcing); DefenseClaw reads their events and never changes them",
			loaded, plural(loaded, "is", "are"), enforcing)
	}
	if len(foreign) > 0 {
		set(checkTetragonYourPolicy, checkWarn, message+"; "+strings.Join(foreign, ", ")+" "+plural(len(foreign), "has", "have")+
			" DefenseClaw's name pattern but "+plural(len(foreign), "is", "are")+" yours: DefenseClaw never changes "+plural(len(foreign), "it", "them")+
			"; rename "+plural(len(foreign), "it", "them")+" if the name is confusing")
		return
	}
	set(checkTetragonYourPolicy, checkInfo, message)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// readinessUsers are the enrolled users' burn-in toward enforce, in uid
// order.
func readinessUsers(in tetragonInputs, now time.Time) []TetragonUserReadiness {
	state := in.State
	out := []TetragonUserReadiness{}
	users := append([]kernelpolicy.UIDStatus(nil), state.UIDs...)
	sort.Slice(users, func(i, j int) bool { return users[i].UID < users[j].UID })
	for _, user := range users {
		record := state.BurnIn.UIDs[strconv.Itoa(user.UID)]
		p := progressFor(user, record, in, now)
		view := TetragonUserReadiness{
			UID: user.UID, User: user.User, State: user.State, Reason: user.Reason, CoveredHours: roundHours(p.Covered),
			NeededHours: roundHours(p.Needed), Percent: p.Percent,
			Ready: (p.Ready || user.State == kernelpolicy.UIDEnforcing) && !p.MonitorOnly && !noDenyAnchor(user.State, user.Reason) &&
				!burnInPaused(user.Reason),
			Reset: p.Reset, Measuring: p.Measuring, MonitorOnly: p.MonitorOnly, Hits: hitDetails(record, user.UID),
		}
		if p.HasETA {
			hours := roundHours(p.ETA)
			view.ETAHours = &hours
		}
		view.Phase = userPhase(view, in.Intent.helperMode() == config.TetragonModeEnforce)
		out = append(out, view)
	}
	return out
}

func roundHours(d time.Duration) float64 { return math.Round(d.Hours()*10) / 10 }

// hitDetails are a user's would-block hits by control, the newest first.
func hitDetails(record *kernelpolicy.UIDRecord, uid int) []TetragonHitDetail {
	out := []TetragonHitDetail{}
	if record == nil {
		return out
	}
	for control, stats := range record.WouldBlock {
		if stats == nil {
			continue
		}
		hit := TetragonHitDetail{Control: control, Count: stats.Count, Last: formatTime(stats.Last)}
		if len(stats.Paths) > 0 {
			hit.Path = homeRelative(stats.Paths[0].Value, uid)
		}
		if len(stats.Binaries) > 0 {
			hit.Binary = stats.Binaries[0].Value
		}
		out = append(out, hit)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Last != out[j].Last {
			return out[i].Last > out[j].Last
		}
		return out[i].Control < out[j].Control
	})
	return out
}

// finishedBurnIn counts the users whose burn-in finished (or who are
// enforcing), monitor-only ones included.
func finishedBurnIn(users []TetragonUserReadiness) int {
	n := 0
	for _, user := range users {
		if user.Ready || (user.MonitorOnly && (user.Percent == 100 || user.State == kernelpolicy.UIDEnforcing)) {
			n++
		}
	}
	return n
}

// approvalFor is the approve step for the users' readiness.
func approvalFor(intent tetragonIntent, users []TetragonUserReadiness) *TetragonApproval {
	enforce := intent
	enforce.Mode = config.TetragonModeEnforce
	out := &TetragonApproval{State: approvalOf(enforce), Digest: kernelpolicy.Digest(), EnforceAck: intent.ack(), Users: len(users)}
	for _, user := range users {
		if user.Ready {
			out.ReadyUsers++
		}
	}
	return out
}

// readinessNext is the next step after the checks.
func readinessNext(rep *TetragonReadiness, failed []string) []string {
	verify := adminCommand("enterprise", "linux", "tetragon", "verify", "--ready-for", rep.ReadyFor)
	switch {
	case rep.ReadyFor == config.TetragonModeOff:
		return []string{"This host runs mode off: DefenseClaw does not use Tetragon. Check a mode with:",
			"  " + adminCommand("enterprise", "linux", "tetragon", "verify", "--ready-for", "consume")}
	case rep.ReadyFor == config.TetragonModeEnforce && modeRank(rep.Mode) < modeRank(config.TetragonModeObserve):
		// The burn-in is measured in observe: name that step, not a fix.
		text := "Not ready for enforce: this host runs " + rep.Mode + ", and the burn-in is measured in observe. Move to observe first"
		if others := without(failed, checkBurnIn); len(others) > 0 {
			text += " (and fix " + strings.Join(others, ", ") + ")"
		}
		return []string{text + "; check it with:",
			"  " + adminCommand("enterprise", "linux", "tetragon", "verify", "--ready-for", config.TetragonModeObserve)}
	case len(failed) > 0:
		return []string{
			fmt.Sprintf("Not ready for %s: %d %s (%s). Fix %s, then run again:", rep.ReadyFor, len(failed),
				plural(len(failed), "check fails", "checks fail"), strings.Join(failed, ", "), plural(len(failed), "it", "them")),
			"  " + verify,
		}
	case rep.Approve != nil:
		if rep.Mode == config.TetragonModeEnforce && rep.Approve.State == "approved" {
			return []string{"Ready: this host runs enforce as its config asks: " + enforceCounts(rep.Users, false)}
		}
		return []string{"Ready for enforce: " + enforceCounts(rep.Users, true),
			"Set the approve block above in your admin config and apply it with your config management."}
	case rep.ReadyFor == rep.Mode:
		return []string{"Ready: this host runs " + rep.Mode + " as its config asks."}
	}
	return []string{"Ready for " + rep.ReadyFor + ". Next: in your admin config set", "  enterprise:", "    tetragon:",
		"      mode: " + rep.ReadyFor, "and apply it with your config management (its ensure run restarts the sensor helper)."}
}

// enforceCounts says how many users enforce denies for (or would, with
// would), how many wait for their burn-in and how many stay monitor-only:
// "1 of 3 users would be enforced now; 1 stays in monitor until its burn-in
// completes; 1 stays monitor-only (connector in observe mode)."
//
// Two limits of the controls cap who is denied (SPEC-TETRAGON-UX, security
// review): a user whose agent is matched only by a process id, and every
// user but the lowest uid when several have a native agent install, stay in
// monitor. Running enforce, the helper names them (noDenyAnchor); in observe
// the count says that enforce denies for one of several ready users.
//
// Running enforce, a user counts as enforced only while the helper says it
// denies for them: one who finished burn-in is held in monitor by a pause or
// an operator's change to the controls policy, and is named so (GAP-0055).
func enforceCounts(users []TetragonUserReadiness, would bool) string {
	ready, monitorOnly, unanchored, held := 0, 0, 0, 0
	limitSet, heldSet := map[string]bool{}, map[string]bool{}
	var holders []string
	for _, user := range users {
		if user.State == kernelpolicy.UIDEnforcing {
			holders = append(holders, userName(kernelpolicy.UIDStatus{UID: user.UID, User: user.User}))
		}
		switch {
		case user.Ready && !would && user.State != kernelpolicy.UIDEnforcing:
			held++
			heldSet[defaultStr(monitorReasonWords[user.Reason], defaultStr(user.Reason, "see tetragon status"))] = true
		case user.Ready:
			ready++
		case user.MonitorOnly:
			monitorOnly++
		case noDenyAnchor(user.State, user.Reason):
			unanchored++
			limitSet[user.Reason] = true
		}
	}
	verb := plural(ready, "is enforced", "are enforced")
	if would {
		verb = "would be enforced now"
	}
	var text string
	switch {
	case would && ready > 1:
		text = fmt.Sprintf("%d of %d %s finished burn-in, and enforce denies for one of them (the lowest uid with a native agent"+
			" install; the others stay in monitor, %s)", ready, len(users), plural(len(users), "user", "users"), kernelpolicy.WarnBinaryScopeLimited)
	case len(users) > 0 && ready == len(users):
		return fmt.Sprintf("every enrolled user (%d) %s.", len(users), strings.Replace(verb, "are", "is", 1))
	default:
		text = fmt.Sprintf("%d of %d %s %s", ready, len(users), plural(len(users), "user", "users"), verb)
	}
	if held > 0 {
		reasons := make([]string, 0, len(heldSet))
		for reason := range heldSet {
			reasons = append(reasons, reason)
		}
		sort.Strings(reasons)
		text += fmt.Sprintf("; %d finished burn-in and %s not enforced now (%s)", held, plural(held, "is", "are"), strings.Join(reasons, ", "))
	}
	if waiting := len(users) - ready - monitorOnly - unanchored - held; waiting > 0 {
		text += fmt.Sprintf("; %d %s in monitor until %s burn-in completes", waiting, plural(waiting, "stays", "stay"), plural(waiting, "its", "their"))
	}
	if unanchored > 0 {
		limits := make([]string, 0, len(limitSet))
		for limit := range limitSet {
			limits = append(limits, limit)
		}
		sort.Strings(limits)
		text += fmt.Sprintf("; %d %s in monitor without a deny anchor (%s)", unanchored, plural(unanchored, "stays", "stay"), strings.Join(limits, ", "))
		if limitSet[kernelpolicy.WarnBinaryScopeLimited] && len(holders) > 0 {
			// Name who holds the one anchor: with an agent under an
			// administrator prefix it can be an account that runs no agent
			// (GAP-0094).
			text += fmt.Sprintf("; %s holds the deny anchor (the lowest uid with a native agent install;"+
				" leave other accounts out with enrollment.exclude_users to move it)", strings.Join(holders, ", "))
		}
	}
	if monitorOnly > 0 {
		text += fmt.Sprintf("; %d %s monitor-only (connector in observe mode)", monitorOnly, plural(monitorOnly, "stays", "stay"))
	}
	return text + "."
}

// noDenyAnchor reports a user that finished burn-in but that the enforcing
// controls cannot deny for: the helper keeps it in monitor and names the
// limit as its reason.
// noDenyAnchor reports a user whom enforce cannot deny for in this release:
// no agent is installed (nothing to anchor), or the agent's only anchor
// never denies. Such a user is never counted ready (GAP-0042: four users
// with no agent made "6 of 7 users are ready").
func noDenyAnchor(state, reason string) bool {
	if state == kernelpolicy.UIDInactive && reason == kernelpolicy.ReasonNoAnchors {
		return true
	}
	return state == kernelpolicy.UIDMonitor && (reason == kernelpolicy.WarnPIDMonitorOnly || reason == kernelpolicy.WarnBinaryScopeLimited)
}

func without(list []string, value string) []string {
	var out []string
	for _, item := range list {
		if item != value {
			out = append(out, item)
		}
	}
	return out
}

// RunTetragonVerify runs `enterprise linux tetragon verify [--ready-for]`.
func RunTetragonVerify(ctx context.Context, env *Env, readyFor string) *TetragonReadiness {
	rep := &TetragonReadiness{SchemaVersion: TetragonVerifySchemaVersion, Action: TetragonActionVerify,
		KernelPolicy: kernelpolicy.Digest(), Checks: []TetragonCheck{}, Users: []TetragonUserReadiness{}, Next: []string{},
		Errors: []enterprisestatus.Message{}}
	fail := func(code int, errCode, message string) *TetragonReadiness {
		rep.Errors = append(rep.Errors, enterprisestatus.Message{Code: errCode, Message: message})
		rep.ExitCode = code
		return rep
	}
	switch {
	case env.GOOS != "linux":
		return fail(enterprisestatus.UnixExitInvalidArgs, codeUnsupportedPlatform, "Tetragon is a Linux sensor; enterprise linux tetragon runs on Linux hosts only")
	case readyFor != "" && modeRank(readyFor) == 0:
		return fail(enterprisestatus.UnixExitInvalidArgs, codeInvalidArguments, fmt.Sprintf("--ready-for %q is not consume, observe or enforce", readyFor))
	case env.Geteuid() != 0:
		return fail(enterprisestatus.UnixExitFailure, codeNotRoot, "run this command as root (sudo or the MDM agent): the sensor helper's state is root-only")
	}
	in, err := env.tetragonInputs(ctx)
	if err != nil {
		return fail(enterprisestatus.UnixExitFailure, codeKernelStateUnreadable, tetragonMessage(codeKernelStateUnreadable, tetragonFacts{Error: err.Error()}))
	}
	if readyFor == "" {
		// The mode the config asks for: the configured one when a cap (Plane
		// C off) holds it at off, so the check names the cap.
		readyFor = in.Intent.helperMode()
		if in.Intent.Reason == config.TetragonReasonPlaneCOff {
			readyFor = in.Intent.Configured
		}
	}
	out := tetragonReadiness(in, readyFor, env.tetragonProbes(ctx), env.Now())
	if !in.HaveIntent {
		out.Errors = append(out.Errors, enterprisestatus.Message{Code: codeConfig,
			Message: "the installed config could not be read or does not validate (the checks use the defaults); see " + literal(adminCommand("enterprise", "linux", "status"))})
	}
	if !out.Ready {
		out.ExitCode = enterprisestatus.UnixExitFailure
	}
	out.OK = out.ExitCode == 0
	return out
}

// tetragonInputs reads everything the findings and the checks need.
func (e *Env) tetragonInputs(ctx context.Context) (tetragonInputs, error) {
	state, err := kernelpolicy.ReadState(e.sensorDirs())
	if err != nil {
		return tetragonInputs{}, err
	}
	intent, haveIntent := e.installedTetragonIntent()
	if !haveIntent {
		intent = tetragonIntentOf(nil, e.GOOS, nil)
	}
	l := &lifecycle{env: e, opts: Options{Action: ActionStatus}, result: enterprisestatus.New(ActionStatus, "standalone", e.GOOS, e.ProductVersion)}
	in := tetragonInputs{GOOS: e.GOOS, Intent: intent, HaveIntent: haveIntent, State: state, Running: l.helperRunning(ctx),
		Host: e.tetragonHost()}
	if intent.PlaneC {
		in.Gateway = l.gatewayPlaneC(ctx)
	}
	return in, nil
}

// tetragonProbes reads the unit state and the kernel's security modules.
func (e *Env) tetragonProbes(ctx context.Context) tetragonProbes {
	probes := tetragonProbes{TetragonActive: e.Services.Active(ctx, Unit{Name: "tetragon.service", Kind: "tetragon"})}
	if data, err := readBounded(e.P(lsmListPath), 4096); err == nil {
		probes.LSM, probes.LSMKnown = strings.TrimSpace(string(data)), true
	}
	return probes
}

// WriteTetragonReadiness prints a readiness report: JSON, or the text view
// (lines within 80 columns; a copy-paste command keeps its own line).
func WriteTetragonReadiness(w io.Writer, rep *TetragonReadiness, asJSON bool) error {
	if asJSON {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(rep)
	}
	if len(rep.Checks) == 0 {
		for _, e := range rep.Errors {
			fmt.Fprintf(w, "✗ %s: %s\n", e.Code, e.Message)
		}
		return nil
	}
	header := "Tetragon readiness for " + rep.ReadyFor
	if rep.Mode != rep.ReadyFor {
		header += " (this host runs " + rep.Mode + ")"
	}
	fmt.Fprintln(w, header)
	for _, check := range rep.Checks {
		mark := map[string]string{checkPass: "✓", checkFail: "✗", checkWarn: "!", checkInfo: "i"}[check.Status]
		if mark == "" {
			continue
		}
		writeWrapped(w, "  "+mark+" ", "    ", sentence(check.Message), 80)
		for _, fix := range check.Fix {
			fmt.Fprintf(w, "      %s\n", fix)
		}
		if check.ID == checkBurnIn && len(rep.Users) > 0 {
			writeBurnInTable(w, rep)
		}
	}
	if a := rep.Approve; a != nil && modeRank(rep.Mode) >= modeRank(config.TetragonModeObserve) &&
		(a.State != "approved" || rep.Mode != config.TetragonModeEnforce) {
		fmt.Fprintln(w, "  Approve this build's kernel controls (same value on every host of it):")
		fmt.Fprintf(w, "    enterprise:\n      tetragon:\n        mode: enforce\n        enforce_ack: %s\n", a.Digest)
		if a.State == "stale" && a.EnforceAck != "" {
			fmt.Fprintf(w, "    # ring upgrade: enforce_ack: [%s, %s]\n", strings.ReplaceAll(a.EnforceAck, ",", ", "), a.Digest)
		}
	}
	for _, e := range rep.Errors {
		writeWrapped(w, "✗ ", "  ", e.Code+": "+e.Message, 80)
	}
	writeNext(w, rep.Next)
	return nil
}

// writeNext prints the next-step lines: a sentence wrapped at 80 columns, a
// copy-paste line (indented) as it is.
func writeNext(w io.Writer, lines []string) {
	for _, line := range lines {
		if strings.HasPrefix(line, " ") {
			fmt.Fprintln(w, line)
			continue
		}
		writeWrapped(w, "", "", line, 80)
	}
}

// writeBurnInTable prints the per-user burn-in of the enforce promotion.
func writeBurnInTable(w io.Writer, rep *TetragonReadiness) {
	needed := "the configured burn-in"
	if len(rep.Users) > 0 && rep.Users[0].NeededHours > 0 {
		needed = trimHours(rep.Users[0].NeededHours) + "h"
	}
	fmt.Fprintf(w, "  Burn-in (%s of agent use, no would-block hit, per user on this host):\n", needed)
	fmt.Fprintf(w, "    %-16s %-21s %-9s %s\n", "USER", "PROGRESS", "ETA", "HITS")
	for _, user := range rep.Users {
		progress, eta := fmt.Sprintf("%3d%%", user.Percent), "-"
		switch {
		case user.Ready:
			progress = "ready"
		case user.MonitorOnly:
			progress, eta = "monitor", "never"
		case user.Reset:
			progress = "reset"
		case user.Measuring:
			eta = "measuring"
		}
		if user.ETAHours != nil && !user.Ready && !user.MonitorOnly {
			eta = humanDuration(time.Duration(*user.ETAHours * float64(time.Hour)))
		}
		hits := 0
		for _, hit := range user.Hits {
			hits += hit.Count
		}
		fmt.Fprintf(w, "    %-16s %6.1fh/%-5s %-7s %-9s %d\n", readinessUserLabel(user), user.CoveredHours,
			trimHours(user.NeededHours)+"h", progress, eta, hits)
		for i, hit := range user.Hits {
			if i == 3 {
				fmt.Fprintf(w, "      and %d more\n", len(user.Hits)-3)
				break
			}
			what := strings.TrimPrefix(hit.Control, "kernel.") + ":"
			if hit.Path != "" {
				what += " " + hit.Path
			}
			if hit.Binary != "" {
				what += " by " + hit.Binary
			}
			fmt.Fprintf(w, "      %s\n", what)
			hold := "Stays in monitor until " + trimHours(user.NeededHours) + "h pass with no hit."
			if user.NeededHours <= 0 {
				// burn_in 0: a hit holds nobody in monitor (GAP-0055).
				hold = "With burn_in 0 a hit does not hold this user in monitor: in enforce this open is denied."
			}
			writeWrapped(w, "        ", "        ", "last "+hit.Last+". "+hold+
				" If the tool is expected, this user cannot be enforced for this control in this release;"+
				" other users are not affected.", 80)
		}
	}
}

func readinessUserLabel(user TetragonUserReadiness) string {
	if user.User != "" {
		return fmt.Sprintf("%s (%d)", user.User, user.UID)
	}
	return fmt.Sprintf("uid %d", user.UID)
}

// trimHours prints whole hours without a fraction.
func trimHours(hours float64) string {
	if hours == math.Trunc(hours) {
		return strconv.FormatFloat(hours, 'f', 0, 64)
	}
	return strconv.FormatFloat(hours, 'f', 1, 64)
}

// writeWrapped prints text after first, wrapped at width with rest as the
// indent of the following lines. A word longer than a line (a path, a
// command) keeps its own line.
func writeWrapped(w io.Writer, first, rest, text string, width int) {
	line := first
	empty := true
	for _, word := range wrapWords.FindAllString(text, -1) {
		if !empty && len([]rune(line))+1+len([]rune(word)) > width {
			fmt.Fprintln(w, line)
			line, empty = rest, true
		}
		if empty {
			line += word
			empty = false
		} else {
			line += " " + word
		}
	}
	fmt.Fprintln(w, line)
}

// wrapWords are the words a line wraps between: a quoted command is one word,
// so it is never broken across lines.
var wrapWords = func() *regexp.Regexp {
	const tick = "`"
	return regexp.MustCompile(tick + "[^" + tick + "]*" + tick + `\S*|\S+`)
}()

// sentence starts a message with a capital letter.
func sentence(text string) string {
	if text != "" && text[0] >= 'a' && text[0] <= 'z' {
		return string(text[0]-'a'+'A') + text[1:]
	}
	return text
}

// ---- burn-in arithmetic ----

// burnInProgress is one enrolled user's burn-in, in the terms an
// administrator plans with: covered agent-hours of the needed ones, and the
// calendar time until ready at the rate so far.
type burnInProgress struct {
	Covered, Needed time.Duration
	// Percent is Covered of Needed, 0-100 (100 when no burn-in is needed).
	Percent int
	Ready   bool
	// ETA is the calendar time until ready; HasETA is false while
	// Measuring (the window is younger than kernelpolicy.ETAMinWindow), with no agent
	// use yet, and for users with no anchored agent.
	ETA       time.Duration
	HasETA    bool
	Measuring bool
	// Reset is set when a would-block hit restarted the window.
	Reset bool
	// NoAgent is set for a user with no anchored agent (nothing accrues).
	NoAgent bool
	// MonitorOnly is set for a user none of whose connectors is in action
	// mode: enforce never denies for them, whatever the burn-in says.
	MonitorOnly bool
}

// progressFor is progressOf with what the installed config says about the
// user's connectors: a user without a command-line connector in action mode
// is monitor-only and has no ETA. Without a readable config it is not known.
func progressFor(user kernelpolicy.UIDStatus, record *kernelpolicy.UIDRecord, in tetragonInputs, now time.Time) burnInProgress {
	p := progressOf(user, record, now)
	if burnInPaused(user.Reason) {
		p.Ready, p.Measuring, p.HasETA = false, false, false
	}
	if monitorOnlyUser(user, in) {
		p.MonitorOnly, p.HasETA, p.ETA = true, false, 0
	}
	return p
}

// burnInPaused reports a user reason under which a live session pauses the
// user's burn-in: one waits for the controls policy to load, or one is over
// the monitor controls' session limit (GAP-0089).
func burnInPaused(reason string) bool {
	return reason == kernelpolicy.WarnSessionPolicyPending || reason == kernelpolicy.WarnRootsOverLimit
}

// monitorOnlyUser reports whether enforce would never deny for user: the
// helper says so (guardrail_observe), or none of its connectors is an
// enrolled command-line connector in action mode in the installed config.
func monitorOnlyUser(user kernelpolicy.UIDStatus, in tetragonInputs) bool {
	if user.State == kernelpolicy.UIDInactive && user.Reason == kernelpolicy.ReasonGuardrailObserve {
		return true
	}
	if !in.HaveIntent {
		return false
	}
	for _, connector := range user.Connectors {
		for _, action := range in.Intent.ActionCLI {
			if connector == action {
				return false
			}
		}
	}
	return true
}

// progressOf computes a user's burn-in from the helper's per-user status and
// burnin.json at now. The ETA is kernelpolicy.BurnInETA's calendar estimate.
func progressOf(user kernelpolicy.UIDStatus, record *kernelpolicy.UIDRecord, now time.Time) burnInProgress {
	p := burnInProgress{
		Covered: time.Duration(user.CoveredSeconds) * time.Second,
		Needed:  time.Duration(user.NeededSeconds) * time.Second,
	}
	p.NoAgent = user.State == kernelpolicy.UIDInactive && user.Reason == kernelpolicy.ReasonNoAnchors
	switch {
	case p.Needed <= 0:
		p.Percent, p.Ready = 100, true
	case p.Covered >= p.Needed:
		p.Percent, p.Ready = 100, true
	default:
		p.Percent = int(math.Floor(100 * float64(p.Covered) / float64(p.Needed)))
	}
	if record != nil && p.Needed > 0 {
		// With burn_in 0 there is no window for a hit to restart: an
		// enforcing user read "reset" (GAP-0056).
		for _, hit := range record.WouldBlock {
			if hit != nil && !hit.Last.IsZero() && !hit.Last.Before(record.WindowStart.Add(-time.Second)) {
				p.Reset = true
			}
		}
	}
	if p.Ready || p.NoAgent || record == nil {
		return p
	}
	p.ETA, p.Measuring, p.HasETA = kernelpolicy.BurnInETA(p.Covered, p.Needed, record.WindowStart, now)
	return p
}

// nextReady is the shortest ETA of the users still in burn-in, as of now; a
// monitor-only user is never ready.
func nextReady(in tetragonInputs, now time.Time) (time.Duration, bool) {
	best, found := time.Duration(0), false
	for _, user := range in.State.UIDs {
		if user.State == kernelpolicy.UIDEnforcing {
			continue
		}
		p := progressFor(user, in.State.BurnIn.UIDs[strconv.Itoa(user.UID)], in, now)
		if p.HasETA && (!found || p.ETA < best) {
			best, found = p.ETA, true
		}
	}
	return best, found
}

// humanDuration is a calendar duration in the words the ETA uses: "~1 hour",
// "~5 hours" under two days, "~9 days" after.
func humanDuration(d time.Duration) string {
	hours := d.Hours()
	switch {
	case hours < 1.5:
		return "~1 hour"
	case hours < 48:
		return fmt.Sprintf("~%d hours", int(math.Round(hours)))
	}
	return fmt.Sprintf("~%d days", int(math.Round(hours/24)))
}
