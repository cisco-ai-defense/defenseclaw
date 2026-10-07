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
// /sys/kernel/security/lsm and the unit states. Exit 0 when no check fails, 1
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
	checkOrphans            = "defenseclaw.orphans"
	checkTetragonYourPolicy = "tetragon.your_policies"
)

// tetragonCheckIDs lists every check in the order it prints.
var tetragonCheckIDs = []string{
	checkTetragonInstalled, checkTetragonRunning, checkTetragonAPI, checkTetragonSocket, checkTetragonVersion,
	checkTetragonStream, checkKeepSensorsOnExit, checkBPFLSM, checkMetricsLoopback, checkHealthLoopback,
	checkPlaneC, checkAgents, checkConnectorsAction, checkApproval, checkBurnIn, checkPause, checkOverrides,
	checkOrphans, checkTetragonYourPolicy,
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
	Mode         string                  `json:"mode"`
	ReadyFor     string                  `json:"ready_for"`
	Ready        bool                    `json:"ready"`
	KernelPolicy string                  `json:"kernel_policy"`
	Checks       []TetragonCheck         `json:"checks"`
	Users        []TetragonUserReadiness `json:"users"`
	Approve      *TetragonApproval       `json:"approve,omitempty"`
	// Next are the lines of the next step, as printed.
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
	CoveredHours float64 `json:"covered_hours"`
	NeededHours  float64 `json:"needed_hours"`
	Percent      int     `json:"percent"`
	Ready        bool    `json:"ready"`
	Reset        bool    `json:"reset"`
	Measuring    bool    `json:"measuring"`
	// ETAHours is the calendar time until ready at the user's rate so far;
	// absent while measuring, without agent use, and once ready.
	ETAHours *float64            `json:"eta_hours,omitempty"`
	Hits     []TetragonHitDetail `json:"hits"`
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
			setEnforceKernelChecks(set, state, probes, restart)
		} else {
			skip(checkKeepSensorsOnExit, "only enforce needs it")
			skip(checkBPFLSM, "only enforce needs it")
		}
		metrics, metricsKnown := in.Extra.Tetragon.MetricsAddress, in.Extra.Tetragon.MetricsAddress != ""
		if !metricsKnown {
			metrics, metricsKnown = host.MetricsAddress, host.MetricsKnown
		}
		health := defaultStr(in.Extra.Tetragon.HealthAddress, host.HealthAddress)
		setLoopbackCheck(set, checkMetricsLoopback, "metrics", metrics, metricsKnown, "127.0.0.1:2112", "metrics-server", restart,
			" (without metrics, events lost reads unknown)")
		setLoopbackCheck(set, checkHealthLoopback, "health", health, health != "", "127.0.0.1:6789", "health-server-address", restart, "")
	}

	// DefenseClaw.
	if intent.PlaneC {
		set(checkPlaneC, checkPass, "AI Discovery Plane C is on")
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
	} else {
		skip(checkAgents, "only observe and enforce need it")
		skip(checkPause, "only observe and enforce need it")
		skip(checkOverrides, "only observe and enforce need it")
	}
	if rank >= modeRank(config.TetragonModeEnforce) {
		setConnectorsCheck(set, intent)
		rep.Users = readinessUsers(state, now)
		rep.Approve = approvalFor(intent, rep.Users)
		switch rep.Approve.State {
		case "approved":
			set(checkApproval, checkPass, "enforce_ack approves this build's kernel controls ("+rep.KernelPolicy+")")
		case "stale":
			set(checkApproval, checkInfo, "The approval (enforce_ack "+intent.ack()+") does not include this build's "+rep.KernelPolicy+"; approve it (below)")
		default:
			set(checkApproval, checkInfo, "this build's kernel controls are not approved yet; approve them (below)")
		}
		set(checkBurnIn, checkInfo, fmt.Sprintf("%d of %d enrolled users finished burn-in on this host", rep.Approve.ReadyUsers, rep.Approve.Users))
	} else {
		for _, id := range []string{checkConnectorsAction, checkApproval, checkBurnIn} {
			skip(id, "only enforce needs it")
		}
	}
	setOrphansCheck(set, in)
	setYourPoliciesCheck(set, in)
	return finishReadiness(rep, checks)
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
			set(checkTetragonSocket, checkPass, "the socket and its directory are root-owned and not world-writable")
		case host.UntrustedPath != "":
			set(checkTetragonSocket, checkFail, host.UntrustedPath+" must be owned by root and not writable by others (found owner "+
				host.UntrustedOwner+", mode "+host.UntrustedPerm+"); restart Tetragon so it recreates the socket", restart)
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

func setEnforceKernelChecks(set func(id, status, message string, fix ...string), state kernelpolicy.State, probes tetragonProbes, restart string) {
	switch keep := state.Tetragon.KeepSensorsOnExit; {
	case keep != nil && !*keep:
		set(checkKeepSensorsOnExit, checkPass, "Tetragon does not keep sensors on exit")
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
	set(checkAgents, checkPass, message)
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

func setConnectorsCheck(set func(id, status, message string, fix ...string), intent tetragonIntent) {
	switch {
	case len(intent.ActionCLI)+len(intent.ObserveCLI) == 0:
		set(checkConnectorsAction, checkWarn, "no command-line connector is enrolled (a kernel control anchors only command-line agents)")
	case len(intent.ObserveCLI) > 0:
		fix := make([]string, 0, len(intent.ObserveCLI))
		for _, connector := range intent.ObserveCLI {
			fix = append(fix, "guardrail.connectors."+connector+".mode: action")
		}
		set(checkConnectorsAction, checkWarn, strings.Join(intent.ObserveCLI, ", ")+" "+plural(len(intent.ObserveCLI), "is", "are")+
			" in observe mode (their agents stay monitor-only); set the mode in the admin config and apply it, or accept monitor-only", fix...)
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
	policies := in.Extra.CustomerPolicies
	enforcing := 0
	for _, policy := range policies {
		if policy.enforcing() {
			enforcing++
		}
	}
	message := "DefenseClaw never changes your own Tetragon policies; it reads their events"
	if len(policies) > 0 {
		message = fmt.Sprintf("%d of your Tetragon policies %s loaded (%d enforcing); DefenseClaw reads their events and never changes them",
			len(policies), plural(len(policies), "is", "are"), enforcing)
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

// readinessUsers are the enrolled users' burn-in, in uid order.
func readinessUsers(state kernelpolicy.State, now time.Time) []TetragonUserReadiness {
	out := []TetragonUserReadiness{}
	users := append([]kernelpolicy.UIDStatus(nil), state.UIDs...)
	sort.Slice(users, func(i, j int) bool { return users[i].UID < users[j].UID })
	for _, user := range users {
		record := state.BurnIn.UIDs[strconv.Itoa(user.UID)]
		p := progressOf(user, record, now)
		view := TetragonUserReadiness{
			UID: user.UID, User: user.User, State: user.State, CoveredHours: roundHours(p.Covered), NeededHours: roundHours(p.Needed),
			Percent: p.Percent, Ready: p.Ready || user.State == kernelpolicy.UIDEnforcing, Reset: p.Reset, Measuring: p.Measuring,
			Hits: hitDetails(record, user.UID),
		}
		if p.HasETA {
			hours := roundHours(p.ETA)
			view.ETAHours = &hours
		}
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
	case len(failed) > 0:
		return []string{
			fmt.Sprintf("Not ready for %s: %d %s (%s). Fix %s, then run again:", rep.ReadyFor, len(failed),
				plural(len(failed), "check fails", "checks fail"), strings.Join(failed, ", "), plural(len(failed), "it", "them")),
			"  " + verify,
		}
	case rep.Approve != nil:
		a := rep.Approve
		summary := fmt.Sprintf("Ready for enforce: %d of %d users would be enforced now; the others stay in monitor until their burn-in completes.", a.ReadyUsers, a.Users)
		if a.Users > 0 && a.ReadyUsers == a.Users {
			summary = fmt.Sprintf("Ready for enforce: every enrolled user (%d) would be enforced now.", a.Users)
		}
		if rep.Mode == config.TetragonModeEnforce && a.State == "approved" {
			summary = strings.Replace(summary, "would be enforced now", "is enforced or enforcing as its burn-in completes", 1)
			return []string{"Ready: this host runs enforce as its config asks. " + summary}
		}
		return []string{summary, "Set the approve block above in your admin config and apply it with your config management."}
	case rep.ReadyFor == rep.Mode:
		return []string{"Ready: this host runs " + rep.Mode + " as its config asks."}
	}
	return []string{"Ready for " + rep.ReadyFor + ". Next: in your admin config set", "  enterprise:", "    tetragon:",
		"      mode: " + rep.ReadyFor, "and apply it with your config management (its ensure run restarts the sensor helper)."}
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
	return tetragonInputs{GOOS: e.GOOS, Intent: intent, HaveIntent: haveIntent, State: state, Running: l.helperRunning(ctx),
		Host: e.tetragonHost(), Extra: e.readHelperExtras()}, nil
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
	if a := rep.Approve; a != nil && (a.State != "approved" || rep.Mode != config.TetragonModeEnforce) {
		fmt.Fprintln(w, "  Approve this build's kernel controls (same value on every host of it):")
		fmt.Fprintf(w, "    enterprise:\n      tetragon:\n        mode: enforce\n        enforce_ack: %s\n", a.Digest)
		if a.State == "stale" && a.EnforceAck != "" {
			fmt.Fprintf(w, "    # ring upgrade: enforce_ack: [%s, %s]\n", strings.ReplaceAll(a.EnforceAck, ",", ", "), a.Digest)
		}
	}
	for _, e := range rep.Errors {
		writeWrapped(w, "✗ ", "  ", e.Code+": "+e.Message, 80)
	}
	for _, line := range rep.Next {
		fmt.Fprintln(w, line)
	}
	return nil
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
		case user.Reset:
			progress = "reset"
		case user.Measuring:
			eta = "measuring"
		}
		if user.ETAHours != nil && !user.Ready {
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
			writeWrapped(w, "        ", "        ", "last "+hit.Last+". Stays in monitor until "+trimHours(user.NeededHours)+
				"h pass with no hit. If the tool is expected, this user cannot be enforced for this control in this release;"+
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
	if record != nil {
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

// nextReady is the shortest ETA of the users still in burn-in, as of now.
func nextReady(state kernelpolicy.State, now time.Time) (time.Duration, bool) {
	best, found := time.Duration(0), false
	for _, user := range state.UIDs {
		if user.State == kernelpolicy.UIDEnforcing {
			continue
		}
		p := progressOf(user, state.BurnIn.UIDs[strconv.Itoa(user.UID)], now)
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
