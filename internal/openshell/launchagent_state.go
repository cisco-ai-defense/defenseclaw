// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package openshell

import (
	"context"
	"strconv"
	"strings"
	"time"
)

// LaunchAgentState contains the service fields needed to judge an on-demand
// launchd job. A loaded job can be idle before its first start or after a
// clean exit.
type LaunchAgentState struct {
	State, ExitReason, ExitCode, SpawnError string
	Runs                                    int
}

// ParseLaunchAgentState reads the service fields from launchctl print output.
func ParseLaunchAgentState(raw []byte) LaunchAgentState {
	var s LaunchAgentState
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		key, value, ok := strings.Cut(line, " = ")
		if !ok {
			continue
		}
		switch key {
		case "state":
			if s.State == "" {
				s.State = value
			}
		case "runs":
			s.Runs, _ = strconv.Atoi(value)
		case "last exit reason":
			s.ExitReason = value
		case "last exit code":
			s.ExitCode = value
		case "last spawn error":
			s.SpawnError = value
		}
	}
	return s
}

// Failure reports a failed start, allowing a cleanly idle on-demand job.
// A currently running job is healthy even if launchd kept an older exit reason.
func (s LaunchAgentState) Failure(expectedRunning bool) string {
	if s.State == "running" {
		return ""
	}
	if s.CodeSigningKilled() {
		return "last start was killed for code signing (" + strings.TrimSpace(s.ExitReason+" "+s.SpawnError) + ")"
	}
	if s.SpawnError != "" {
		return "last spawn error: " + s.SpawnError
	}
	if expectedRunning {
		return "loaded but not running when it must be running"
	}
	return ""
}

// CodeSigningKilled reports a job that is not running because macOS killed
// or refused its last start for code signing (OS_REASON_CODESIGNING).
func (s LaunchAgentState) CodeSigningKilled() bool {
	return s.State != "running" && (strings.Contains(strings.ToUpper(s.ExitReason), "CODESIGN") || strings.Contains(strings.ToUpper(s.SpawnError), "CODESIGN"))
}

// Notice describes an idle job's previous exit without treating an on-demand
// start as a failed LaunchAgent. EX_CONFIG is the exec shim's deliberate exit
// when an account prerequisite is missing or untrusted.
func (s LaunchAgentState) Notice() string {
	if s.State != "not running" {
		return ""
	}
	code, _, _ := strings.Cut(strings.TrimSpace(s.ExitCode), ":")
	code, _, _ = strings.Cut(strings.TrimSpace(code), " ")
	n, err := strconv.Atoi(code)
	if err != nil || n == 0 {
		return ""
	}
	if n == 78 {
		return "last exit code 78 (EX_CONFIG): a prerequisite of this account is missing, so the last start stopped on purpose"
	}
	return "last exit code " + strconv.Itoa(n)
}

// CheckIDManagedLaunchAgent is the managed Mac's current-user gateway job.
const CheckIDManagedLaunchAgent = "managed-openshell-launchagent"

// managedLaunchAgentsDir is where the gateway job's plist is; a var for tests.
var managedLaunchAgentsDir = LaunchAgentsDir

// ManagedLaunchAgentCheck reads the current user's loaded gateway job in both
// launchd domains; an ssh session can leave it in user/<uid>.
// The administrator's enterprise repair owns all launchctl mutations.
func (d *Doctor) ManagedLaunchAgentCheck(ctx context.Context) *Check {
	if !d.Managed || d.GOOS != "darwin" {
		return nil
	}
	d.defaults()
	uid := strconv.Itoa(d.Geteuid())
	label, _ := FindLaunchAgent(managedLaunchAgentsDir, GatewayAgentBase)
	var failed, warning, healthy *Check
	for _, domain := range []string{"gui/" + uid, "user/" + uid} {
		target := domain + "/" + label
		raw, err := d.Runner.Output(ctx, Command{Name: "launchctl", Args: []string{"print", target}, Timeout: 10 * time.Second})
		if err != nil && launchAgentMissing(raw, err) {
			continue
		}
		c := &Check{ID: CheckIDManagedLaunchAgent, Title: "OpenShell LaunchAgent"}
		if err != nil {
			c.Status, c.Detail = StatusWarn, "could not inspect "+target+": "+err.Error()
			if warning == nil {
				warning = c
			}
			continue
		}
		state := ParseLaunchAgentState(raw)
		if state.State == "" {
			c.Status, c.Detail = StatusWarn, "launchctl returned no service state for "+target
			if warning == nil {
				warning = c
			}
			continue
		}
		if why := state.Failure(false); why != "" {
			c.Status, c.Detail = StatusFail, target+" failed: "+why
			c.Fix = &Fix{Summary: "ask your administrator to repair this computer's sandbox LaunchAgent", Command: "sudo defenseclaw-gateway enterprise macos repair", Sudo: true}
			if failed == nil {
				failed = c
			}
			continue
		}
		if notice := state.Notice(); notice != "" {
			c.Status, c.Detail = StatusWarn, target+" is loaded and idle: "+notice+"; see the other doctor rows for the account prerequisite"
			if warning == nil {
				warning = c
			}
			continue
		}
		c.Status = StatusPass
		if state.State == "running" {
			c.Detail = target + " is running"
		} else {
			c.Detail = target + " is loaded and idle; starts with the next sandbox command"
		}
		if healthy == nil {
			healthy = c
		}
	}
	if failed != nil {
		return failed
	}
	if warning != nil {
		return warning
	}
	return healthy
}

func launchAgentMissing(raw []byte, err error) bool {
	message := strings.ToLower(string(raw) + " " + err.Error())
	return strings.Contains(message, "could not find service") || strings.Contains(message, "could not find domain") || strings.Contains(message, "no such process")
}
