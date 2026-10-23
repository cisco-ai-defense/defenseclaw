// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

func TestMacOSIdleLaunchAgentExitIsWarningWithoutReload(t *testing.T) {
	for _, tc := range []struct {
		name, code, warning string
	}{
		{name: "EX_CONFIG prerequisite", code: "78: EX_CONFIG", warning: "prerequisite of this account"},
		{name: "other exit", code: "1", warning: "last exit code 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, f, cfg := newLaunchdTestHost(t)
			job := &launchdJobFixture{loaded: true, state: "not running", code: "0", runs: 1}
			f.jobs[h.alice.UID][h.env.launchAgentLabel(labelOpenShellGateway)] = job
			runAction := func(action string) *enterprisestatus.Result {
				if action == ActionEnsure {
					return h.ensure(cfg)
				}
				return h.run(Options{Action: action})
			}
			for _, action := range []string{ActionStatus, ActionVerify, ActionEnsure, ActionRepair} {
				job.code = "0"
				baseline := runAction(action)
				job.code = tc.code
				r := runAction(action)
				warning := messagesOf(r.Warnings, codeSandboxUserState)
				var services []string
				for _, s := range r.Services {
					if strings.Contains(s.Name, h.env.launchAgentLabel(labelOpenShellGateway)) {
						services = append(services, s.State)
					}
				}
				if messagesOf(r.Errors, codeSandboxUserState) != "" || len(r.Errors) != len(baseline.Errors) || r.ExitCode != baseline.ExitCode || r.SecurityComplete != baseline.SecurityComplete || !strings.Contains(warning, tc.warning) || len(f.mutated) != 0 || len(h.env.loadOpenShellState().Pending) != 0 {
					t.Fatalf("%s treated idle exit as failed: errors=%+v exit=%d baseline_exit=%d security_complete=%v baseline_security=%v warning=%q mutations=%v pending=%+v", action, r.Errors, r.ExitCode, baseline.ExitCode, r.SecurityComplete, baseline.SecurityComplete, warning, f.mutated, h.env.loadOpenShellState().Pending)
				}
				if len(services) != 1 || strings.HasPrefix(services[0], "failed:") || !strings.Contains(services[0], tc.warning) {
					t.Fatalf("%s service row=%v", action, services)
				}
			}
			seeded := &enterprisestatus.Result{SecurityComplete: true}
			(&lifecycle{env: h.env, opts: Options{Action: ActionStatus}, result: seeded}).describeMacOSAgents(context.Background())
			if !seeded.SecurityComplete || len(seeded.Errors) != 0 {
				t.Fatalf("idle warning made a complete machine incomplete: %+v", seeded)
			}
		})
	}
}

func TestMacOSPackageReloadsIdleExit78OnlyForNewIdentity(t *testing.T) {
	h, f := newMacOSPackageLaunchdHost(t)
	f.jobs[h.alice.UID][h.env.launchAgentLabel(labelOpenShellGateway)] = &launchdJobFixture{loaded: true, state: "not running", code: "78: EX_CONFIG", runs: 1}
	replaceMacOSPackageBinaries(t, h, "1.0.2")
	r := h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package"})
	if len(r.Errors) != 0 || len(f.mutated) != 2 || !strings.Contains(f.mutated[0], "bootout") || !strings.Contains(f.mutated[1], "bootstrap") {
		t.Fatalf("changed binary did not refresh idle job without kickstart: errors=%+v calls=%v", r.Errors, f.mutated)
	}
	f.mutated = nil
	r = h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package"})
	if len(r.Errors) != 0 || len(f.mutated) != 0 || len(h.env.loadOpenShellState().Pending) != 0 {
		t.Fatalf("same identity retried the idle job: errors=%+v calls=%v pending=%+v", r.Errors, f.mutated, h.env.loadOpenShellState().Pending)
	}
}

func TestMacOSIdleLaunchAgentNeverExitedIsNotFailure(t *testing.T) {
	h, f, _ := newLaunchdTestHost(t)
	f.jobs[h.alice.UID][h.env.launchAgentLabel(labelOpenShellGateway)] = &launchdJobFixture{loaded: true, state: "not running", code: "(never exited)", runs: 3}
	r := h.run(Options{Action: ActionRepair})
	if messagesOf(r.Errors, codeSandboxUserState) != "" || len(f.mutated) != 0 || len(h.env.loadOpenShellState().Pending) != 0 {
		t.Fatalf("idle job treated as failure: errors=%+v calls=%v pending=%+v", r.Errors, f.mutated, h.env.loadOpenShellState().Pending)
	}
}

func TestMacOSLaunchAgentFailureStatesStillFail(t *testing.T) {
	for _, tc := range []struct {
		name, reason, spawn string
		running             int
	}{
		{name: "code signing exit reason", reason: "OS_REASON_CODESIGNING"},
		{name: "other spawn error", spawn: "permission denied"},
		{name: "gateway down while sandbox runs", running: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, f, _ := newLaunchdTestHost(t)
			f.jobs[h.alice.UID][h.env.launchAgentLabel(labelOpenShellGateway)] = &launchdJobFixture{loaded: true, state: "not running", reason: tc.reason, spawn: tc.spawn, code: "0", runs: 1}
			if tc.running > 0 {
				h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Running: tc.running}
			}
			r := h.run(Options{Action: ActionStatus})
			if message := messagesOf(r.Errors, codeSandboxUserState); message == "" || !strings.Contains(message, strconv.Itoa(h.alice.UID)) || r.SecurityComplete {
				t.Fatalf("missed failed state: errors=%+v security_complete=%v", r.Errors, r.SecurityComplete)
			}
		})
	}
}
