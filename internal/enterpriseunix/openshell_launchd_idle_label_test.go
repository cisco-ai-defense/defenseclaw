// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// answersOnceLoaded is the account side of a Mac whose account cannot load a
// LaunchAgent itself (the lifecycle asks it through sudo, outside its
// session): its sandbox status answers only once the installed sandbox
// label is loaded in its domain.
type answersOnceLoaded struct {
	*fakeSandboxOps
	f     *fixtureLaunchdRunner
	label func() string
}

func (o answersOnceLoaded) Status(ctx context.Context, a SandboxAccount) (SandboxStatus, error) {
	if job := o.f.jobs[a.UID][o.label()]; job == nil || !job.loaded {
		return SandboxStatus{}, errors.New("exit 1: your sandbox service does not answer")
	}
	return o.fakeSandboxOps.Status(ctx, a)
}

// GAP-0049: the package upgrade renamed both LaunchAgents while the account
// ran a sandbox under the daemon of the earlier label; once that sandbox
// stopped, that daemon exited by itself and nothing loaded the installed
// label: the account's status could not answer, ensure kept waiting and
// repair found nothing to repair. The lifecycle now loads the installed
// sandbox label in place of the earlier one that does not run, the status
// answers, and the earlier gateway job is replaced under the drain, so
// status and verify are healthy after one repair.
func TestMacOSRepairLoadsTheRenamedSandboxAgentAfterTheEarlierDaemonExited(t *testing.T) {
	h, f := newMacOSPackageLaunchdHost(t)
	asMacOSPackageOf103(t, h)
	uid := h.alice.UID
	f.jobs[uid][labelSandbox] = &launchdJobFixture{loaded: true, state: "running", runs: 1}
	f.jobs[uid][labelOpenShellGateway] = &launchdJobFixture{loaded: true, state: "running", runs: 1}
	h.ops.status[uid] = SandboxStatus{Active: true, Running: 1}
	replaceMacOSPackageBinaries(t, h, "1.0.4")
	r := h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package"})
	if len(r.Errors) != 0 || len(f.mutated) != 0 {
		t.Fatalf("running sandboxes were interrupted: %+v %v", r.Errors, f.mutated)
	}
	if entry := h.env.loadOpenShellState().Pending[strconv.Itoa(uid)]; entry.Kind != "launchd" {
		t.Fatalf("the label change was not pending: %+v", entry)
	}
	current := installedAgentLabel(t, h, labelSandbox)
	currentGateway := installedAgentLabel(t, h, labelOpenShellGateway)

	// The sandbox stopped; the earlier daemon exited by itself, its job
	// stays loaded, the earlier gateway job still runs.
	f.jobs[uid][labelSandbox].state = "not running"
	h.ops.status[uid] = SandboxStatus{Active: true}
	h.env.SandboxUsers = answersOnceLoaded{fakeSandboxOps: h.ops, f: f, label: func() string { return current }}
	f.mutated = nil
	repair := h.run(Options{Action: ActionRepair})
	if len(repair.Errors) != 0 {
		t.Fatalf("repair failed: %+v", repair.Errors)
	}
	gui := "gui/" + strconv.Itoa(uid)
	for _, want := range []string{
		"launchctl bootout " + gui + "/" + labelSandbox,
		"launchctl bootstrap " + gui + " " + h.env.P("/Library/LaunchAgents/"+current+".plist"),
		"launchctl bootout " + gui + "/" + labelOpenShellGateway,
		"launchctl bootstrap " + gui + " " + h.env.P("/Library/LaunchAgents/"+currentGateway+".plist"),
	} {
		if !slices.Contains(f.mutated, want) {
			t.Fatalf("repair did not run %q; mutations %v", want, f.mutated)
		}
	}
	if entry, waiting := h.env.loadOpenShellState().Pending[strconv.Itoa(uid)]; waiting {
		t.Fatalf("the label change still waits: %+v", entry)
	}
	if !strings.Contains(strings.Join(repair.Changes, "\n"), "which does not run") {
		t.Fatalf("repair changes do not name the replaced idle job: %v", repair.Changes)
	}
	// The fixture host has no hook guardian ledger, which verify reports
	// on its own: only the sandbox rows matter here.
	verify := h.run(Options{Action: ActionVerify})
	for _, e := range verify.Errors {
		if strings.Contains(e.Message, "sandbox") || strings.Contains(e.Message, "LaunchAgent") {
			t.Fatalf("verify after repair: %+v", verify.Errors)
		}
	}
	status := h.run(Options{Action: ActionStatus})
	if got := messagesOf(status.Warnings, codeSandboxUserState) + messagesOf(status.Warnings, codeSandboxPending); strings.Contains(got, "earlier") || strings.Contains(got, "waits") {
		t.Fatalf("status still warns: %q", got)
	}
}

// A sandbox job of the earlier label that runs is never replaced this way:
// it is the daemon of a sandbox that may still run.
func TestMacOSRunningEarlierSandboxAgentIsNotReplacedBeforeItsSandboxesStop(t *testing.T) {
	h, f := newMacOSPackageLaunchdHost(t)
	asMacOSPackageOf103(t, h)
	uid := h.alice.UID
	f.jobs[uid][labelSandbox] = &launchdJobFixture{loaded: true, state: "running", runs: 1}
	f.jobs[uid][labelOpenShellGateway] = &launchdJobFixture{loaded: true, state: "running", runs: 1}
	h.ops.status[uid] = SandboxStatus{Active: true, Running: 1}
	replaceMacOSPackageBinaries(t, h, "1.0.4")
	_ = h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package"})
	f.mutated = nil
	_ = h.run(Options{Action: ActionRepair})
	if len(f.mutated) != 0 {
		t.Fatalf("a running earlier daemon was replaced: %v", f.mutated)
	}
}
