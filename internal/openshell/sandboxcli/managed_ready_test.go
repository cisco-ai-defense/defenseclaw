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

//go:build !windows

package sandboxcli

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// A managed computer whose organization runs sandboxes but whose account's
// OpenShell is not installed or started yet: the run asks the daemon to
// ready it, then runs, with the openshell CLI the daemon installed; status
// and doctor say the first run readies it (GAP-0437, GAP-0441). An
// organization's unavailability is refused without readying anything.
func TestRunReadiesManagedOpenShellAtFirstRun(t *testing.T) {
	ta := newTestApp(t, "")
	gw := ta.daemon.status.Gateway
	ta.daemon.status.Available, ta.daemon.status.Gateway = false, nil
	ta.daemon.status.Reason = "the OpenShell gateway is not available: openshell: no gateway registration found"
	ta.daemon.status.Managed = managedStatusFixture()
	cli := ""
	ta.daemon.onReady = func(st *sandboxapi.Status) {
		st.Available, st.Reason, st.Gateway = true, "", gw
		cli = ta.home + "/.local/bin/openshell"
	}
	ta.OpenShellCLI = func() string { return cli }

	ta.printStatus(&ta.daemon.status)
	has(t, ta.output(), "OpenShell isn't installed for your account yet: your first `defenseclaw sandbox run` installs OpenShell 0.1.3 and starts its gateway")
	if c := ta.probeDaemon(bg, true).check; c.Status != openshell.StatusPass {
		t.Fatalf("doctor daemon row before the first run: %+v", c)
	}

	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude", Rm: true}))
	if r, c := ta.daemon.callsTo("POST", sandboxapi.PathReady), ta.daemon.callsTo("POST", sandboxapi.PathSandboxes); len(r) != 1 || len(c) != 1 {
		t.Fatalf("ready calls %d, create calls %d", len(r), len(c))
	} else if string(r[0].Body) != `{"harness":"claudecode"}` {
		t.Fatalf("ready request = %s, want the run's harness", r[0].Body)
	}
	has(t, ta.output()+ta.err.String(), "Installing OpenShell 0.1.3 for your account and starting it (first run only)")
	if ta.Cfg.OpenShell.Binary != cli {
		t.Fatalf("openshell CLI after ready = %q", ta.Cfg.OpenShell.Binary)
	}
	// Installed: the daemon stops the gateway while no sandbox runs, and
	// the next run starts it, installing nothing (GAP-0465).
	ta.daemon.status.Available = false
	ta.printStatus(&ta.daemon.status)
	has(t, ta.output(), "your OpenShell gateway starts with your next `defenseclaw sandbox run`")

	off := newTestApp(t, "")
	off.daemon.status.Available, off.daemon.status.Managed = false, managedStatusFixture()
	off.daemon.status.Managed.Unavailable = "OpenShell is not installed on this computer"
	err := off.Run(bg, RunOptions{Harness: "claude"})
	if err == nil || !strings.Contains(err.Error(), "sandboxes are unavailable") {
		t.Fatalf("unavailable run: %v", err)
	}
	if r := off.daemon.callsTo("POST", sandboxapi.PathReady); len(r) != 0 {
		t.Fatalf("an unavailable computer readied OpenShell: %d calls", len(r))
	}
}

// A first run that the run's own policy forbids (here a pack whose
// harness.allowed leaves the agent out) is refused before the daemon
// readies anything: no OpenShell is installed or started for a run that
// cannot go ahead (GAP-0812).
func TestAForbiddenFirstManagedRunReadiesNothing(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.status.Available, ta.daemon.status.Gateway = false, nil
	ta.daemon.status.Managed = managedStatusFixture()
	ta.daemon.explain.Violations = []sandboxapi.Violation{{Key: "harness", Fatal: true, Admin: true,
		Constraint: "harness.allowed", Message: "codex is not an allowed harness of pack team-pack"}}
	err := ta.Run(bg, RunOptions{Harness: "codex", Pack: "team-pack"})
	if err == nil || !strings.Contains(err.Error(), "codex is not an allowed harness of pack team-pack") {
		t.Fatalf("forbidden first run: %v", err)
	}
	if r := ta.daemon.callsTo("POST", sandboxapi.PathReady); len(r) != 0 {
		t.Fatalf("a forbidden first run readied OpenShell: %d ready calls", len(r))
	}
}

// A run's ready names the run's own agent, so the daemon asks only that
// agent's policy view (S2 review, loop round 2).
func TestRunReadiesTheRequestedManagedHarness(t *testing.T) {
	ta := newTestApp(t, "")
	gw := ta.daemon.status.Gateway
	ta.daemon.status.Available, ta.daemon.status.Gateway = false, nil
	ta.daemon.status.Managed = managedStatusFixture()
	ta.daemon.onReady = func(st *sandboxapi.Status) {
		st.Available, st.Gateway = true, gw
	}
	api, err := ta.api()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ta.preflight(bg, api, sandboxapi.ReadyRequest{Harness: "codex"}, nil); err != nil {
		t.Fatal(err)
	}
	ready := ta.daemon.callsTo("POST", sandboxapi.PathReady)
	if len(ready) != 1 || string(ready[0].Body) != `{"harness":"codex"}` {
		t.Fatalf("codex ready request = %+v", ready)
	}
}

// GAP-1551: a run's ready names its --pack, which the daemon judges the
// agent under.
func TestRunReadiesWithTheRunsPack(t *testing.T) {
	ta := newTestApp(t, "")
	gw := ta.daemon.status.Gateway
	ta.daemon.status.Available, ta.daemon.status.Gateway = false, nil
	ta.daemon.status.Managed = managedStatusFixture()
	ta.daemon.onReady = func(st *sandboxapi.Status) { st.Available, st.Gateway = true, gw }
	_ = ta.Run(bg, RunOptions{Harness: "codex", Pack: "codex-pack"})
	ready := ta.daemon.callsTo("POST", sandboxapi.PathReady)
	if len(ready) != 1 || string(ready[0].Body) != `{"harness":"codex","pack":"codex-pack"}` {
		t.Fatalf("ready request = %+v", ready)
	}
}

// GAP-1552: when the run's policy view is provisional (the directory did not
// answer, off VPN), the ready waits for it before it starts anything; the
// run says so instead of pausing without a word.
func TestAProvisionalRunSaysItWaitsForTheDirectory(t *testing.T) {
	ta := newTestApp(t, "")
	gw := ta.daemon.status.Gateway
	ta.daemon.status.Available, ta.daemon.status.Gateway = false, nil
	ta.daemon.status.Managed = managedStatusFixture()
	ta.daemon.explain.Managed = managedExplainFixture()
	ta.daemon.explain.Managed.Provisional = true
	ta.daemon.onReady = func(st *sandboxapi.Status) { st.Available, st.Gateway = true, gw }
	_ = ta.Run(bg, RunOptions{Harness: "codex"})
	has(t, ta.output(), "your organization's directory did not answer, so DefenseClaw waits up to 10s for your sandbox policy")
}

// While another account's sandboxes hold the one gateway port, a run is
// refused with the one-account-at-a-time text and the contact, readies
// nothing, and status and doctor say the same, not certificates and CAs
// (GAP-0461).
func TestRunWhileAnotherAccountUsesSandboxes(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.status.Available, ta.daemon.status.Gateway = false, nil
	ta.daemon.status.Managed = managedStatusFixture()
	ta.daemon.status.GatewayElsewhere = "another account"
	ta.daemon.status.Reason = sandboxapi.AccountBusyMessage + " (one account at a time). Try again when that account has no sandbox running."
	err := ta.Run(bg, RunOptions{Harness: "claude"})
	if err == nil || !strings.Contains(err.Error(), "one account at a time") || !strings.Contains(err.Error(), "For help, contact it-security@example.com") ||
		strings.Contains(err.Error(), "certificate") {
		t.Fatalf("run: %v", err)
	}
	// The one ready call is the run telling its daemon about the refusal, so
	// the managed audit records account_busy (GAP-0598); the daemon answers
	// busy at once and starts nothing, and no sandbox is created.
	if r, c := ta.daemon.callsTo("POST", sandboxapi.PathReady), ta.daemon.callsTo("POST", sandboxapi.PathSandboxes); len(r) != 1 || len(c) != 0 {
		t.Fatalf("while another account holds the port: %d ready calls, %d create calls; want 1 and 0", len(r), len(c))
	}
	ta.printStatus(&ta.daemon.status)
	has(t, ta.output(), managedAccountBusyText)
	if c := ta.probeDaemon(bg, true).check; c.Status != openshell.StatusWarn || !strings.Contains(c.Detail, "one account at a time") {
		t.Fatalf("doctor daemon row: %+v", c)
	}
}

// GAP-0613: an engine the shell names only with DOCKER_HOST answers the
// doctor but not the sandbox daemon, which uses the account's current
// Docker context. The doctor warns and the launch refusal says what to do.
func TestManagedMacDockerHostOfTheShellIsNamed(t *testing.T) {
	withManagedHost(t)
	t.Setenv("DOCKER_HOST", "unix:///Users/ent-frank/.colima/default/docker.sock")
	ta := newTestApp(t, "")
	m := managedStatusFixture()
	ta.DockerEngine = func(context.Context) (string, error) { return "Ubuntu 24.04.4 LTS", nil }
	c := ta.managedDockerCheck(bg, m)
	if c.Status != openshell.StatusWarn || c.Fix == nil {
		t.Fatalf("doctor row with the shell's DOCKER_HOST: %+v", c)
	}
	has(t, c.Fix.Summary, "docker context create", "docker context use")

	ta = newTestApp(t, "")
	ta.daemon.status.Managed = managedStatusFixture()
	ta.daemon.status.Gateway.Driver = "vm"
	ta.daemon.explain.VMFirstBoot = true
	ta.daemon.errors["POST "+sandboxapi.PathSandboxes] = &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Detail: "docker_unavailable",
		Message: sandboxapi.DockerUnavailable("permission denied", "it-security@example.com")}
	err := ta.ManagedError(bg, ta.Run(bg, RunOptions{Harness: "claude"}))
	if err == nil || !strings.Contains(err.Error(), "Your shell sets DOCKER_HOST") || !strings.Contains(err.Error(), "docker context use") {
		t.Fatalf("launch refusal = %v", err)
	}
}

// On a managed Mac the doctor checks that Docker answers for the account:
// its agent images are built there (GAP-0443).
func TestManagedMacDoctorChecksDocker(t *testing.T) {
	t.Setenv("DOCKER_HOST", "")
	ta := newTestApp(t, "")
	m := managedStatusFixture()
	ta.DockerEngine = func(context.Context) (string, error) { return "", errors.New("Cannot connect to the Docker daemon") }
	c := ta.managedDockerCheck(bg, m)
	if c.Status != openshell.StatusFail || c.Fix == nil {
		t.Fatalf("no Docker: %+v", c)
	}
	has(t, c.Fix.Summary, "start Docker Desktop", "contact it-security@example.com")
	ta.DockerEngine = func(context.Context) (string, error) { return "Docker Desktop", nil }
	if c := ta.managedDockerCheck(bg, m); c.Status != openshell.StatusPass {
		t.Fatalf("Docker answers: %+v", c)
	}
}

// On a managed computer a copy is staged with the copy policy the daemon
// answers (the organization's pack, which this process cannot read), never
// with a local resolve of the pack by name; without one it refuses
// (GAP-0478).
func TestManagedCopyStagesWithTheDaemonsPolicy(t *testing.T) {
	ta := newTestApp(t, "")
	ta.Cfg.DeploymentMode = string(config.DeploymentModeManagedEnterprise)
	ta.Cfg.Enterprise.Profile = managed.ProfileStandalone
	ws := &sandboxapi.WorkspacePolicy{Masks: []string{".env", "certs/*.{pem,key}"}, Unmask: []string{".env.example"}, GitDepth: 5, MaxUploadMB: 10}
	opts, err := ta.copyStageOptions(packs.Flags{Pack: "contractors", Project: ta.project}, "dc-claude-a", ws)
	if err != nil || !slices.Equal(opts.Masks, ws.Masks) || !slices.Equal(opts.Unmask, ws.Unmask) || opts.GitDepth != 5 || opts.MaxBytes != 10<<20 {
		t.Fatalf("stage options = %+v, %v", opts, err)
	}
	if _, err := ta.copyStageOptions(packs.Flags{Pack: "contractors", Project: ta.project}, "dc-claude-a", nil); err == nil {
		t.Fatal("staged without the daemon's copy policy")
	}
}

// A 1.0.4 CLI on a managed computer whose sandbox daemon is still 1.0.3
// (it has not restarted since the package upgrade): that daemon's Ready
// refuses the harness field, so the CLI readies with the empty object it
// takes. The doctor's daemon row, which says the first run readies
// OpenShell, is then true: the run readies it and creates the sandbox.
func TestFirstRunReadiesOnAnOlderManagedDaemon(t *testing.T) {
	ta := newTestApp(t, "")
	gw := ta.daemon.status.Gateway
	ta.daemon.status.Available, ta.daemon.status.Gateway = false, nil
	ta.daemon.status.Managed = managedStatusFixture()
	ta.daemon.statusWithoutAllowed, ta.daemon.strictReady = true, true
	ta.daemon.onReady = func(st *sandboxapi.Status) {
		st.Available, st.Reason, st.Gateway = true, "", gw
	}
	if c := ta.probeDaemon(bg, true).check; c.Status != openshell.StatusPass {
		t.Fatalf("doctor daemon row before the first run: %+v", c)
	}
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude", Rm: true}))
	ready := ta.daemon.callsTo("POST", sandboxapi.PathReady)
	if len(ready) != 2 || string(ready[0].Body) != `{"harness":"claudecode"}` || string(ready[1].Body) != `{}` {
		t.Fatalf("ready requests = %+v, want the harness, then the older daemon's empty object", ready)
	}
	if c := ta.daemon.callsTo("POST", sandboxapi.PathSandboxes); len(c) != 1 {
		t.Fatalf("create calls %d after readying an older daemon", len(c))
	}
}

// GAP-0534: a first run the organization does not allow (sandboxes not
// allowed for the account, or an agent its profile leaves out) announces no
// OpenShell install or start: the ready refuses it in the organization's
// words and installs nothing.
func TestAForbiddenAccountsFirstRunAnnouncesNoInstall(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*sandboxapi.ManagedExplain)
	}{
		{"sandboxes not allowed", func(me *sandboxapi.ManagedExplain) { me.Allowed = false }},
		{"agent left out", func(me *sandboxapi.ManagedExplain) { me.AllowedHarnesses = []string{"claudecode"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.daemon.status.Available, ta.daemon.status.Gateway = false, nil
			ta.daemon.status.Managed = managedStatusFixture()
			ta.daemon.explain.Managed = managedExplainFixture()
			tc.edit(ta.daemon.explain.Managed)
			_ = ta.Run(bg, RunOptions{Harness: "codex"})
			if out := ta.output(); strings.Contains(out, "Installing OpenShell") || strings.Contains(out, "Starting your OpenShell gateway") {
				t.Fatalf("a forbidden first run announced an install or start:\n%s", out)
			}
			if r := ta.daemon.callsTo("POST", sandboxapi.PathReady); len(r) != 1 {
				t.Fatalf("ready calls = %d, want the one whose refusal the run prints", len(r))
			}
		})
	}
	// The allowed run still says what it does.
	ta := newTestApp(t, "")
	ta.daemon.status.Available, ta.daemon.status.Gateway = false, nil
	ta.daemon.status.Managed = managedStatusFixture()
	ta.daemon.explain.Managed = managedExplainFixture()
	_ = ta.Run(bg, RunOptions{Harness: "codex"})
	if out := ta.output(); !strings.Contains(out, "Installing OpenShell") && !strings.Contains(out, "Starting your OpenShell gateway") {
		t.Fatalf("an allowed first run did not say it readies OpenShell:\n%s", out)
	}
}
