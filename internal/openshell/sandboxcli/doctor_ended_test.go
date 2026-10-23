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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// TestDoctorAdviceForAnOldErrorStateMicroVM: on an OpenShell before 0.1.5
// a MicroVM in the error state can be neither stopped nor started, and
// nothing flushes it. The rounds before said the upgrade (or, on a managed
// computer, the administrator's pin move) waits two minutes for it, then
// that the user's stop lets it go; but its VM may still run and write.
// The advice now matches what the upgrade does: it is refused while
// OpenShell does not report the MicroVM stopped, whatever OpenShell says
// of why, and only its delete lets it go ahead, after which nothing of it
// is left to stop and start. One whose VM is gone runs nothing, and a
// docker sandbox keeps the plain advice.
func TestDoctorAdviceForAnOldErrorStateMicroVM(t *testing.T) {
	check := func(ta *testApp) openshell.Check {
		t.Helper()
		ta.HostDoctor = func(context.Context, *openshell.Doctor) *openshell.DoctorReport { return &openshell.DoctorReport{} }
		for _, c := range ta.runDoctor(bg).Checks {
			if c.ID == CheckIDHooks {
				return c
			}
		}
		t.Fatal("no sandbox-hooks check")
		return openshell.Check{}
	}
	afterDocker := ", then `defenseclaw sandbox stop NAME` and `defenseclaw sandbox start NAME` for hic, which keep the sandbox and its work"
	afterVM := ", then `defenseclaw sandbox stop NAME` and `defenseclaw sandbox start NAME` for hic; the sandbox remains, but its MicroVM work is kept only through the last successful disk sync"
	held := func(move string) string {
		return move + " is refused while OpenShell does not report hic stopped, and this OpenShell neither stops nor starts a MicroVM in its error state: " +
			"`defenseclaw sandbox delete NAME` deletes it with its work"
	}
	perUser := "upgrade OpenShell to " + openshell.InstallerVersion
	managed := "your organization's OpenShell setting moves this account to " + openshell.InstallerVersion + " on its own where DefenseClaw installs OpenShell (ask IT otherwise)"
	for _, tc := range []struct {
		name, driver, reason string
		managed              bool
		want                 string
	}{
		{"per user", "vm", "MainProcessFailed: Canonical main process exited with status 1", false, perUser + " (see Gateway; " + held("the upgrade") + ")"},
		{"per user, timed out", "vm", "ProvisioningTimedOut: Provisioning repair window expired after 300 seconds", false, perUser + " (see Gateway; " + held("the upgrade") + ")"},
		{"managed", "vm", "MainProcessFailed: Canonical main process exited with status 1", true, managed + " (" + held("the move") + ")"},
		{"managed, not polled", "vm", "ProcessPollFailed: Bad file descriptor", true, managed + " (" + held("the move") + ")"},
		{"managed, VM gone", "vm", "ProcessExited: VM process exited with status 1", true, managed + afterVM},
		{"docker", "docker", "ContainerExited: exited", false, perUser + " (see Gateway)" + afterDocker},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.daemon.status.Gateway.Version = "0.1.3"
			if tc.managed {
				ta.daemon.status.Managed = &sandboxapi.ManagedStatus{}
			}
			lost := sampleSandbox("hic")
			lost.Phase, lost.Driver, lost.PhaseReason = "error", tc.driver, tc.reason
			ta.daemon.add(lost)
			c := check(ta)
			if c.Status != openshell.StatusWarn || c.Fix == nil || c.Fix.Summary != tc.want {
				t.Fatalf("advice = %+v\nwant %q", c, tc.want)
			}
			if strings.Contains(c.Fix.Summary, "disk back") || strings.Contains(c.Fix.Summary, "lets the") {
				t.Fatalf("the advice still counts on a flush or a let-go nothing makes: %q", c.Fix.Summary)
			}
		})
	}
}

// A failed MicroVM can keep running after its main process fails. Doctor
// must describe the same lossy recovery as the start and stop commands,
// while a VM whose process exited and an errored Docker sandbox keep the
// ordinary stop/start path.
func TestDoctorAdviceForALingeringFailedMicroVM(t *testing.T) {
	for _, tc := range []struct {
		name, driver, reason string
		lingering            bool
	}{
		{"main process failed", "vm", "MainProcessFailed: Canonical main process exited with status 1", true},
		{"VM process exited", "vm", "ProcessExited: VM process exited with status 1", false},
		{"Docker container exited", "docker", "ContainerExited: exited", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sb := sampleSandbox("failed")
			sb.Phase, sb.Driver, sb.PhaseReason = "error", tc.driver, tc.reason
			ta := newTestApp(t, "", sb)
			ta.daemon.status.Gateway.Version = openshell.SupportedMin
			c := ta.hooksCheck(bg, "")
			if c.Status != openshell.StatusWarn || c.Fix == nil {
				t.Fatalf("hooks check = %+v", c)
			}
			if tc.driver == "vm" && !strings.Contains(c.Detail, "MicroVM") {
				t.Errorf("failed VM reported as a Docker container: %s", c.Detail)
			}
			if tc.driver == "vm" && !tc.lingering && !strings.Contains(c.Fix.Summary, "last successful disk sync") {
				t.Errorf("failed VM advice promises work without a confirmed sync: %s", c.Fix.Summary)
			}
			if tc.lingering {
				for _, want := range []string{
					"`defenseclaw sandbox start failed --end-vm`",
					"what the VM has not written to its disk is lost",
					"`defenseclaw sandbox delete failed`",
					"deletes it and its work",
				} {
					if !strings.Contains(c.Fix.Summary, want) {
						t.Errorf("failed MicroVM advice lacks %q: %s", want, c.Fix.Summary)
					}
				}
				if strings.Contains(c.Fix.Summary, "which keep the sandbox and its work") {
					t.Errorf("failed MicroVM advice promises to keep work: %s", c.Fix.Summary)
				}
			} else if !strings.Contains(c.Fix.Summary, "`defenseclaw sandbox stop NAME` and `defenseclaw sandbox start NAME`") ||
				strings.Contains(c.Fix.Summary, "--end-vm") {
				t.Errorf("ordinary error advice = %s", c.Fix.Summary)
			}
			if tc.driver == "vm" && strings.Contains(c.Fix.Summary, "which keep the sandbox and its work") {
				t.Errorf("failed VM advice promises all work: %s", c.Fix.Summary)
			}
		})
	}
}

func TestDoctorAdviceForAnotherHeldMicroVMError(t *testing.T) {
	sb := sampleSandbox("failed")
	sb.Phase, sb.Driver, sb.PhaseReason = "error", "vm", "ProcessPollFailed: Bad file descriptor"
	ta := newTestApp(t, "", sb)
	ta.daemon.status.Gateway.Version = openshell.SupportedMin
	c := ta.hooksCheck(bg, "")
	if c.Fix == nil || !strings.Contains(c.Fix.Summary, "`defenseclaw sandbox stop failed`") ||
		!strings.Contains(c.Fix.Summary, "last successful disk sync") || strings.Contains(c.Fix.Summary, "`defenseclaw sandbox start NAME`") {
		t.Fatalf("held failed VM advice promises stop/start recovery: %+v", c)
	}
}

// TestStopOfAnEndedMicroVMSaysHowToStopIt: OpenShell returns the stop of
// a MicroVM whose main process completed or failed as it is, and its VM
// may still run. The round before told the user that the stop let it go,
// so the next gateway restart, upgrade or setup move would stop it with
// what it had not written lost. Now the stop says that DefenseClaw stops
// no gateway under it until OpenShell reports it stopped, and how to get
// there on the gateway's release; a stop that OpenShell made says stopped.
func TestStopOfAnEndedMicroVMSaysHowToStopIt(t *testing.T) {
	for _, tc := range []struct {
		name, phase, reason, release, want string
	}{
		{"completed", "completed", "", openshell.SupportedMin,
			"⚠ box is completed: OpenShell does not stop it, so its MicroVM may still run, and DefenseClaw stops, restarts and upgrades no OpenShell gateway under it, " +
				"nor moves this account to another OpenShell setup, until OpenShell reports it stopped: nothing in OpenShell writes this MicroVM's disk back or stops it: " +
				"its VM still runs what its workload left running, and its start ends that VM with no flush first, so what the VM has not written to its disk is lost: " +
				"`defenseclaw sandbox start box --end-vm` ends the VM that way, then `defenseclaw sandbox stop box` once it is ready; or `defenseclaw sandbox delete box` (DefenseClaw sandbox) or `openshell sandbox delete box` (raw OpenShell sandbox), which deletes it and its work"},
		{"failed", "error", "MainProcessFailed: Canonical main process exited with status 1", openshell.SupportedMin,
			"⚠ box is in OpenShell's error state: OpenShell does not stop it, so its MicroVM may still run"},
		{"completed, old gateway", "completed", "", "0.1.3",
			"until OpenShell reports it stopped: `defenseclaw sandbox delete box` (DefenseClaw sandbox) or `openshell sandbox delete box` (raw OpenShell sandbox), which deletes it and its work (this OpenShell neither stops nor starts a completed MicroVM)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sb := sampleSandbox("box")
			sb.Phase, sb.Driver, sb.PhaseReason = tc.phase, "vm", tc.reason
			ta := newTestApp(t, "", sb)
			ta.daemon.status.Gateway.Version = tc.release
			ta.ok(t, ta.Stop(bg, StopOptions{Name: "box", Yes: true}))
			has(t, ta.output(), tc.want)
			lacks(t, ta.output(), "box is stopped", "lets", "let go")
		})
	}
	sb := sampleSandbox("box")
	sb.Phase, sb.Driver = "completed", "docker"
	ta := newTestApp(t, "", sb)
	ta.ok(t, ta.Stop(bg, StopOptions{Name: "box", Yes: true}))
	has(t, ta.output(), "box is stopped")
	lacks(t, ta.output(), "OpenShell does not stop it")
}

// endedOn has a MicroVM gateway of release (the fake's own when empty)
// with the sandbox dc-done, whose workload completed, and running ready
// ones.
func endedOn(t *testing.T, ta *testApp, release string, running int) {
	t.Helper()
	fake, client := useGateway(ta)
	fake.SetDriver(openshell.DriverVM)
	if release != "" {
		fake.SetRelease(release)
	}
	phases := map[string]openshell.SandboxPhase{"dc-done": openshell.PhaseCompleted}
	for i := range running {
		phases["dc-claude-theirs-"+string(rune('a'+i))] = openshell.PhaseReady
	}
	for name, phase := range phases {
		if _, err := client.CreateSandbox(bg, name, &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{}); err != nil {
			t.Fatal(err)
		}
		if err := fake.SetPhase(openshell.DefaultWorkspace, name, phase); err != nil {
			t.Fatal(err)
		}
	}
}

// TestRestartConsentRefusesWhileOpenShellDoesNotReportEveryMicroVMStopped:
// the consent questions of the gateway restarts DefenseClaw makes (doctor
// --fix, setup) read the sandboxes as the restart's own gate does
// (openshell.CheckSandboxesStopped). The rounds before told the user the
// restart waits for a MicroVM whose workload ended, then that the user's
// stop lets it go, and stopped running ones themselves. Now a MicroVM
// that OpenShell does not report stopped, ready or completed, refuses the
// restart, on every release: the question says how to stop each, defaults
// to no, and --yes does not fix it. Once OpenShell reports them stopped
// the fix applies.
func TestRestartConsentRefusesWhileOpenShellDoesNotReportEveryMicroVMStopped(t *testing.T) {
	applied := 0
	report := hostReport(func(r *openshell.DoctorReport) {
		r.Driver = openshell.DriverVM
		r.Checks = append(r.Checks, openshell.Check{ID: openshell.CheckIDVMResources, Title: "MicroVM resources", Status: openshell.StatusWarn,
			Detail: "every MicroVM gets 2 vCPUs", Fix: &openshell.Fix{Summary: "raise them and restart the gateway", Automatic: true, RestartsGateway: true,
				Apply: func(context.Context) error { applied++; return nil }}})
	})
	const refused = "MicroVM resources: this restarts the OpenShell gateway, and DefenseClaw makes it only once OpenShell reports every MicroVM sandbox on the gateway stopped, " +
		"which it does not for these: dc-done (completed): nothing in OpenShell writes this MicroVM's disk back or stops it"
	const ready = "dc-claude-theirs-a (ready): `defenseclaw sandbox stop dc-claude-theirs-a`"

	for _, release := range []string{openshell.SupportedMin, "0.1.3"} {
		ta := newTestApp(t, "")
		ta.HostDoctor = report
		endedOn(t, ta, release, 1)
		_ = ta.RunDoctor(bg, DoctorOptions{Fix: true, Yes: true})
		has(t, ta.output(), "MicroVM resources: this restarts the OpenShell gateway, and DefenseClaw makes it only once OpenShell reports every MicroVM sandbox on the gateway stopped",
			ready, "not fixed with --yes while OpenShell does not report every MicroVM sandbox on the gateway stopped")
		lacks(t, ta.output(), "write its disk back", "work kept", "lets the restart", "each first with OpenShell's own stop")
		if applied != 0 {
			t.Fatalf("OpenShell %s, MicroVMs not stopped: applied %d times", release, applied)
		}
	}
	ta := newTestApp(t, "")
	ta.HostDoctor = report
	endedOn(t, ta, openshell.SupportedMin, 0)
	_ = ta.RunDoctor(bg, DoctorOptions{Fix: true, Yes: true})
	has(t, ta.output(), refused)

	// OpenShell reports them stopped: the fix applies.
	ta = newTestApp(t, "")
	ta.HostDoctor = report
	fake, client := useGateway(ta)
	fake.SetDriver(openshell.DriverVM)
	if _, err := client.CreateSandbox(bg, "dc-done", &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := fake.SetPhase(openshell.DefaultWorkspace, "dc-done", openshell.PhaseStopped); err != nil {
		t.Fatal(err)
	}
	_ = ta.RunDoctor(bg, DoctorOptions{Fix: true, Yes: true})
	lacks(t, ta.output(), "DefenseClaw makes it only once", "not fixed with --yes")
	if applied != 1 {
		t.Fatalf("every MicroVM stopped: applied %d times", applied)
	}

	// setup's restart: not made, and not asked.
	ta = newTestApp(t, "")
	endedOn(t, ta, openshell.SupportedMin, 0)
	ok, err := ta.consentGatewayRestart(bg, SetupOptions{}, true, true, false)
	if err != nil || ok {
		t.Fatalf("setup with a completed MicroVM: %v, %v", ok, err)
	}
	has(t, ta.output(), "applying this restarts the OpenShell gateway, and DefenseClaw makes it only once OpenShell reports every MicroVM sandbox on the gateway stopped, "+
		"which it does not for these: dc-done (completed)")
	lacks(t, ta.output(), "Restart the OpenShell gateway now?")
}
