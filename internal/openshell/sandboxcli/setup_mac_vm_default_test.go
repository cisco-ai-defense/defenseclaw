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
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// TestSetupMovesAMacGatewayOffTheVMDriver (GAP-1704): a Mac whose OpenShell
// gateway already runs the vm driver (the upstream default of a fresh
// OpenShell) was never asked the MicroVM question, and setup, --yes
// included, wrote compute_driver = "vm", on which no sandbox starts on a
// Mac. It is asked like any Mac: the default, no, and --yes plan the
// docker driver in the same plan and restart; only a yes keeps vm.
func TestSetupMovesAMacGatewayOffTheVMDriver(t *testing.T) {
	const question = `Run sandboxes in OpenShell MicroVMs? This gateway runs the MicroVM driver, but on a Mac MicroVMs do not start until OpenShell fixes it; ` +
		`no switches it to the docker driver, which runs sandboxes on Docker Desktop 29.8 or newer (the run-time Landlock check decides) ` +
		`(sets compute_driver = "docker" in ~/.config/openshell/gateway.toml and restarts the gateway; sandboxes made on the MicroVM driver cannot start after the switch) [y/N]`
	for _, tc := range []struct {
		name  string
		input string
		yes   bool
		want  openshell.ComputeDriver
	}{
		{"no", "n\ny\n", false, openshell.DriverDocker},
		{"default", "\ny\n", false, openshell.DriverDocker},
		{"--yes", "", true, openshell.DriverDocker},
		{"yes", "y\n", false, openshell.DriverVM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta := setupApp(t, tc.input, "", false)
			if tc.yes {
				ta.IO.TTY, ta.IO.InTTY = false, false
			}
			ta.GOOS = "darwin"
			ta.gateway.state.Env = map[string]string{openshell.EnvTelemetryEnabled: "false"}
			ta.gateway.state.TOMLPath = filepath.Join(ta.home, ".config", "openshell", "gateway.toml")
			ta.HostDoctor = macReport(openshell.DriverVM, nil)
			ta.gateway.applyRes = &openshell.GatewayApplyResult{}
			_, _ = useGateway(ta)
			ta.ok(t, ta.Setup(bg, SetupOptions{Yes: tc.yes, SkipImages: true, NoWrappers: true}))
			p := ta.gateway.planned
			if len(p) != 1 || p[0].ComputeDriver != tc.want || ta.gateway.applied != 1 {
				t.Fatalf("gateway plans = %+v, applied %d, want compute_driver %q:\n%s", p, ta.gateway.applied, tc.want, ta.output())
			}
			if !tc.yes {
				has(t, ta.output(), question)
			}
			if tc.want == openshell.DriverDocker {
				if p[0].VMIdentity != nil || p[0].VMResources != nil {
					t.Fatalf("docker plan carries MicroVM settings: %+v", p[0])
				}
				has(t, ta.output(), "✓ gateway configured and restarted", "Done →")
				lacks(t, ta.output(), `compute_driver = "vm"`, "it runs sandboxes in OpenShell MicroVMs", "every run works on a copy (the MicroVM driver")
				return
			}
			has(t, ta.output(), "✓ gateway configured and restarted: it runs sandboxes in OpenShell MicroVMs")
		})
	}
}

// TestSetupSaysAMacGatewayLeftOnTheVMDriverIsNotReady (GAP-1704): the
// switch to docker restarts the gateway, which --yes does not give while a
// sandbox is on it. Setup then names the MicroVM sandboxes the switch
// strands, applies nothing, and ends not ready rather than done.
func TestSetupSaysAMacGatewayLeftOnTheVMDriverIsNotReady(t *testing.T) {
	ta := setupApp(t, "", "", false)
	ta.IO.TTY, ta.IO.InTTY = false, false
	ta.GOOS = "darwin"
	ta.gateway.state.Env = map[string]string{openshell.EnvTelemetryEnabled: "false"}
	ta.HostDoctor = macReport(openshell.DriverVM, nil)
	ta.gateway.applyRes = &openshell.GatewayApplyResult{}
	runningOn(t, ta, 1)
	wantExit(t, ta.Setup(bg, SetupOptions{Yes: true, SkipImages: true, NoWrappers: true}), 1)
	if p := ta.gateway.planned; len(p) != 1 || p[0].ComputeDriver != openshell.DriverDocker || ta.gateway.applied != 0 || ta.gateway.restarts != 0 {
		t.Fatalf("plans %+v, applied %d, restarts %d", p, ta.gateway.applied, ta.gateway.restarts)
	}
	has(t, ta.output(), "applying this restarts the OpenShell gateway on the docker driver: the 1 sandbox on it (dc-claude-theirs-a) were made on the MicroVM driver",
		"the gateway still runs the MicroVM driver, where no sandbox starts on a Mac; it runs sandboxes on the docker driver once it restarts on them",
		"not ready for sandboxes yet: the gateway still runs the MicroVM driver, where no sandbox starts on a Mac; restart it on the docker driver (`defenseclaw sandbox setup --restart-gateway`)")
	lacks(t, ta.output(), "Done →")
}

// macVMThenDocker is a Mac whose OpenShell gateway runs the vm driver: the
// first doctor run reports the MicroVM driver's view of the machine
// (Landlock by the MicroVM's kernel, Docker host networking and file
// sharing skipped), every later run the docker driver's view of the same
// machine, the nth of them edited by docker[n] (the last one repeats).
func macVMThenDocker(docker ...func(*openshell.DoctorReport)) func(context.Context, *openshell.Doctor) *openshell.DoctorReport {
	runs := 0
	return func(ctx context.Context, d *openshell.Doctor) *openshell.DoctorReport {
		runs++
		if runs == 1 {
			return macReport(openshell.DriverVM, nil)(ctx, d)
		}
		return macReport(openshell.DriverDocker, docker[min(runs-2, len(docker)-1)])(ctx, d)
	}
}

// hostNetworking puts Docker Desktop's host networking and file sharing
// checks, as the doctor's docker view reports them, in a report.
func hostNetworking(on bool) func(*openshell.DoctorReport) {
	return func(r *openshell.DoctorReport) {
		hostNet := openshell.Check{ID: openshell.CheckIDDockerHostNetwork, Title: "Docker host networking", Status: openshell.StatusPass, Detail: "enabled in Docker Desktop"}
		if !on {
			hostNet.Status, hostNet.Detail = openshell.StatusFail, "Docker Desktop host networking is off; the OpenShell supervisor needs it"
			hostNet.Fix = &openshell.Fix{Summary: "turn on Docker Desktop → Settings → Resources → Network → Enable host networking, then apply and restart"}
		}
		r.Checks = append(r.Checks, hostNet,
			openshell.Check{ID: openshell.CheckIDDockerFileSharing, Title: "Docker file sharing", Status: openshell.StatusPass, Detail: "/Users/u is shared with Docker Desktop"})
	}
}

// TestSetupChecksTheDockerDriverBeforeAMacGatewayLeavesVM (GAP-1704,
// RV-1704): on a gateway on vm the doctor's report is the MicroVM driver's
// view, so the move to docker checked none of what the docker driver
// needs, and setup said Done on a Mac whose Docker Desktop host networking
// is off, where the first run fails. Setup now checks the machine again
// for the docker driver before anything changes and applies a docker
// gateway's gates: host networking left off ends not ready, a terminal
// checks again once it is on, and a Docker VM without Landlock stops setup.
func TestSetupChecksTheDockerDriverBeforeAMacGatewayLeavesVM(t *testing.T) {
	const checking = "Checking this machine for the docker driver…  ✓ darwin/arm64  ✓ Landlock  ✓ Docker 29.1.5"
	const off = "✗ Docker host networking: Docker Desktop host networking is off; the OpenShell supervisor needs it\n"
	newMac := func(t *testing.T, input string, yes bool, doctor func(context.Context, *openshell.Doctor) *openshell.DoctorReport) *testApp {
		ta := setupApp(t, input, "", false)
		if yes {
			ta.IO.TTY, ta.IO.InTTY = false, false
		}
		ta.GOOS = "darwin"
		ta.gateway.state.Env = map[string]string{openshell.EnvTelemetryEnabled: "false"}
		ta.HostDoctor = doctor
		ta.gateway.applyRes = &openshell.GatewayApplyResult{}
		_, _ = useGateway(ta)
		return ta
	}
	t.Run("host networking off", func(t *testing.T) {
		ta := newMac(t, "", true, macVMThenDocker(hostNetworking(false)))
		wantExit(t, ta.Setup(bg, SetupOptions{Yes: true, SkipImages: true, NoWrappers: true}), 1)
		out := ta.output()
		has(t, out, checking, off,
			"→ turn on Docker Desktop → Settings → Resources → Network → Enable host networking, then apply and restart",
			"not ready for sandboxes yet: the docker driver needs Docker host networking (turn on Docker Desktop → Settings → Resources → Network → "+
				"Enable host networking, then apply and restart); then `defenseclaw sandbox run ")
		lacks(t, out, "Done →", "Check Docker Desktop again?")
		if p := ta.gateway.planned; len(p) != 1 || p[0].ComputeDriver != openshell.DriverDocker || ta.gateway.applied != 1 {
			t.Fatalf("plans %+v, applied %d", p, ta.gateway.applied)
		}
	})
	t.Run("host networking turned on at the question", func(t *testing.T) {
		// No to MicroVMs, yes to check again, yes to the mounts, yes to the restart.
		ta := newMac(t, "n\ny\ny\ny\n", false, macVMThenDocker(hostNetworking(false), hostNetworking(true)))
		ta.ok(t, ta.Setup(bg, SetupOptions{SkipImages: true, NoWrappers: true}))
		out := ta.output()
		has(t, out, checking, off, "Check Docker Desktop again? (once you have changed the setting above)", "Done →")
		lacks(t, out, "not ready for sandboxes yet")
	})
	t.Run("no Landlock in Docker's VM", func(t *testing.T) {
		ta := newMac(t, "", true, macVMThenDocker(func(r *openshell.DoctorReport) { *r.Get(openshell.CheckIDLandlock) = noLandlockInTheVM }))
		wantErr(t, ta.Setup(bg, SetupOptions{Yes: true, SkipImages: true, NoWrappers: true}), "this machine cannot run sandboxes yet (Landlock)")
		if len(ta.gateway.planned) != 0 || ta.gateway.applied != 0 {
			t.Fatalf("plans %+v, applied %d", ta.gateway.planned, ta.gateway.applied)
		}
	})
}

// TestSetupSaysAnUnmanagedMacGatewayLeftOnVMIsNotReady (RV-1704 nit): an
// OpenShell gateway setup cannot restart, moving off vm, ended Done when the
// user did not let setup write the change (or wrote it, the restart still
// theirs to make), though the gateway stays on the MicroVM driver, where no
// sandbox starts on a Mac; the MicroVM twin ends not ready.
func TestSetupSaysAnUnmanagedMacGatewayLeftOnVMIsNotReady(t *testing.T) {
	for _, write := range []bool{false, true} {
		answer := map[bool]string{false: "n", true: "y"}[write]
		t.Run("write "+answer, func(t *testing.T) {
			// No to MicroVMs, yes to the mounts, then the write.
			ta := setupApp(t, "n\ny\n"+answer+"\n", "", false)
			ta.GOOS = "darwin"
			ta.HostDoctor = unmanagedReportOn(true, true, openshell.DriverVM, nil)
			ta.gateway.applyRes = &openshell.GatewayApplyResult{Files: []openshell.AppliedFile{{Path: ta.ConfigPath}}}
			_, _ = useGateway(ta)
			wantExit(t, ta.Setup(bg, SetupOptions{SkipImages: true, NoWrappers: true}), 1)
			out := ta.output()
			lacks(t, out, "Done →")
			if p := ta.gateway.planned; len(p) != 1 || p[0].ComputeDriver != openshell.DriverDocker || len(ta.gateway.written) != map[bool]int{false: 0, true: 1}[write] {
				t.Fatalf("plans %+v, written %d", p, len(ta.gateway.written))
			}
			if write {
				has(t, out, "not ready for sandboxes yet: restart the OpenShell gateway yourself, the way you started it, so it runs the docker driver (restarting it stops every ",
					"); then `defenseclaw sandbox run ")
				return
			}
			has(t, out, "not ready for sandboxes yet: the gateway change was not written, so a restart alone leaves the gateway on the MicroVM driver, where no sandbox starts on a Mac. "+
				"Rerun `defenseclaw sandbox setup` and let it write the change, then restart the OpenShell gateway yourself, the way you started it; then `defenseclaw sandbox run ")
		})
	}
}
