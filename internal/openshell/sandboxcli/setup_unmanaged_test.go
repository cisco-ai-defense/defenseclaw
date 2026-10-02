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
)

// The doctor's words for an OpenShell whose gateway no gateway service runs
// (openshell doctor.go unmanagedFix, procs.go unmanagedService).
const (
	macReleaseCLI   = "/Users/dev/openshell-direct/prefix/bin/openshell"
	linuxReleaseCLI = "/home/dev/.local/bin/openshell"
	startedByHand   = "/Users/dev/openshell-direct/prefix/bin/openshell-gateway (process 4666) was started by hand, " +
		"not Homebrew's nvidia/openshell/openshell service: it does not start again at login, and DefenseClaw cannot restart it"
	runsAnotherWay = "openshell-gateway is not installed; the gateway that answers runs another way, so DefenseClaw cannot start or restart it"
	startIt        = "start that OpenShell's gateway yourself, the way you started it before. DefenseClaw starts and restarts the gateway only through "
)

// unmanagedReport is the doctor's report of an OpenShell 0.1.1 installed
// another way than the one whose service DefenseClaw runs the gateway
// through, on a Mac (the MicroVM driver) or on Linux, with its gateway
// answering or not.
func unmanagedReport(mac, answers bool) func(context.Context, *openshell.Doctor) *openshell.DoctorReport {
	return unmanagedReportOn(mac, answers, openshell.DriverVM, nil)
}

// unmanagedReportOn is unmanagedReport with a Mac's gateway on driver,
// which more adjusts.
func unmanagedReportOn(mac, answers bool, driver openshell.ComputeDriver, more func(*openshell.DoctorReport)) func(context.Context, *openshell.Doctor) *openshell.DoctorReport {
	edit := func(r *openshell.DoctorReport) {
		svc := r.Get(openshell.CheckIDGatewayService)
		service, cli, detail := "Homebrew's nvidia/openshell/openshell service", macReleaseCLI, startedByHand
		r.Service = &openshell.ServiceState{Manager: "brew", Unit: openshell.GatewayFormula}
		if !mac {
			service, cli, detail = "the openshell-gateway user service, which NVIDIA's installer sets up", linuxReleaseCLI, runsAnotherWay
			r.Service = &openshell.ServiceState{Manager: "systemd", Unit: openshell.GatewayService}
		}
		r.CLIPath = cli
		svc.Status, svc.Detail = openshell.StatusWarn, detail
		if answers {
			return
		}
		svc.Status, svc.Detail = openshell.StatusFail, r.Service.Unit+" is not installed"
		fix := &openshell.Fix{Summary: startIt + service + ", and the OpenShell 0.1.1 at " + cli + " was installed another way. " +
			"For a gateway DefenseClaw starts and restarts, stop that one and remove that OpenShell (DefenseClaw's install step would find it " +
			"and install nothing), then install the formula", Command: "defenseclaw sandbox setup --install-openshell"}
		svc.Fix = fix
		c := r.Get(openshell.CheckIDGatewayVersion)
		c.Title, c.Status, c.Detail, c.Fix = "Gateway", openshell.StatusFail, "the gateway is not answering: connection refused", fix
		r.GatewayVersion = ""
	}
	if mac {
		return macReport(driver, func(r *openshell.DoctorReport) {
			edit(r)
			r.MicroVM.DriverBinary, r.MicroVM.DriverFromFormula = "/Users/dev/openshell-direct/prefix/libexec/openshell-driver-vm", false
			if more != nil {
				more(r)
			}
		})
	}
	return hostReport(func(r *openshell.DoctorReport) {
		edit(r)
		if more != nil {
			more(r)
		}
	})
}

// TestSetupUsesAGatewayRunAnotherWay (RT U1): on a Mac whose OpenShell
// 0.1.1 came from the release binaries, its gateway started by hand, the
// doctor said "✓ ready for sandboxes" with a ⚠ Gateway service, but setup
// printed "✗ OpenShell 0.1.1 is not from Homebrew's nvidia/openshell
// formula" and exited 1 before any of its other work, though sandboxes ran
// fine; on Linux without the openshell-gateway user unit it refused the
// same way. Setup now stops only where it would have to start that
// gateway, with the doctor's fix. With the gateway answering it says that
// DefenseClaw cannot start or restart it, writes a gateway change without
// restarting anything and tells the user to restart the gateway, as the
// doctor's fixes say, and goes on.
func TestSetupUsesAGatewayRunAnotherWay(t *testing.T) {
	for _, mac := range []bool{true, false} {
		goos, line, gatewayWarn := "darwin", "  ⚠ OpenShell 0.1.1 is not from Homebrew's nvidia/openshell formula\n", startedByHand
		if !mac {
			goos, line, gatewayWarn = "linux", "  ⚠ OpenShell 0.1.1 has no openshell-gateway user service\n", runsAnotherWay
		}
		newApp := func(t *testing.T, input string, answers bool) (*testApp, *fakeInstaller) {
			ta := setupApp(t, input, "", false)
			ta.GOOS = goos
			ta.HostDoctor = unmanagedReport(mac, answers)
			ta.gateway.applyRes = &openshell.GatewayApplyResult{Files: []openshell.AppliedFile{{Path: ta.ConfigPath}}}
			_, _ = useGateway(ta)
			inst := &fakeInstaller{}
			ta.Installer = func(consent func(*openshell.InstallPlan) (bool, error)) Installer {
				inst.consent = consent
				return inst
			}
			return ta, inst
		}
		// Where it would have to start the gateway, setup stops with the
		// doctor's fix, before it installs, plans or asks anything.
		for flags, o := range map[string]SetupOptions{"": {}, "--install-openshell": {InstallOpenShell: true}, "-n": {NonInteractive: true}} {
			t.Run(strings.TrimSpace(goos+" gateway down "+flags), func(t *testing.T) {
				ta, inst := newApp(t, "", false)
				wantErr(t, ta.Setup(bg, o), "the OpenShell gateway is not usable yet (Gateway); see `defenseclaw sandbox doctor`")
				has(t, ta.output(), line, "✗ Gateway: the gateway is not answering: connection refused\n", "→ "+startIt)
				lacks(t, ta.output(), "Install OpenShell", "is needed", "already installed", "✓ OpenShell", "Write this change?", "⚠ Gateway service")
				if inst.ran || len(ta.gateway.planned) != 0 || len(ta.gateway.written) != 0 || ta.gateway.applied != 0 {
					t.Fatalf("installer ran %v, plans %+v, written %d, applied %d", inst.ran, ta.gateway.planned, len(ta.gateway.written), ta.gateway.applied)
				}
			})
		}
		// With the gateway answering setup goes on, writes the change the
		// user answers yes to (the default, which -n takes) and restarts
		// nothing; a no leaves it for later.
		for _, tc := range []struct {
			name, input string
			o           SetupOptions
			write       bool
		}{
			{"yes", "\n", SetupOptions{}, true},
			{"-n", "", SetupOptions{NonInteractive: true, InstallOpenShell: true}, true},
			{"no", "n\n", SetupOptions{}, false},
		} {
			t.Run(goos+" gateway run by hand, "+tc.name, func(t *testing.T) {
				input := tc.input
				if !mac && input != "" {
					// The mounts and telemetry questions come first.
					input = "\n\n" + input
				}
				ta, inst := newApp(t, input, true)
				if tc.o.NonInteractive {
					ta.IO.TTY = false
				}
				tc.o.SkipImages, tc.o.NoWrappers = true, true
				ta.ok(t, ta.Setup(bg, tc.o))
				out := ta.output()
				has(t, out, line, "⚠ Gateway service: "+gatewayWarn+"\n",
					"→ setup uses this gateway as it runs: after a gateway change, restart it yourself, the way you started it\n",
					"then you restart the gateway, the way you started it, so it loads the change (DefenseClaw cannot restart it)",
					"✓ openshell.enabled is on", "Done →")
				lacks(t, out, "✗", "Restart the OpenShell gateway now?", "restarts the gateway", "systemctl --user restart", "brew services restart", "doctor --fix")
				if !tc.o.NonInteractive {
					has(t, out, "Write this change? DefenseClaw cannot restart this gateway: you restart it, the way you started it, to apply it [Y/n]")
				}
				if !mac && !tc.o.NonInteractive {
					has(t, out, "Disable OpenShell's anonymous usage telemetry? (edits gateway.env; you restart the gateway yourself, "+
						"with its variables in the gateway's environment, to apply it)")
				}
				if inst.ran || ta.gateway.applied != 0 || ta.gateway.restarts != 0 || len(ta.gateway.planned) != 1 {
					t.Fatalf("installer ran %v, applied %d, restarts %d, plans %+v", inst.ran, ta.gateway.applied, ta.gateway.restarts, ta.gateway.planned)
				}
				if !tc.write {
					if len(ta.gateway.written) != 0 {
						t.Fatalf("wrote %d plans on no", len(ta.gateway.written))
					}
					has(t, out, "skipped: the OpenShell gateway change above (`defenseclaw sandbox setup` writes it; then you restart the gateway, the way you started it)")
					lacks(t, out, "configuration written", "so it runs on the change above")
					return
				}
				if len(ta.gateway.written) != 1 || !ta.gateway.written[0].Manual {
					t.Fatalf("written = %+v", ta.gateway.written)
				}
				// No sandbox runs (TestSetupSaysTheRestartYouMakeStopsSandboxes
				// names running ones).
				stops := "restarting it stops every sandbox on it\n"
				if mac {
					stops = "restarting it stops every sandbox on it (none runs now): stop a MicroVM sandbox you start before then first " +
						"(`defenseclaw sandbox stop NAME`, which flushes its disk), or what it wrote since its last sync is lost\n"
				}
				has(t, out, "✓ gateway configuration written; it takes effect when you restart the gateway\n",
					"⚠ restart the OpenShell gateway yourself, the way you started it, so it runs on the change above (DefenseClaw cannot restart it); "+stops)
				if p := ta.gateway.planned[0]; mac && (p.ComputeDriver != openshell.DriverVM || p.VMIdentity == nil) || !mac && (!p.EnableBindMounts || p.Env[openshell.EnvTelemetryEnabled] != "false") {
					t.Fatalf("plan = %+v", p)
				}
				// Teardown restores what it wrote.
				if r, err := ta.loadReceipt(); err != nil || len(r.GatewayFiles) != 1 {
					t.Fatalf("receipt = %+v, %v", r, err)
				}
			})
		}
	}

	// Without a CLI NVIDIA's installer runs, and sets the unit up.
	ta := setupApp(t, "n\n", "", false)
	ta.HostDoctor = hostReport(func(r *openshell.DoctorReport) {
		c := r.Get(openshell.CheckIDGatewayService)
		c.Status, c.Detail = openshell.StatusFail, "openshell-gateway is not installed"
		r.Service = &openshell.ServiceState{Manager: "systemd", Unit: openshell.GatewayService}
		r.CLIVersion = ""
		c = r.Get(openshell.CheckIDCLI)
		c.Status, c.Detail = openshell.StatusFail, "openshell is not on PATH"
	})
	wantErr(t, ta.Setup(bg, SetupOptions{}), "OpenShell 0.1.1 is needed")
	has(t, ta.output(), "✗ OpenShell not installed", "Install OpenShell 0.1.1 with NVIDIA's installer? (sudo; sha256 verified) [y/N]")
	lacks(t, ta.output(), "user service", "⚠ Gateway service")
}

// TestSetupSaysAnUnwrittenChangeNeedsSetup (fu2 review 2): on a Mac with a
// gateway run by hand on the docker driver, over a Docker VM without
// Landlock, a yes to the MicroVMs and a no to "Write this change?" wrote
// nothing, yet setup ended "restart the OpenShell gateway yourself … so it
// runs the MicroVM driver" (and "…once it restarts on them"): a restart
// leaves that gateway on docker. With nothing written, setup says to rerun
// it and let it write the change first; a written change keeps the
// restart.
func TestSetupSaysAnUnwrittenChangeNeedsSetup(t *testing.T) {
	for _, write := range []bool{false, true} {
		answer := "n"
		if write {
			answer = "y"
		}
		t.Run("write "+answer, func(t *testing.T) {
			ta := setupApp(t, "y\n"+answer+"\n", "", false)
			ta.GOOS = "darwin"
			ta.HostDoctor = unmanagedReportOn(true, true, openshell.DriverDocker, func(r *openshell.DoctorReport) {
				*r.Get(openshell.CheckIDLandlock) = noLandlockInTheVM
			})
			ta.gateway.applyRes = &openshell.GatewayApplyResult{Files: []openshell.AppliedFile{{Path: ta.ConfigPath}}}
			_, _ = useGateway(ta)
			ta.ok(t, ta.Setup(bg, SetupOptions{SkipImages: true, NoWrappers: true}))
			out := ta.output()
			has(t, out, "Run sandboxes in OpenShell MicroVMs?", "Write this change? DefenseClaw cannot restart this gateway")
			lacks(t, out, "Done →", "every run works on a copy (the MicroVM driver")
			if ta.gateway.applied != 0 || ta.gateway.restarts != 0 || len(ta.gateway.written) != map[bool]int{false: 0, true: 1}[write] {
				t.Fatalf("applied %d, restarts %d, written %d", ta.gateway.applied, ta.gateway.restarts, len(ta.gateway.written))
			}
			if write {
				has(t, out, "it runs sandboxes in MicroVMs once it restarts on them",
					"not ready for sandboxes yet: restart the OpenShell gateway yourself, the way you started it, so it runs the MicroVM driver; then `defenseclaw sandbox run ")
				lacks(t, out, "the gateway change was not written")
				return
			}
			has(t, out, "skipped: the OpenShell gateway change above (`defenseclaw sandbox setup` writes it; then you restart the gateway, the way you started it)",
				"the gateway still runs the docker driver, where no sandbox can start (the Linux VM Docker runs in has no Landlock); "+
					"it runs sandboxes in MicroVMs once `defenseclaw sandbox setup` writes the change above and you restart the gateway",
				"not ready for sandboxes yet: the gateway change was not written, so a restart alone leaves the gateway on the docker driver. "+
					"Rerun `defenseclaw sandbox setup` and let it write the change, then restart the OpenShell gateway yourself, the way you started it; "+
					"then `defenseclaw sandbox run ")
			lacks(t, out, "once it restarts on them", "so it runs the MicroVM driver", "so it runs on the change above")
		})
	}
}

// TestSetupSaysTheRestartYouMakeStopsSandboxes (fu2 review 5): setup
// writes a change for a gateway run by hand and leaves its restart to the
// user, but neither its plan nor its last line said that the restart stops
// every sandbox on the gateway, and on a Mac's MicroVM gateway a sandbox
// stopped without a flush loses what it wrote since its last sync (the
// flush DefenseClaw's own restarts make first). Both say so now, and the
// last line names the sandboxes running on it.
func TestSetupSaysTheRestartYouMakeStopsSandboxes(t *testing.T) {
	for _, mac := range []bool{true, false} {
		goos, input := "darwin", "\n"
		if !mac {
			// The mounts and telemetry questions come first.
			goos, input = "linux", "\n\n\n"
		}
		t.Run(goos, func(t *testing.T) {
			ta := setupApp(t, input, "", false)
			ta.GOOS = goos
			ta.HostDoctor = unmanagedReport(mac, true)
			ta.gateway.applyRes = &openshell.GatewayApplyResult{Files: []openshell.AppliedFile{{Path: ta.ConfigPath}}}
			ta.App.Gateway = onDriver{ta.gateway, map[bool]openshell.ComputeDriver{true: openshell.DriverVM, false: ""}[mac]}
			runningOn(t, ta, 2)
			ta.ok(t, ta.Setup(bg, SetupOptions{SkipImages: true, NoWrappers: true}))
			out := ta.output()
			const last = "⚠ restart the OpenShell gateway yourself, the way you started it, so it runs on the change above (DefenseClaw cannot restart it); "
			if !mac {
				has(t, out, "so it loads the change (DefenseClaw cannot restart it); restarting it stops every sandbox on it\n",
					last+"restarting it stops every sandbox on it, and 2 sandboxes run on it now (dc-claude-theirs-a, dc-claude-theirs-b)\n")
				lacks(t, out, "flushes")
				return
			}
			has(t, out, "so it loads the change (DefenseClaw cannot restart it); restarting it stops every sandbox on it: first stop the MicroVM sandboxes "+
				"running on it with `defenseclaw sandbox stop NAME`, which flushes their disks, or what they wrote since their last sync is lost\n",
				last+"restarting it stops every sandbox on it: first stop the MicroVM sandboxes running on it (dc-claude-theirs-a, dc-claude-theirs-b) "+
					"with `defenseclaw sandbox stop NAME`, which flushes their disks, or what they wrote since their last sync is lost\n")
			if ta.gateway.restarts != 0 || ta.gateway.applied != 0 || len(ta.gateway.written) != 1 {
				t.Fatalf("restarts %d, applied %d, written %d", ta.gateway.restarts, ta.gateway.applied, len(ta.gateway.written))
			}
		})
	}
}

// onDriver is a gateway whose configuration selects driver, as Plan says.
type onDriver struct {
	*fakeGateway
	driver openshell.ComputeDriver
}

func (g onDriver) Plan(ctx context.Context, ch openshell.GatewayChanges) (*openshell.GatewayPlan, error) {
	plan, err := g.fakeGateway.Plan(ctx, ch)
	if err == nil && ch.ComputeDriver != "" {
		plan.ComputeDriver, plan.FromDriver = ch.ComputeDriver, g.driver
	}
	return plan, err
}

// TestTeardownRestoresTheFilesOfAGatewayRunAnotherWay: the gateway files
// setup wrote for a gateway no gateway service runs are restored, and the
// user is told to restart it (Rollback returns ErrNoGatewayService). The
// plan the user agreed to said "then restart the OpenShell gateway, which
// drops the connections of every sandbox on it", a restart DefenseClaw
// does not make (fu2 review 4): it says the user restarts it, what that
// stops, and on the MicroVM driver to stop the sandboxes still running
// (another owner's, which teardown leaves) first, which flushes their
// disks.
func TestTeardownRestoresTheFilesOfAGatewayRunAnotherWay(t *testing.T) {
	const yourself = "then you restart the OpenShell gateway yourself, the way you started it, so it loads them (DefenseClaw cannot restart it); " +
		"restarting it stops every sandbox on it"
	for _, driver := range []string{"docker", "vm"} {
		t.Run(driver, func(t *testing.T) {
			ta := newTestApp(t, "")
			writeConfig(t, ta, "")
			toml := ta.home + "/gateway.toml"
			writeFile(t, toml, "[openshell]\nversion = 2\n")
			if err := ta.recordGatewayApply(&openshell.GatewayApplyResult{Files: []openshell.AppliedFile{{Path: toml}}}); err != nil {
				t.Fatal(err)
			}
			runningOn(t, ta, 1)
			ta.daemon.status.Gateway.Driver = driver
			ta.App.Gateway = noServiceGateway{ta.gateway}
			ta.ok(t, ta.Teardown(bg, TeardownOptions{Yes: true, KeepImages: true}))
			out := ta.output()
			has(t, out, "✓ restored the OpenShell gateway configuration; restart the gateway yourself, the way you started it, so it runs on it")
			if driver == "vm" {
				has(t, out, yourself+": first stop the MicroVM sandboxes running on it (dc-claude-theirs-a) with `defenseclaw sandbox stop NAME`, "+
					"which flushes their disks, or what they wrote since their last sync is lost")
			} else {
				has(t, out, yourself+", and 1 sandbox runs on it now (dc-claude-theirs-a)")
				lacks(t, out, "flushes")
			}
			lacks(t, out, "could not", "and restarted it", "then restart the OpenShell gateway, which drops the connections")
			if r, err := ta.loadReceipt(); err != nil || len(r.GatewayFiles) != 0 {
				t.Fatalf("receipt = %+v, %v", r, err)
			}
		})
	}
	// A gateway service runs the gateway: teardown restarts it.
	ta := newTestApp(t, "")
	writeConfig(t, ta, "")
	toml := ta.home + "/gateway.toml"
	writeFile(t, toml, "[openshell]\nversion = 2\n")
	if err := ta.recordGatewayApply(&openshell.GatewayApplyResult{Files: []openshell.AppliedFile{{Path: toml}}}); err != nil {
		t.Fatal(err)
	}
	ta.ok(t, ta.Teardown(bg, TeardownOptions{Yes: true, KeepImages: true}))
	has(t, ta.output(), "then restart the OpenShell gateway, which drops the connections of every sandbox on it",
		"✓ restored the OpenShell gateway configuration and restarted it")
	lacks(t, ta.output(), "yourself")
}

// noServiceGateway is a gateway no gateway service runs.
type noServiceGateway struct{ *fakeGateway }

func (g noServiceGateway) Rollback(ctx context.Context, res *openshell.GatewayApplyResult) error {
	_ = g.fakeGateway.Rollback(ctx, res)
	return openshell.ErrNoGatewayService
}

func (noServiceGateway) NoService(context.Context) bool { return true }
