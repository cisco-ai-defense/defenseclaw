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

package sandboxcli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
)

// Installer installs OpenShell, and on a Mac what its MicroVM driver
// needs (openshell.Installer).
type Installer interface {
	Install(ctx context.Context) (*openshell.InstallResult, error)
	InstallE2fsprogs(ctx context.Context) error
	ResignVMDriver(ctx context.Context) error
}

func (a *App) defaultInstaller(consent func(*openshell.InstallPlan) (bool, error)) Installer {
	d := openshell.DiscoverOptions{}
	if a.Cfg != nil {
		d.Gateway = a.Cfg.OpenShell.Gateway.Name
	}
	return &openshell.Installer{
		Out: a.IO.Out, Consent: consent, Discover: d,
		ConfirmBreakingUpgrade: func(*openshell.InstallPlan) (bool, error) {
			// Only a person can say the old runtime is backed up: --yes
			// does not answer this.
			ok, err := a.ask("An OpenShell 0.0.x runtime is installed; 0.1 cannot use its state. Have you backed it up and cleaned it up (`defenseclaw sandbox legacy-cleanup`)?", false, false)
			if errors.Is(err, ErrNoTerminal) {
				return false, errors.New("an OpenShell 0.0.x runtime is installed and 0.1 cannot use its state; back it up, clean it up " +
					"(`defenseclaw sandbox legacy-cleanup`) and run setup again on a terminal")
			}
			return ok, err
		},
	}
}

// setupTroubleshootingURL is the sandbox guide's troubleshooting section.
const setupTroubleshootingURL = openshell.TroubleshootingURL

// SetupOptions are the `sandbox setup` flags.
type SetupOptions struct {
	InstallOpenShell bool
	NoMounts         bool
	// Wrappers installs the shell wrappers without asking; NoWrappers
	// never asks.
	Wrappers   bool
	NoWrappers bool
	// NonInteractive never prompts: consented steps run, others are
	// skipped. Yes answers every question with its default.
	NonInteractive    bool
	Yes               bool
	Harnesses         []string
	UpstreamTelemetry bool
	SkipImages        bool
	// RestartGateway lets setup restart the OpenShell gateway to apply its
	// configuration while sandboxes run on it (see consentGatewayRestart).
	RestartGateway bool
}

// Setup is the one-time `sandbox setup` flow: host checks, the consented
// OpenShell install, bind mounts on the local gateway, the upstream
// telemetry choice, harnesses, credentials, shell wrappers and images.
func (a *App) Setup(ctx context.Context, o SetupOptions) error {
	a.defaults()
	if err := a.CheckSupported(); err != nil {
		return err
	}
	if a.Cfg == nil {
		return errors.New("DefenseClaw is not set up yet; run `defenseclaw init` first")
	}
	// Setup asks before it changes the OpenShell gateway (and restarts it),
	// the configuration and the shell rc files. Without a terminal nothing
	// answers, and a question further on would fail with the earlier steps
	// done: the user says up front which answers to take.
	if !a.IO.TTY && !o.Yes && !o.NonInteractive {
		return errors.New("`sandbox setup` asks before it changes the OpenShell gateway, the configuration and your shell, and there is no terminal; " +
			"pass --yes to accept the defaults, or --non-interactive to skip what needs an answer")
	}
	assume := o.Yes || o.NonInteractive
	a.println()
	a.println(a.bold("DefenseClaw sandbox setup"))

	// 1. The machine. The line starts before the checks, which can take
	// a while (Homebrew is slow to answer about its services).
	a.printf("  Checking this machine…  ")
	rep := a.runDoctor(ctx)
	a.printf("%s\n", a.machineLine(rep))
	// A Mac runs sandboxes in OpenShell MicroVMs. Until its gateway does,
	// the Landlock check is of the Linux VM Docker runs in, which on
	// Docker Desktop has none: no reason to stop before the question that
	// switches the gateway (step 2).
	macOS := a.GOOS == "darwin"
	microVM := macOS && rep.Driver == openshell.DriverVM
	if err := a.machineFailure(rep, macOS && !microVM); err != nil {
		return err
	}
	// An OpenShell installed another way than the one whose service
	// DefenseClaw starts and restarts the gateway through: setup uses its
	// gateway while it answers, and writes a gateway change for the user
	// to restart it on (restartYourself).
	unmanaged := rep.GatewayUnmanaged()
	// restartYourself: setup wrote a change for that gateway; unwritten:
	// the user declined to have it written, which a restart does not load.
	restartYourself, unwritten := false, false
	// Steps left out say so at the end, with the command that does them.
	var skipped []string

	// 2. The compute driver (macOS): OpenShell's MicroVM driver, whose
	// MicroVMs have their own kernel with Landlock.
	if macOS && !microVM {
		if c := rep.Get(openshell.CheckIDLandlock); c != nil && c.Status == openshell.StatusFail {
			a.note("Landlock: " + c.Detail + "; MicroVMs have their own kernel, which enforces it")
		}
		a.listDockerSandboxes(ctx, rep)
		where := openshell.GatewayTOMLFile
		if st, err := a.Gateway.State(); err == nil && st.TOMLPath != "" {
			where = a.tildePath(st.TOMLPath)
		}
		restarts := " and restarts the gateway"
		if unmanaged {
			restarts = "; you restart the gateway yourself to apply it"
		}
		yes, err := a.ask(`Run sandboxes in OpenShell MicroVMs? macOS needs them: Docker Desktop's Linux kernel has no Landlock. (sets compute_driver = "vm" in `+
			where+restarts+"; OpenShell calls this driver experimental)", true, assume)
		if err != nil {
			return err
		}
		microVM = yes
		if !yes {
			// The docker driver needs the Landlock the Docker VM lacks.
			if err := a.machineFailure(rep, false); err != nil {
				return err
			}
		}
	}
	// Off Linux the docker driver runs sandboxes on the kernel of Docker
	// Desktop's Linux VM, which the doctor asks for Landlock in an image
	// already on this machine. With none yet (the check offers to download
	// the base image the harness images are built on), setup downloads it
	// and asks again, before it installs anything that could never run.
	if c := rep.Get(openshell.CheckIDLandlock); !microVM && c != nil && c.Status == openshell.StatusWarn {
		download := c.Fix != nil && c.Fix.Apply != nil
		pull := false
		if download && !o.SkipImages {
			var err error
			pull, err = a.ask("Download the OpenShell base image now to check Docker Desktop's Linux VM for Landlock? (about 4 GB; the harness images are built on it)", true, assume)
			if err != nil {
				return err
			}
		}
		if !pull {
			a.warn("Landlock: " + c.Detail)
			if download {
				skipped = append(skipped, "checking Docker Desktop's Linux VM for Landlock (`"+CommandName+" doctor --fix` downloads the base image and checks it)")
			}
		} else {
			a.note("Downloading the OpenShell base image (about 4 GB)…")
			if err := c.Fix.Apply(ctx); err != nil {
				return fmt.Errorf("download the OpenShell base image: %w", err)
			}
			a.printf("  Checking this machine again…  ")
			rep = a.runDoctor(ctx)
			a.printf("%s\n", a.machineLine(rep))
			if err := a.machineFailure(rep, false); err != nil {
				return err
			}
		}
	}

	// 3. OpenShell. On macOS DefenseClaw starts and restarts the gateway
	// through the Homebrew formula's service, on Linux through the
	// openshell-gateway user unit. The gateway of an OpenShell installed
	// another way (unmanaged) is the user's to start and restart: setup
	// uses it while it answers, and stops, like the doctor, with the way on
	// (the Gateway check's fix) where it would have to start it. The
	// install would not help: DefenseClaw's install step
	// (openshell.Installer.Install), finding its supported CLI, would not
	// run NVIDIA's installer, which would install the formula or set up the
	// unit.
	//
	// The install is offered only where DefenseClaw's install step would
	// run NVIDIA's installer: no CLI, or one it upgrades
	// (DoctorReport.OpenShellInstallNeeded). Over a supported CLI it
	// installs nothing, so a failed Gateway or Gateway service check is
	// the doctor's fix's, which the loop below prints (a stopped service
	// is started, a gateway of another release than the CLI is restarted
	// through its service).
	if rep.OpenShellInstallNeeded() {
		install := o.InstallOpenShell
		if !install && !o.NonInteractive {
			// On macOS the installer installs a Homebrew formula, without sudo.
			how := "sudo"
			if a.GOOS == "darwin" {
				how = "Homebrew"
			}
			var err error
			install, err = a.ask("Install OpenShell "+openshell.SupportedMin+" with NVIDIA's installer? ("+how+"; sha256 verified)", false, o.Yes)
			if err != nil {
				return err
			}
		}
		if !install {
			return fmt.Errorf("OpenShell %s is needed; rerun with --install-openshell, or install it yourself and rerun setup", openshell.SupportedMin)
		}
		inst := a.Installer(func(*openshell.InstallPlan) (bool, error) {
			if o.InstallOpenShell || o.Yes {
				return true, nil
			}
			return a.ask("Run this plan?", false, false)
		})
		res, err := inst.Install(ctx)
		if serr := a.homebrewNotWritable(err); serr != nil {
			return serr
		}
		var hb *openshell.HomebrewInstallError
		switch {
		case errors.As(err, &hb) && hb.FormulaInstalled:
			// The script got past the install and failed after it, in
			// starting the gateway or registering it with the CLI: the
			// checks below name the step that still fails, with its fix.
			a.warn("install OpenShell: the nvidia/openshell formula is installed, but NVIDIA's installer failed after it " +
				"(it starts the gateway and registers it with the OpenShell CLI); what it printed is above")
		case errors.Is(err, openshell.ErrHomebrewInstall):
			a.bad("install OpenShell: Homebrew could not install the nvidia/openshell formula")
			a.note("→ " + homebrewInstallHint(err))
			return &Silent{Err: fmt.Errorf("install OpenShell: %w", err)}
		case err != nil:
			return fmt.Errorf("install OpenShell: %w", err)
		case res.Installed:
			a.ok("OpenShell " + res.CLIVersion.String() + " installed, gateway running")
		default:
			a.ok("OpenShell " + res.CLIVersion.String() + " is already installed")
		}
		rep = a.runDoctor(ctx)
	}
	// A stopped service leaves the gateway not answering, whose fix (start
	// it) comes first; with the gateway answering, the service's own fix.
	for _, id := range []string{openshell.CheckIDCLI, openshell.CheckIDRegistration, openshell.CheckIDMTLS, openshell.CheckIDGatewayVersion,
		openshell.CheckIDGatewayService} {
		if c := rep.Get(id); c != nil && c.Status == openshell.StatusFail {
			a.bad(c.Title + ": " + c.Detail)
			if c.Fix != nil {
				a.note("→ " + c.Fix.Line())
			}
			return &Silent{Err: fmt.Errorf("the OpenShell gateway is not usable yet (%s); see `%s doctor`", c.Title, CommandName)}
		}
	}
	if unmanaged = rep.GatewayUnmanaged(); unmanaged {
		// Its gateway answers (the Gateway check passed).
		detail := "no gateway service runs the OpenShell gateway"
		if c := rep.Get(openshell.CheckIDGatewayService); c != nil && c.Detail != "" {
			detail = c.Detail
		}
		a.warn("Gateway service: " + detail)
		a.note("→ setup uses this gateway as it runs: after a gateway change, restart it yourself, the way you started it")
	}
	if microVM {
		var err error
		if rep, err = a.prepareMicroVMs(ctx, o, rep); err != nil {
			return err
		}
	}

	// 4. The gateway configuration: on a Mac the MicroVM driver, else bind
	// mounts; and upstream telemetry. One plan, one restart.
	state, err := a.Gateway.State()
	if err != nil {
		return fmt.Errorf("read the OpenShell gateway configuration: %w", err)
	}
	changes := openshell.GatewayChanges{}
	copyOnly := o.NoMounts
	if microVM {
		// A MicroVM mounts no host folders: nothing to ask.
		changes = microVMChanges(rep, state, a.Geteuid())
		copyOnly = true
	} else if !o.NoMounts && !state.BindMounts.Enabled() {
		yes, err := a.ask("Allow sandboxes to mount the project folder you launch from? (enables bind mounts on your local OpenShell gateway; "+
			"DefenseClaw mounts only the launch folder and the read-only settings "+strings.Join(mountedSettingsHarnesses(harness.Names()), " and ")+
			" sandboxes need)", true, assume)
		if err != nil {
			return err
		}
		changes.EnableBindMounts = yes
		copyOnly = !yes
	}
	// A saved openshell.upstream_telemetry: true is an earlier answer to
	// keep it, which setup does not ask again.
	keepTelemetry := o.UpstreamTelemetry || a.Cfg.OpenShell.UpstreamTelemetry
	telemetryOff := !keepTelemetry
	if a.GOOS == "darwin" {
		// Setup changes the telemetry only through the systemd unit, whose
		// environment files it can check (the doctor skips the telemetry
		// check here). The Homebrew service's wrapper sources gateway.env
		// too, so say how to turn it off by hand.
		switch {
		case telemetryOff && unmanaged:
			a.note("OpenShell's anonymous usage telemetry stays on: setup turns it off on Linux only. To turn it off here, start the gateway with " +
				openshell.EnvTelemetryEnabled + "=false in its environment")
		case telemetryOff:
			a.note("OpenShell's anonymous usage telemetry stays on: setup turns it off on Linux only. To turn it off here, set " +
				openshell.EnvTelemetryEnabled + "=false in " + a.tildePath(firstNonEmpty(state.EnvPath, "gateway.env")) +
				", which the Homebrew service reads, and restart the gateway (`brew services restart " + openshell.GatewayFormula + "`)")
		}
	} else {
		switch {
		case keepTelemetry && !o.UpstreamTelemetry && state.TelemetryEnabled():
			a.note("OpenShell's anonymous usage telemetry stays on (openshell.upstream_telemetry is true in " + a.tildePath(a.ConfigPath) + ")")
		case !keepTelemetry && state.TelemetryEnabled():
			// Say what a yes costs before it is given: an edit of
			// gateway.env and a restart of the shared gateway.
			question := "Disable OpenShell's anonymous usage telemetry?"
			switch {
			case assume:
			case unmanaged:
				question += " (edits " + a.tildePath(firstNonEmpty(state.EnvPath, "gateway.env")) +
					"; you restart the gateway yourself, with its variables in the gateway's environment, to apply it)"
			default:
				question += " (edits " + a.tildePath(firstNonEmpty(state.EnvPath, "gateway.env")) +
					" and restarts the OpenShell gateway" + a.restartImpact(ctx) + ")"
			}
			yes, err := a.ask(question, true, assume)
			if err != nil {
				return err
			}
			telemetryOff = yes
		}
		if telemetryOff && state.TelemetryEnabled() {
			changes.Env = map[string]string{openshell.EnvTelemetryEnabled: "false"}
		} else if !telemetryOff && !state.TelemetryEnabled() {
			changes.UnsetEnv = []string{openshell.EnvTelemetryEnabled}
		}
	}
	// A gateway on a compute driver DefenseClaw does not drive runs none of
	// its sandboxes: offer the switch to docker in the same plan (GAP-1264).
	if !microVM && a.GOOS != "darwin" {
		if why := undrivenGatewayDriver(rep, state); why != "" {
			yes, err := a.ask("Switch your local OpenShell gateway to the docker compute driver? ("+why+
				"; sandboxes made on the current driver cannot start after the switch)", true, assume)
			if err != nil {
				return err
			}
			if yes {
				changes.ComputeDriver = openshell.DriverDocker
			} else {
				skipped = append(skipped, "the switch to the docker compute driver (no sandbox starts until the OpenShell gateway runs docker)")
			}
		}
	}
	// Switching the driver strands the other driver's sandboxes. The
	// gateway runs MicroVMs once it restarts on them: a restart not given
	// leaves it on docker.
	switching := microVM && rep.Driver != openshell.DriverVM
	switched := false
	if changes.EnableBindMounts || changes.ComputeDriver != "" || len(changes.Env) > 0 || len(changes.UnsetEnv) > 0 {
		plan, err := a.Gateway.Plan(ctx, changes)
		if err != nil {
			return fmt.Errorf("plan the gateway change: %w", err)
		}
		plan.Manual = unmanaged
		switch {
		case !plan.Empty():
			for _, l := range strings.Split(strings.TrimRight(plan.String(), "\n"), "\n") {
				a.note(l)
			}
			if id := changes.VMIdentity; id != nil && state.VM.Identity() != *id {
				a.note(fmt.Sprintf("sandbox_uid and sandbox_gid are gateway-wide: every MicroVM sandbox on this gateway, including ones made "+
					"outside DefenseClaw with `openshell sandbox create`, then runs as %s (one whose image expects another user may find its HOME read-only)", id))
			}
			if unmanaged {
				// Nothing restarts: the gateway loads the change when its
				// user restarts it.
				write, err := a.ask("Write this change? DefenseClaw cannot restart this gateway: you restart it, the way you started it, to apply it", true, assume)
				if err != nil {
					return err
				}
				if !write {
					skipped = append(skipped, "the OpenShell gateway change above (`"+CommandName+" setup` writes it; then you restart the gateway, the way you started it)")
					unwritten = true
					break
				}
				res, err := a.Gateway.Write(ctx, plan)
				if rerr := a.recordGatewayApply(res); rerr != nil {
					a.warn("could not record the gateway change for teardown: " + rerr.Error())
				}
				if err != nil {
					return fmt.Errorf("change the gateway configuration: %w", err)
				}
				a.ok("gateway configuration written; it takes effect when you restart the gateway")
				restartYourself = true
				break
			}
			restart, err := a.consentGatewayRestart(ctx, o, assume, microVM, switching)
			if err != nil {
				return err
			}
			if restart {
				res, err := a.Gateway.Apply(ctx, plan)
				if rerr := a.recordGatewayApply(res); rerr != nil {
					a.warn("could not record the gateway change for teardown: " + rerr.Error())
				}
				if err != nil {
					return fmt.Errorf("change the gateway configuration: %w", err)
				}
				switched = switching
				if microVM {
					a.ok("gateway configured and restarted: it runs sandboxes in OpenShell MicroVMs")
				} else {
					a.ok("gateway configured and restarted")
				}
			} else {
				skipped = append(skipped, "the OpenShell gateway change above (it restarts the gateway; apply it with `"+
					CommandName+" doctor --fix` or `"+CommandName+" setup --restart-gateway`)")
			}
		case switching:
			// The configuration already selects MicroVMs, but the gateway
			// was not restarted on it.
			a.note("the gateway configuration already selects the MicroVM driver; the gateway has not been restarted on it")
			if unmanaged {
				restartYourself = true
				break
			}
			restart, err := a.consentGatewayRestart(ctx, o, assume, microVM, switching)
			if err != nil {
				return err
			}
			if !restart {
				skipped = append(skipped, "restarting the OpenShell gateway on the MicroVM driver (`"+CommandName+" doctor --fix` or `"+CommandName+" setup --restart-gateway`)")
				break
			}
			if err := a.Gateway.Restart(ctx); err != nil {
				return fmt.Errorf("restart the OpenShell gateway: %w", err)
			}
			switched = true
			a.ok("gateway restarted: it runs sandboxes in OpenShell MicroVMs")
		}
	}
	onMicroVMs := microVM && (!switching || switched)
	// On a Docker VM without Landlock (Docker Desktop's) no sandbox starts
	// until the gateway runs MicroVMs.
	stuck := microVM && !onMicroVMs && failed(rep, openshell.CheckIDLandlock)
	// A change the user did not let setup write: a restart alone loads
	// nothing.
	once := "once it restarts on them"
	if unwritten {
		once = "once `" + CommandName + " setup` writes the change above and you restart the gateway"
	}
	// Without bind mounts no harness whose settings are mounted can start.
	noMounts := !microVM && copyOnly && !state.BindMounts.Enabled() && !changes.EnableBindMounts
	switch {
	case onMicroVMs:
		a.note("every run works on a copy (the MicroVM driver mounts no host folders); `" + CommandName + " pull` brings the changes back")
	case stuck:
		a.warn("the gateway still runs the docker driver, where no sandbox can start (the Linux VM Docker runs in has no Landlock); " +
			"it runs sandboxes in MicroVMs " + once)
	case microVM:
		a.note("the gateway still runs the docker driver; it runs sandboxes in MicroVMs " + once)
	case noMounts:
		a.warn("without bind mounts no " + strings.Join(mountedSettingsHarnesses(harness.Names()), " or ") +
			" sandbox can start, a `--copy` run included: DefenseClaw mounts their per-run settings read-only. " +
			"Other harnesses run on a copy; `" + CommandName + " doctor --fix` enables bind mounts")
	case copyOnly:
		a.note("without project mounts every run works on a copy (`--copy`)")
	}

	// 4. Harnesses and credentials. --harness adds to openshell.harnesses.
	specs, err := a.harnesses(o.Harnesses)
	if err != nil {
		return err
	}
	names := mergeHarnesses(a.Cfg.OpenShell.Harnesses, specs)
	a.printHarnesses(specs, names)

	// 5. The configuration.
	updates := map[string]any{
		"openshell.enabled": true, "openshell.harnesses": names, "openshell.upstream_telemetry": !telemetryOff,
	}
	mode := a.Cfg.OpenShell.Workdir.Mode
	switch {
	case microVM:
		// The driver clamps every run to a copy, and `policy explain`
		// names it: openshell.workdir.mode is not the reason to record.
	case copyOnly && (mode == "" || mode == config.OpenShellWorkdirMount):
		updates["openshell.workdir.mode"] = config.OpenShellWorkdirCopy
	case changes.EnableBindMounts && mode == config.OpenShellWorkdirCopy:
		// Mounts were just allowed; the copy mode an earlier setup
		// without them recorded goes, and the pack decides again.
		updates["openshell.workdir.mode"] = ""
	case !copyOnly && mode == config.OpenShellWorkdirCopy:
		a.note("openshell.workdir.mode is copy in " + a.tildePath(a.ConfigPath) + ", so runs still work on a copy; " +
			"set it to mount (or remove it) to mount the folder live")
	}
	if err := a.patchConfig(updates); err != nil {
		return err
	}
	a.Cfg.OpenShell.Enabled, a.Cfg.OpenShell.Harnesses, a.Cfg.OpenShell.UpstreamTelemetry = true, names, !telemetryOff
	a.ok("openshell.enabled is on in " + a.tildePath(a.ConfigPath))

	// 6. Wrappers, for the harness commands people type.
	var wrappable []*harness.Spec
	for _, s := range specs {
		if typed, ok := launchedCommands[s.Command]; ok {
			a.note(fmt.Sprintf("%s gets no shell wrapper: `%s` starts %s itself, which a wrapper cannot catch; start it with `%s run %s`",
				s.DisplayName, typed, s.Command, CommandName, HarnessArg(s)))
			continue
		}
		wrappable = append(wrappable, s)
	}
	if len(wrappable) > 0 {
		wrap := o.Wrappers
		if !wrap && !o.NoWrappers && !o.NonInteractive {
			var cmds []string
			for _, s := range wrappable {
				cmds = append(cmds, "`"+s.Command+"`")
			}
			wrap, err = a.ask("Make "+strings.Join(cmds, " and ")+" run sandboxed automatically? (shell wrapper; undo any time)", false, o.Yes)
			if err != nil {
				return err
			}
		}
		if wrap {
			for _, s := range wrappable {
				if err := a.enableWrapper(s, WrapperOptions{Harness: s.Name}); err != nil {
					a.warn("wrapper for " + s.Command + ": " + err.Error())
				}
			}
		} else if o.NonInteractive && !o.NoWrappers {
			skipped = append(skipped, "shell wrappers (not asked with --non-interactive; add one with `"+CommandName+" enable "+HarnessArg(wrappable[0])+"`)")
		}
	}
	// The closing command names a harness that can start: without bind
	// mounts one whose settings are not mounted, if any is set up.
	cmd := "claude"
	if len(specs) > 0 {
		cmd = HarnessArg(specs[0])
	}
	startable := !noMounts
	for _, s := range specs {
		if noMounts && !mountsSettings(s) {
			cmd, startable = HarnessArg(s), true
			break
		}
	}

	// 7. Images, then the ingress provider profile (imported once here:
	// every profile import briefly drops running sandboxes' connections).
	// A harness named with --harness gets its image; on a terminal, setup
	// asks before it downloads one for a harness it picked itself (the
	// defaults, openshell.harnesses).
	if !o.SkipImages {
		for _, s := range specs {
			build := assume || len(o.Harnesses) > 0
			if !build {
				// A current image is only checked, not built: no need to ask.
				current, err := a.Images.Current(s, microVM)
				build = err == nil && current
			}
			if !build {
				build, err = a.ask(fmt.Sprintf("Build the %s image now? (the first build downloads about 3 GB; otherwise the first `%s run %s` builds it)",
					s.DisplayName, CommandName, HarnessArg(s)), true, false)
				if err != nil {
					return err
				}
			}
			if !build {
				skipped = append(skipped, fmt.Sprintf("the %s image (the first `%s run %s` builds it, or `%s image build %s`)",
					s.DisplayName, CommandName, HarnessArg(s), CommandName, HarnessArg(s)))
				continue
			}
			if err := a.buildImage(ctx, s, microVM, false, false); err != nil {
				return err
			}
		}
	} else {
		skipped = append(skipped, "harness images (--skip-images; the first run builds them, or `"+CommandName+" image build`)")
	}
	if onMicroVMs {
		a.note("the first run of each image prepares its MicroVM disk (about a minute, and about 5 GB, which OpenShell keeps)")
	}
	a.importIngressProfile(ctx)

	// 8. The daemon picks the change up, the driver included.
	var driver openshell.ComputeDriver
	if onMicroVMs {
		driver = openshell.DriverVM
	}
	ready, noDockerGroup := a.waitDaemon(ctx, driver)
	for _, s := range skipped {
		a.note("skipped: " + s)
	}
	a.println()
	switch {
	case stuck && unwritten:
		a.warn("not ready for sandboxes yet: the gateway change was not written, so a restart alone leaves the gateway on the docker driver. Rerun `" +
			CommandName + " setup` and let it write the change, then restart the OpenShell gateway yourself, the way you started it; then `" +
			CommandName + " run " + cmd + "`")
		return nil
	case stuck && unmanaged:
		a.warn("not ready for sandboxes yet: restart the OpenShell gateway yourself, the way you started it, so it runs the MicroVM driver; then `" +
			CommandName + " run " + cmd + "`")
		return nil
	case stuck:
		a.warn("not ready for sandboxes yet: restart the OpenShell gateway on the MicroVM driver (`" + CommandName + " setup --restart-gateway`), then `" +
			CommandName + " run " + cmd + "`")
		return nil
	case noDockerGroup:
		a.warn("not ready for sandboxes yet: the DefenseClaw daemon started before you joined the docker group, so it cannot reach Docker. " +
			"Restart it so it picks up the group: `defenseclaw-gateway restart`; then `" + CommandName + " run " + cmd + "`")
		return nil
	case !ready:
		a.warn("not ready for sandboxes yet: the DefenseClaw daemon has not turned sandboxes on; run `" + CommandName +
			" doctor --fix`, then `" + CommandName + " run " + cmd + "`")
		return nil
	case restartYourself:
		// No flush comes first, as with a restart of DefenseClaw's
		// (consentGatewayRestart): the sandboxes are the user's to stop.
		a.warn("restart the OpenShell gateway yourself, the way you started it, so it runs on the change above (DefenseClaw cannot restart it); " +
			a.manualRestartStops(ctx, rep.Driver == openshell.DriverVM, nil))
	}
	if !startable {
		a.warn("not ready for sandboxes yet: no " + strings.Join(mountedSettingsHarnesses(harness.Names()), " or ") +
			" sandbox can start without bind mounts; enable them with `" + CommandName + " doctor --fix`, then `cd <project> && " +
			CommandName + " run " + cmd + "`")
		return nil
	}
	a.ok("Done →  cd <project> && " + CommandName + " run " + cmd)
	return nil
}

// homebrewNotWritable reports a Homebrew prefix that belongs to another
// account as the error setup returns, already printed with the way on; nil
// for any other error.
func (a *App) homebrewNotWritable(err error) error {
	var hw *openshell.HomebrewNotWritableError
	if !errors.As(err, &hw) {
		return nil
	}
	a.bad("install OpenShell: " + a.tildeText(hw.Problem()))
	a.note("→ " + a.tildeText(hw.Fix()))
	return &Silent{Err: fmt.Errorf("install OpenShell: %w", err)}
}

// homebrewInstallHint says what to update when Homebrew did not install
// the nvidia/openshell formula. With current Command Line Tools selected,
// what it refuses is an older /Applications/Xcode.app, which it checks
// even so ("Your Xcode (26.2) at /Applications/Xcode.app is too outdated.
// Please update to Xcode 27.0 (or delete it)."): updating the Command Line
// Tools would not help.
func homebrewInstallHint(err error) string {
	again := "run `" + CommandName + " setup` again (see " + setupTroubleshootingURL + ")"
	var hb *openshell.HomebrewInstallError
	if !errors.As(err, &hb) || !hb.Tools.OutdatedXcodeApp() {
		return "Homebrew says why above; most often Xcode or the Command Line Tools are older than it wants. Update them as it says, then " + again
	}
	t := hb.Tools
	return fmt.Sprintf("Homebrew says why above. The Command Line Tools %s, which xcode-select selects, are current for macOS %s, "+
		"but Homebrew checks Xcode %s at %s even so: update that Xcode (from the App Store) or delete it, as Homebrew says; "+
		"updating the Command Line Tools does not help. Then %s", openshell.ShortVersion(t.CLT), t.MacOS, t.Xcode, t.XcodeApp, again)
}

// consentGatewayRestart decides whether setup restarts the OpenShell
// gateway to apply its configuration. The gateway is shared: a restart
// drops the connections of every sandbox on it, of every owner and data
// dir. With none running it restarts; otherwise the user is asked (no by
// default), and --yes, --non-interactive or no terminal restart only with
// --restart-gateway. A gateway whose sandboxes cannot be listed counts as
// running some. microVM is a restart on the MicroVM driver, whose running
// sandboxes have their disks flushed and stop (the gateway's Restart
// flushes them: a MicroVM stopped without a flush loses what it wrote
// since its last one); switching one onto it, after which no sandbox made
// on the docker driver can start, so any sandbox on the gateway, running
// or not, is asked about.
func (a *App) consentGatewayRestart(ctx context.Context, o SetupOptions, assume, microVM, switching bool) (bool, error) {
	if o.RestartGateway {
		return true, nil
	}
	sandboxes, known := a.gatewaySandboxes(ctx, !switching)
	if known && len(sandboxes) == 0 {
		return true, nil
	}
	what := "the sandboxes on it could not be listed, so some may be running"
	if known {
		what = plural(int64(len(sandboxes)), "sandbox runs", "sandboxes run") + " on it (" + shortList(sandboxes) + ")"
	}
	switch {
	case switching && known:
		a.warn("applying this restarts the OpenShell gateway on the MicroVM driver: the " + plural(int64(len(sandboxes)), "sandbox", "sandboxes") +
			" on it (" + shortList(sandboxes) + ") were made on the docker driver, stop if running, and cannot start again unless the gateway is switched back")
	case switching:
		a.warn("applying this restarts the OpenShell gateway on the MicroVM driver, and " + what + "; sandboxes made on the docker driver cannot start again after it")
	case microVM:
		a.warn("applying this restarts the OpenShell gateway: its running MicroVM sandboxes have their disks flushed and stop, and " + what)
	default:
		a.warn("applying this restarts the OpenShell gateway, which drops the connections of every sandbox on it, and " + what)
	}
	return a.ask("Restart the OpenShell gateway now?", false, assume)
}

// restartStops says what a restart of a MicroVM gateway does to the
// sandboxes running on it, of every owner, for a doctor fix that restarts
// it: "" when none runs. Their disks are flushed before they stop
// (openshell.FlushSandboxes).
func (a *App) restartStops(ctx context.Context) string {
	running, known := a.runningSandboxes(ctx)
	if known && len(running) == 0 {
		return ""
	}
	what := "every sandbox running on it (they could not be listed)"
	if known {
		what = "the " + plural(int64(len(running)), "sandbox", "sandboxes") + " running on it (" + shortList(running) + ")"
	}
	return "this restarts the OpenShell gateway, which stops " + what + ", once their disks are flushed"
}

// manualRestartStops ends a line that leaves the restart of the OpenShell
// gateway to its user, for a gateway no gateway service runs: the restart
// stops every sandbox on it, of every owner, and DefenseClaw, which does
// not make it, cannot flush the MicroVM ones first. On the MicroVM driver
// (microVM) a sandbox stopped without a flush loses what it wrote since
// its last sync, so the running ones are to be stopped first with `sandbox
// stop`, which flushes their disks. The running sandboxes are named when
// the gateway lists them, but for those in gone (ones the caller removes
// before then).
func (a *App) manualRestartStops(ctx context.Context, microVM bool, gone []string) string {
	running, known := a.runningSandboxes(ctx)
	running = slices.DeleteFunc(running, func(name string) bool { return slices.Contains(gone, name) })
	names := ""
	if known && len(running) > 0 {
		names = " (" + shortList(running) + ")"
	}
	stop := "`" + CommandName + " stop NAME`"
	switch {
	case !microVM && names != "":
		return "restarting it stops every sandbox on it, and " + plural(int64(len(running)), "sandbox runs", "sandboxes run") + " on it now" + names
	case !microVM:
		return "restarting it stops every sandbox on it"
	case known && len(running) == 0:
		return "restarting it stops every sandbox on it (none runs now): stop a MicroVM sandbox you start before then first (" + stop +
			", which flushes its disk), or what it wrote since its last sync is lost"
	}
	return "restarting it stops every sandbox on it: first stop the MicroVM sandboxes running on it" + names + " with " + stop +
		", which flushes their disks, or what they wrote since their last sync is lost"
}

// shortList names at most five of names.
func shortList(names []string) string {
	shown := names
	if len(shown) > 5 {
		shown = append(slices.Clip(shown[:5]), fmt.Sprintf("%d more", len(names)-5))
	}
	return strings.Join(shown, ", ")
}

// runningSandboxes names the sandboxes on the OpenShell gateway that a
// restart would disrupt, of every owner. known is false when the gateway
// could not list them.
func (a *App) runningSandboxes(ctx context.Context) (names []string, known bool) {
	return a.gatewaySandboxes(ctx, true)
}

// gatewaySandboxes names the sandboxes on the OpenShell gateway, of every
// owner: with running, only those a restart would disrupt. known is false
// when the gateway could not list them.
func (a *App) gatewaySandboxes(ctx context.Context, running bool) (names []string, known bool) {
	c, _, err := a.OpenShell(ctx)
	if err != nil {
		return nil, false
	}
	defer c.Close()
	list, err := c.ListSandboxes(ctx, nil)
	if err != nil {
		return nil, false
	}
	for _, sb := range list {
		if sb == nil {
			continue
		}
		if !running || sb.Status.Phase == openshell.PhaseReady || sb.Status.Phase == openshell.PhaseProvisioning {
			names = append(names, sb.Name)
		}
	}
	sort.Strings(names)
	return names, true
}

// listDockerSandboxes says, before the question that switches the gateway
// to MicroVMs, which of DefenseClaw's sandboxes the switch strands: they
// were made on the docker driver, and `pull` starts a sandbox, so their
// work comes back only before the switch. On a Docker VM without Landlock
// they never ran.
func (a *App) listDockerSandboxes(ctx context.Context, rep *openshell.DoctorReport) {
	api, err := a.api()
	if err != nil {
		return
	}
	list, err := api.List(ctx)
	if err != nil || len(list) == 0 {
		return
	}
	names := make([]string, 0, len(list))
	for _, sb := range list {
		names = append(names, sb.Name)
	}
	sort.Strings(names)
	if failed(rep, openshell.CheckIDLandlock) {
		a.warn(plural(int64(len(names)), "sandbox was", "sandboxes were") + " made on the docker driver and never ran here (" + shortList(names) +
			"); after the switch they can only be deleted (`" + CommandName + " delete NAME`)")
		return
	}
	a.warn(plural(int64(len(names)), "sandbox runs", "sandboxes run") + " on the docker driver (" + shortList(names) + "): pull their work now (`" +
		CommandName + " pull NAME`); after the switch it is reachable only by switching back")
}

// microVMChanges are the gateway changes that run sandboxes in MicroVMs:
// the vm driver, this user as every sandbox's (whom the images are built
// for), and the recommended resources where the configuration leaves them
// unset.
func microVMChanges(rep *openshell.DoctorReport, state *openshell.GatewayConfigState, uid int) openshell.GatewayChanges {
	ch := openshell.GatewayChanges{ComputeDriver: openshell.DriverVM}
	id := openshell.VMIdentity{UID: int64(uid), GID: int64(os.Getegid())}
	want := openshell.RecommendedVMResources(0)
	if m := rep.MicroVM; m != nil {
		id, want = m.Identity, m.Recommended
	}
	ch.VMIdentity = &id
	if res := state.VM.Unset(want); res != (openshell.VMResources{}) {
		ch.VMResources = &res
	}
	return ch
}

// prepareMicroVMs installs, with consent, what the MicroVM driver needs
// on this Mac: e2fsprogs, and a driver signed for Apple's Hypervisor. It
// follows the OpenShell install's consent: --install-openshell or --yes
// consent, --non-interactive alone installs nothing, and a no stops setup
// with the command to run. It returns the doctor report of the machine as
// it is then.
func (a *App) prepareMicroVMs(ctx context.Context, o SetupOptions, rep *openshell.DoctorReport) (*openshell.DoctorReport, error) {
	m := rep.MicroVM
	if m == nil {
		return rep, nil
	}
	consent := func(question string) (bool, error) {
		if o.InstallOpenShell || o.Yes {
			return true, nil
		}
		if o.NonInteractive {
			return false, nil
		}
		return a.ask(question, false, false)
	}
	stop := func(what, command string) error {
		a.bad("MicroVM driver: " + what)
		a.note("→ run `" + command + "`, then `" + CommandName + " setup` again")
		return &Silent{Err: fmt.Errorf("the OpenShell MicroVM driver needs %s", what)}
	}
	changed := false
	if m.E2fsprogs == "" {
		yes, err := consent("Install e2fsprogs with Homebrew? The MicroVM driver formats its disks with it (" + openshell.InstallE2fsprogsCommand + ")")
		if err != nil {
			return nil, err
		}
		if !yes {
			return nil, stop("e2fsprogs, which it formats its disks with", openshell.InstallE2fsprogsCommand)
		}
		a.note("Installing e2fsprogs with Homebrew…")
		if err := a.Installer(nil).InstallE2fsprogs(ctx); err != nil {
			if serr := a.homebrewNotWritable(err); serr != nil {
				return nil, serr
			}
			return nil, fmt.Errorf("install e2fsprogs: %w", err)
		}
		a.ok("e2fsprogs installed")
		changed = true
	}
	if m.DriverBinary != "" && !m.HypervisorSigned && m.SignatureUnknown == "" && !m.DriverFromFormula {
		// The formula's post-install step signs only the formula's driver.
		a.bad("MicroVM driver: " + m.DriverBinary + " is not signed for Apple's Hypervisor")
		a.note("→ " + openshell.VMDriverSigningFix(m.DriverBinary) + ", then run `" + CommandName + " setup` again")
		return nil, &Silent{Err: fmt.Errorf("the OpenShell MicroVM driver needs %s signed for Apple's Hypervisor", m.DriverBinary)}
	}
	if m.DriverBinary != "" && !m.HypervisorSigned && m.SignatureUnknown == "" {
		yes, err := consent("Re-run the OpenShell formula's post-install step so its MicroVM driver is signed for Apple's Hypervisor? (" + openshell.ResignVMDriverCommand + ")")
		if err != nil {
			return nil, err
		}
		if !yes {
			return nil, stop(m.DriverBinary+" signed for Apple's Hypervisor", openshell.ResignVMDriverCommand)
		}
		if err := a.Installer(nil).ResignVMDriver(ctx); err != nil {
			return nil, fmt.Errorf("sign the MicroVM driver: %w", err)
		}
		a.ok("MicroVM driver signed for Apple's Hypervisor")
		changed = true
	}
	if changed {
		rep = a.runDoctor(ctx)
	}
	if rep.MicroVM != nil {
		if problems := rep.MicroVM.Problems(); len(problems) > 0 {
			a.bad("MicroVM driver: " + strings.Join(problems, "; "))
			if c := rep.Get(openshell.CheckIDVMDriver); c != nil && c.Fix != nil {
				a.note("→ " + c.Fix.Line())
			}
			return nil, &Silent{Err: errors.New("this machine cannot run MicroVM sandboxes yet (MicroVM driver)")}
		}
	}
	return rep, nil
}

// machineFailure prints the first machine check that keeps sandboxes
// from running, with the way on, and returns it already printed.
// landlockLater leaves out the Landlock check, which the question that
// switches a Mac to MicroVMs decides.
func (a *App) machineFailure(rep *openshell.DoctorReport, landlockLater bool) error {
	for _, id := range []string{openshell.CheckIDPlatform, openshell.CheckIDUser, openshell.CheckIDLandlock, openshell.CheckIDDocker} {
		if id == openshell.CheckIDLandlock && landlockLater {
			continue
		}
		if c := rep.Get(id); c != nil && c.Status == openshell.StatusFail {
			a.bad(c.Title + ": " + c.Detail)
			if c.Fix != nil {
				a.note("→ " + c.Fix.Line())
			}
			return &Silent{Err: fmt.Errorf("this machine cannot run sandboxes yet (%s)", c.Title)}
		}
	}
	return nil
}

func failed(rep *openshell.DoctorReport, id string) bool {
	c := rep.Get(id)
	return c != nil && c.Status == openshell.StatusFail
}

// machineLine is "✓ linux/arm64  ✓ Landlock …  ✓ Docker 29.4  ✗ OpenShell not installed".
func (a *App) machineLine(rep *openshell.DoctorReport) string {
	// On a Mac without OpenShell the MicroVM driver is missing for the same
	// reason, and the formula the install brings it with: one mark, not
	// "✗ MicroVM driver  ✗ OpenShell not installed".
	cli, driver := rep.Get(openshell.CheckIDCLI), rep.Get(openshell.CheckIDVMDriver)
	withoutDriver := cli != nil && cli.Status == openshell.StatusFail && rep.CLIVersion == "" && driver != nil && driver.Status == openshell.StatusFail &&
		rep.MicroVM != nil && rep.MicroVM.DriverBinary == "" && !rep.MicroVM.DriverRunning
	var parts []string
	for _, id := range []string{openshell.CheckIDPlatform, openshell.CheckIDLandlock, openshell.CheckIDDocker, openshell.CheckIDVMDriver, openshell.CheckIDCLI} {
		c := rep.Get(id)
		if c == nil || c.Status == openshell.StatusSkip || (id == openshell.CheckIDVMDriver && withoutDriver) {
			continue
		}
		label, mark := c.Title, a.mark(c.Status != openshell.StatusFail)
		switch id {
		case openshell.CheckIDLandlock:
			switch {
			case rep.Driver == openshell.DriverVM:
				label = "Landlock (MicroVM)"
			case c.Status == openshell.StatusWarn:
				// Off Linux it may not have run (no image to check in yet).
				label, mark = "Landlock not checked", a.style("⚠", ansiYellow)
			}
		case openshell.CheckIDPlatform:
			label = strings.SplitN(c.Detail, ":", 2)[0]
		case openshell.CheckIDDocker:
			if rep.DockerVersion != "" {
				label = "Docker " + rep.DockerVersion
			}
		case openshell.CheckIDCLI:
			switch {
			case a.GOOS == "darwin" && rep.OpenShellOutsideFormula():
				// Its gateway is the user's to start and restart, as the
				// TUI's machine check marks it (RT-A-1): setup says so, or
				// stops where it would have to start it.
				label, mark = "OpenShell", a.style("⚠", ansiYellow)
				if rep.CLIVersion != "" {
					label += " " + rep.CLIVersion
				}
				label += " is not from Homebrew's nvidia/openshell formula"
			case a.GOOS == "linux" && rep.OpenShellOutsideUnit():
				label, mark = "OpenShell", a.style("⚠", ansiYellow)
				if rep.CLIVersion != "" {
					label += " " + rep.CLIVersion
				}
				label += " has no " + openshell.GatewayService + " user service"
			case withoutDriver:
				label = "OpenShell and its MicroVM driver not installed"
			case c.Status == openshell.StatusFail:
				label = "OpenShell not installed"
				if rep.CLIVersion != "" {
					label = "OpenShell " + rep.CLIVersion + " unsupported"
				}
			case rep.CLIVersion != "":
				label = "OpenShell " + rep.CLIVersion
			}
		}
		parts = append(parts, mark+" "+label)
	}
	return strings.Join(parts, "  ")
}

// restartImpact completes "restarts the OpenShell gateway" with what the
// restart disrupts now: the sandboxes running on the shared gateway, of
// every owner.
func (a *App) restartImpact(ctx context.Context) string {
	running, known := a.runningSandboxes(ctx)
	switch {
	case !known:
		return ", which drops the connections of any sandbox running on it"
	case len(running) == 0:
		return "; no sandbox runs on it now"
	}
	return ", which drops the connections of the " + plural(int64(len(running)), "sandbox", "sandboxes") + " running on it"
}

// launchedCommands are harness commands people do not type: another
// command they do type starts them (Kiro's kiro-cli starts kiro-cli-chat,
// the agent the launcher runs). A shell wrapper of such a command never
// runs, and the harness is named by its connector name instead.
var launchedCommands = map[string]string{"kiro-cli-chat": "kiro-cli"}

// namelessCommands are harness commands that do not say which harness they
// run: the harness is named by its connector name, as `image build`,
// `image list` and openshell.harnesses name it (Antigravity's agy).
var namelessCommands = map[string]bool{"agy": true}

// HarnessArg is how a user names spec on the command line (`sandbox run`,
// --harness, `image build`): the command they type for it (claude, codex),
// or its connector name when that command is one they never type (kiro) or
// does not name the harness (antigravity, whose agy is accepted too).
func HarnessArg(spec *harness.Spec) string {
	if _, ok := launchedCommands[spec.Command]; ok || namelessCommands[spec.Command] {
		return spec.Name
	}
	return spec.Command
}

// mergeHarnesses is openshell.harnesses with specs added: setting up one
// more harness keeps those set up before. Entries that name a known
// harness are recorded by its connector name.
func mergeHarnesses(configured []string, specs []*harness.Spec) []string {
	var out []string
	add := func(n string) {
		if n != "" && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	for _, n := range configured {
		if spec, err := ResolveHarness(n); err == nil {
			n = spec.Name
		}
		add(strings.TrimSpace(n))
	}
	for _, s := range specs {
		add(s.Name)
	}
	return out
}

// printHarnesses shows the harnesses this setup sets up, one line each
// with the model credential a run would share (or how to get one), then
// the ones set up before and the others --harness adds.
func (a *App) printHarnesses(specs []*harness.Spec, configured []string) {
	a.line("Harnesses (add another with `" + CommandName + " setup --harness NAME`):")
	width := 0
	for _, s := range specs {
		width = max(width, len(s.DisplayName)+len(HarnessArg(s))+3)
	}
	for _, s := range specs {
		a.line(fmt.Sprintf("  %-*s  %s", width, s.DisplayName+" ("+HarnessArg(s)+")", a.credentialText(s)))
	}
	var earlier, others []string
	for _, h := range harness.Names() {
		spec, _ := harness.Get(h)
		name := HarnessArg(spec)
		if spec.Verification().Status == harness.Unverified {
			name += " (not verified yet)"
		}
		switch {
		case slices.ContainsFunc(specs, func(s *harness.Spec) bool { return s.Name == h }):
		case slices.Contains(configured, h):
			earlier = append(earlier, name)
		default:
			others = append(others, name)
		}
	}
	sort.Strings(earlier)
	sort.Strings(others)
	if len(earlier) > 0 {
		a.line("Set up before: " + strings.Join(earlier, ", "))
	}
	if len(others) > 0 {
		a.line("Other harnesses: " + strings.Join(others, ", "))
	}
}

// credentialText is the model credential a run of s would share, or the
// next step when there is none. It follows openshell.llm as a run does: a
// configured provider without its key refuses the run (there is no sandbox
// to log in inside), and none shares nothing whatever keys are set.
func (a *App) credentialText(s *harness.Spec) string {
	choice, from, _ := a.runLLM(s, "")
	llm, err := a.detectLLM(s, choice, from, "", nil)
	switch {
	case err == nil && llm.Credential != nil:
		return "model credential " + llm.Source + " " + a.style("✓", ansiGreen)
	case err != nil && from == llmFromConfig:
		return "model credential " + a.style("none found", ansiYellow) + ": runs are refused until you " +
			a.providerHint(s, choice) + " (" + from + " " + choice + "; `--llm auto` overrides it for one run)"
	case choice == LLMNone:
		return "model credential " + a.style("none shared", ansiYellow) + " (" + from + " none): you log in inside the sandbox on the first run"
	}
	next := "you log in inside the sandbox on the first run"
	if hint := a.llmHint(s, choice); hint != a.llmHint(&harness.Spec{}, choice) {
		next = "before the first run, " + hint + "; or log in inside the sandbox"
	}
	return "model credential " + a.style("none found", ansiYellow) + ": " + next
}

// importIngressProfile imports the provider profile of this config's hook
// ingress listener (profiles.IngressProfileID) when the gateway lacks it
// (best effort: the daemon imports missing profiles at the first run too).
// With token_delivery: env no sandbox uses it.
func (a *App) importIngressProfile(ctx context.Context) {
	if strings.EqualFold(a.Cfg.OpenShell.TokenDelivery, config.OpenShellTokenDeliveryEnv) {
		return
	}
	p, err := profiles.Render(profiles.IngressID, profiles.Input{IngressPort: a.Cfg.OpenShellIngressPort()})
	if err != nil {
		return
	}
	c, reg, err := a.OpenShell(ctx)
	if err != nil {
		return
	}
	defer c.Close()
	if _, err := c.GetProfile(ctx, p.ID); err == nil || !openshell.IsNotFound(err) {
		return
	}
	imp := manager.CLIProfileImporter{Binary: a.Cfg.OpenShell.EffectiveBinary()}
	if err := imp.Import(ctx, reg.Name, p, 0); err != nil {
		a.warn("could not import the " + p.ID + " provider profile (the first run imports it): " + err.Error())
	}
}

// undrivenGatewayDriver says why the local gateway runs, or its
// configuration selects, a compute driver DefenseClaw does not drive, or
// returns "" when it does not.
func undrivenGatewayDriver(rep *openshell.DoctorReport, state *openshell.GatewayConfigState) string {
	if state != nil {
		if _, ok := state.Driver(); !ok {
			return fmt.Sprintf("its configuration selects the %q compute driver, which DefenseClaw does not drive", state.ComputeDriver)
		}
	}
	if rep != nil {
		if c := rep.Get(openshell.CheckIDGatewayDriver); c != nil && c.Status == openshell.StatusFail {
			return c.Detail
		}
	}
	return ""
}

// waitDaemon waits briefly for the daemon to turn sandboxes on and, when
// driver is set, to drive the gateway on it: the daemon learns a driver
// switch when it next asks the gateway. It reports false when the daemon
// answers but has not turned sandboxes on, and noDockerGroup when the
// daemon started before its user joined the docker group (GAP-2137).
func (a *App) waitDaemon(ctx context.Context, driver openshell.ComputeDriver) (ready, noDockerGroup bool) {
	api, err := a.api()
	if err != nil {
		return true, false
	}
	const wait, poll = 30 * time.Second, 2 * time.Second
	deadline := a.Now().Add(wait)
	for polls := 1; ; polls++ {
		st, err := api.Status(ctx)
		// An older daemon names no driver: docker.
		drives := openshell.DriverDocker
		if err == nil && st.Gateway != nil && st.Gateway.Driver != "" {
			drives = openshell.ComputeDriver(st.Gateway.Driver)
		}
		switch {
		case err != nil:
			a.warn("the DefenseClaw daemon is not running; start it with `defenseclaw-gateway start`")
			return true, false
		case st.Enabled && st.Available && (driver == "" || drives == driver):
			a.ok("the daemon runs the sandbox subsystem (ingress " + st.IngressAddr + ", egress proxy " + st.EgressAddr + ")")
			return true, st.DockerGroupMissing
		}
		// The polls bound the wait when the clock does not move.
		if a.Now().After(deadline) || time.Duration(polls)*poll >= wait {
			if st.Enabled && st.Available {
				a.warn(fmt.Sprintf("the daemon still drives the OpenShell gateway as the %s driver, not %s; restart it (`defenseclaw-gateway restart`) "+
					"if `%s doctor` says the same", drives, driver, CommandName))
				return true, false
			}
			a.warn("the daemon has not turned sandboxes on yet: " + firstNonEmpty(st.Reason, "see `"+CommandName+" doctor`"))
			return false, false
		}
		if a.Sleep(ctx, poll) != nil {
			return true, false
		}
	}
}
