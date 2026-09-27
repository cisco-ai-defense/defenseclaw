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
	"slices"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
)

// Installer installs OpenShell (openshell.Installer).
type Installer interface {
	Install(ctx context.Context) (*openshell.InstallResult, error)
}

func (a *App) defaultInstaller(consent func(*openshell.InstallPlan) (bool, error)) Installer {
	d := openshell.DiscoverOptions{}
	if a.Cfg != nil {
		d.Gateway = a.Cfg.OpenShell.Gateway.Name
	}
	return &openshell.Installer{
		Out: a.IO.Out, Consent: consent, Discover: d,
		ConfirmBreakingUpgrade: func(*openshell.InstallPlan) (bool, error) {
			return a.ask("An OpenShell 0.0.x runtime is installed; 0.1 cannot use its state. Have you backed it up and cleaned it up (`defenseclaw sandbox legacy-cleanup`)?", false, false)
		},
	}
}

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
		return errors.New("DefenseClaw is not set up yet; run `defenseclaw setup` first")
	}
	assume := o.Yes || o.NonInteractive || !a.IO.TTY
	a.println()
	a.println(a.bold("DefenseClaw sandbox setup"))

	// 1. The machine.
	rep := a.runDoctor(ctx)
	a.printf("  Checking this machine…  %s\n", a.machineLine(rep))
	for _, id := range []string{openshell.CheckIDPlatform, openshell.CheckIDUser, openshell.CheckIDLandlock, openshell.CheckIDDocker} {
		if c := rep.Get(id); c != nil && c.Status == openshell.StatusFail {
			a.bad(c.Title + ": " + c.Detail)
			if c.Fix != nil {
				a.note("→ " + c.Fix.Summary + " " + c.Fix.Command)
			}
			return &Silent{Err: fmt.Errorf("this machine cannot run sandboxes yet (%s)", c.Title)}
		}
	}

	// 2. OpenShell.
	if cli := rep.Get(openshell.CheckIDCLI); cli == nil || cli.Status == openshell.StatusFail ||
		failed(rep, openshell.CheckIDGatewayVersion) || failed(rep, openshell.CheckIDGatewayService) {
		install := o.InstallOpenShell
		if !install && !o.NonInteractive {
			var err error
			install, err = a.ask("Install OpenShell "+openshell.SupportedMin+" with NVIDIA's installer? (sudo; sha256 verified)", false, o.Yes)
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
		if err != nil {
			return fmt.Errorf("install OpenShell: %w", err)
		}
		if res.Installed {
			a.ok("OpenShell " + res.CLIVersion.String() + " installed, gateway running")
		} else {
			a.ok("OpenShell " + res.CLIVersion.String() + " is already installed")
		}
		rep = a.runDoctor(ctx)
	}
	for _, id := range []string{openshell.CheckIDCLI, openshell.CheckIDRegistration, openshell.CheckIDMTLS, openshell.CheckIDGatewayVersion} {
		if c := rep.Get(id); c != nil && c.Status == openshell.StatusFail {
			a.bad(c.Title + ": " + c.Detail)
			if c.Fix != nil {
				a.note("→ " + c.Fix.Summary + " " + c.Fix.Command)
			}
			return &Silent{Err: fmt.Errorf("the OpenShell gateway is not usable yet (%s); see `%s doctor`", c.Title, CommandName)}
		}
	}

	// 3. Bind mounts and upstream telemetry: one plan, one restart.
	state, err := a.Gateway.State()
	if err != nil {
		return fmt.Errorf("read the OpenShell gateway configuration: %w", err)
	}
	changes := openshell.GatewayChanges{}
	copyOnly := o.NoMounts
	if !o.NoMounts && !state.BindMounts.Enabled() {
		yes, err := a.ask("Allow sandboxes to mount the project folder you launch from? (enables bind mounts on your local OpenShell gateway; DefenseClaw only ever mounts the launch folder)", true, assume)
		if err != nil {
			return err
		}
		changes.EnableBindMounts = yes
		copyOnly = !yes
	}
	telemetryOff := !o.UpstreamTelemetry
	if !o.UpstreamTelemetry && state.TelemetryEnabled() {
		yes, err := a.ask("Disable OpenShell's anonymous usage telemetry?", true, assume)
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
	if changes.EnableBindMounts || len(changes.Env) > 0 || len(changes.UnsetEnv) > 0 {
		plan, err := a.Gateway.Plan(ctx, changes)
		if err != nil {
			return fmt.Errorf("plan the gateway change: %w", err)
		}
		if !plan.Empty() {
			for _, l := range strings.Split(strings.TrimRight(plan.String(), "\n"), "\n") {
				a.note(l)
			}
			res, err := a.Gateway.Apply(ctx, plan)
			if rerr := a.recordGatewayApply(res); rerr != nil {
				a.warn("could not record the gateway change for teardown: " + rerr.Error())
			}
			if err != nil {
				return fmt.Errorf("change the gateway configuration: %w", err)
			}
			a.ok("gateway configured and restarted")
		}
	}
	if copyOnly {
		a.note("without bind mounts every run works on a copy (`--copy`)")
	}

	// 4. Harnesses and credentials.
	specs, err := a.harnesses(o.Harnesses)
	if err != nil {
		return err
	}
	var names, labels []string
	for _, s := range specs {
		names = append(names, s.Name)
		labels = append(labels, "[x] "+s.DisplayName)
	}
	for _, h := range harness.Names() {
		if !slices.Contains(names, h) {
			spec, _ := harness.Get(h)
			labels = append(labels, "[ ] "+spec.DisplayName)
		}
	}
	a.printf("  Harnesses: %s    Credentials: %s\n", strings.Join(labels, " "), a.credentialLine(specs))

	// 5. The configuration.
	updates := map[string]any{
		"openshell.enabled": true, "openshell.harnesses": names, "openshell.upstream_telemetry": !telemetryOff,
	}
	if copyOnly && (a.Cfg.OpenShell.Workdir.Mode == "" || a.Cfg.OpenShell.Workdir.Mode == config.OpenShellWorkdirMount) {
		updates["openshell.workdir.mode"] = config.OpenShellWorkdirCopy
	}
	if err := a.patchConfig(updates); err != nil {
		return err
	}
	a.Cfg.OpenShell.Enabled, a.Cfg.OpenShell.Harnesses, a.Cfg.OpenShell.UpstreamTelemetry = true, names, !telemetryOff
	a.ok("openshell.enabled is on in " + a.tildePath(a.ConfigPath))

	// 6. Wrappers.
	wrap := o.Wrappers
	if !wrap && !o.NoWrappers && !o.NonInteractive {
		var cmds []string
		for _, s := range specs {
			cmds = append(cmds, "`"+s.Command+"`")
		}
		wrap, err = a.ask("Make "+strings.Join(cmds, " and ")+" run sandboxed automatically? (shell wrapper; undo any time)", false, o.Yes)
		if err != nil {
			return err
		}
	}
	if wrap {
		for _, s := range specs {
			if err := a.Enable(WrapperOptions{Harness: s.Name}); err != nil {
				a.warn("wrapper for " + s.Command + ": " + err.Error())
			}
		}
	}

	// 7. Images, then the ingress provider profile (imported once here:
	// every profile import briefly drops running sandboxes' connections).
	if !o.SkipImages {
		for _, s := range specs {
			if err := a.buildImage(ctx, s, false, false); err != nil {
				return err
			}
		}
	}
	a.importIngressProfile(ctx)

	// 8. The daemon picks the change up.
	a.waitDaemon(ctx)
	cmd := "claude"
	if len(specs) > 0 {
		cmd = specs[0].Command
	}
	a.println()
	a.ok("Done →  cd <project> && " + CommandName + " run " + cmd)
	return nil
}

func failed(rep *openshell.DoctorReport, id string) bool {
	c := rep.Get(id)
	return c != nil && c.Status == openshell.StatusFail
}

// machineLine is "✓ linux/arm64  ✓ Landlock …  ✓ Docker 29.4  ✗ OpenShell not installed".
func (a *App) machineLine(rep *openshell.DoctorReport) string {
	var parts []string
	for _, id := range []string{openshell.CheckIDPlatform, openshell.CheckIDLandlock, openshell.CheckIDDocker, openshell.CheckIDCLI} {
		c := rep.Get(id)
		if c == nil || c.Status == openshell.StatusSkip {
			continue
		}
		label := c.Title
		switch id {
		case openshell.CheckIDPlatform:
			label = strings.SplitN(c.Detail, ":", 2)[0]
		case openshell.CheckIDDocker:
			if rep.DockerVersion != "" {
				label = "Docker " + rep.DockerVersion
			}
		case openshell.CheckIDCLI:
			switch {
			case c.Status == openshell.StatusFail:
				label = "OpenShell not installed"
				if rep.CLIVersion != "" {
					label = "OpenShell " + rep.CLIVersion + " unsupported"
				}
			case rep.CLIVersion != "":
				label = "OpenShell " + rep.CLIVersion
			}
		}
		parts = append(parts, a.mark(c.Status != openshell.StatusFail)+" "+label)
	}
	return strings.Join(parts, "  ")
}

// credentialLine lists the model credentials a run would share.
func (a *App) credentialLine(specs []*harness.Spec) string {
	var parts []string
	for _, s := range specs {
		llm, err := a.detectLLM(s, LLMAuto, "", nil)
		switch {
		case err != nil || llm.Credential == nil:
			parts = append(parts, s.Command+": "+a.style("none found", ansiYellow))
		default:
			parts = append(parts, llm.Source+" "+a.style("✓", ansiGreen))
		}
	}
	return strings.Join(parts, "  ")
}

// importIngressProfile imports the DefenseClaw ingress provider profile
// when the gateway lacks it (best effort: the daemon imports missing
// profiles at the first run too).
func (a *App) importIngressProfile(ctx context.Context) {
	c, reg, err := a.OpenShell(ctx)
	if err != nil {
		return
	}
	defer c.Close()
	if _, err := c.GetProfile(ctx, profiles.IngressID); err == nil || !openshell.IsNotFound(err) {
		return
	}
	p, err := profiles.Render(profiles.IngressID, profiles.Input{IngressPort: a.Cfg.OpenShellIngressPort()})
	if err != nil {
		return
	}
	imp := manager.CLIProfileImporter{Binary: a.Cfg.OpenShell.EffectiveBinary()}
	if err := imp.Import(ctx, reg.Name, p, false); err != nil {
		a.warn("could not import the " + profiles.IngressID + " provider profile (the first run imports it): " + err.Error())
	}
}

// waitDaemon waits briefly for the daemon to turn sandboxes on.
func (a *App) waitDaemon(ctx context.Context) {
	api, err := a.api()
	if err != nil {
		return
	}
	deadline := a.Now().Add(30 * time.Second)
	for {
		st, err := api.Status(ctx)
		switch {
		case err != nil:
			a.warn("the DefenseClaw daemon is not running; start it with `defenseclaw-gateway start`")
			return
		case st.Enabled && st.Available:
			a.ok("the daemon runs the sandbox subsystem (ingress " + st.IngressAddr + ", egress proxy " + st.EgressAddr + ")")
			return
		}
		if a.Now().After(deadline) {
			a.warn("the daemon has not turned sandboxes on yet: " + firstNonEmpty(st.Reason, "see `"+CommandName+" doctor`"))
			return
		}
		if a.Sleep(ctx, 2*time.Second) != nil {
			return
		}
	}
}
