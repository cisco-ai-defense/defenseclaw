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
	"sort"
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
	// A saved openshell.upstream_telemetry: true is an earlier answer to
	// keep it, which setup does not ask again.
	keepTelemetry := o.UpstreamTelemetry || a.Cfg.OpenShell.UpstreamTelemetry
	telemetryOff := !keepTelemetry
	if a.GOOS == "darwin" {
		// Homebrew's launchd service does not read gateway.env (the doctor
		// skips the telemetry check there): nothing to ask or change.
		if telemetryOff {
			a.note("OpenShell's anonymous usage telemetry stays on under Homebrew (its service does not read gateway.env)")
		}
	} else {
		switch {
		case keepTelemetry && !o.UpstreamTelemetry && state.TelemetryEnabled():
			a.note("OpenShell's anonymous usage telemetry stays on (openshell.upstream_telemetry is true in " + a.tildePath(a.ConfigPath) + ")")
		case !keepTelemetry && state.TelemetryEnabled():
			// Say what a yes costs before it is given: an edit of
			// gateway.env and a restart of the shared gateway.
			yes, err := a.ask("Disable OpenShell's anonymous usage telemetry? (edits "+a.tildePath(firstNonEmpty(state.EnvPath, "gateway.env"))+
				" and restarts the OpenShell gateway"+a.restartImpact(ctx)+")", true, assume)
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
	// Steps left out say so at the end, with the command that does them.
	var skipped []string
	if changes.EnableBindMounts || len(changes.Env) > 0 || len(changes.UnsetEnv) > 0 {
		plan, err := a.Gateway.Plan(ctx, changes)
		if err != nil {
			return fmt.Errorf("plan the gateway change: %w", err)
		}
		if !plan.Empty() {
			for _, l := range strings.Split(strings.TrimRight(plan.String(), "\n"), "\n") {
				a.note(l)
			}
			restart, err := a.consentGatewayRestart(ctx, o, assume)
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
				a.ok("gateway configured and restarted")
			} else {
				skipped = append(skipped, "the OpenShell gateway change above (it restarts the gateway; apply it with `"+
					CommandName+" doctor --fix` or `"+CommandName+" setup --restart-gateway`)")
			}
		}
	}
	if copyOnly {
		a.note("without bind mounts every run works on a copy (`--copy`)")
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
				if err := a.Enable(WrapperOptions{Harness: s.Name}); err != nil {
					a.warn("wrapper for " + s.Command + ": " + err.Error())
				}
			}
		} else if o.NonInteractive && !o.NoWrappers {
			skipped = append(skipped, "shell wrappers (not asked with --non-interactive; add one with `"+CommandName+" enable "+HarnessArg(wrappable[0])+"`)")
		}
	}
	cmd := "claude"
	if len(specs) > 0 {
		cmd = HarnessArg(specs[0])
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
				current, err := a.Images.Current(s)
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
			if err := a.buildImage(ctx, s, false, false); err != nil {
				return err
			}
		}
	} else {
		skipped = append(skipped, "harness images (--skip-images; the first run builds them, or `"+CommandName+" image build`)")
	}
	a.importIngressProfile(ctx)

	// 8. The daemon picks the change up.
	a.waitDaemon(ctx)
	for _, s := range skipped {
		a.note("skipped: " + s)
	}
	a.println()
	a.ok("Done →  cd <project> && " + CommandName + " run " + cmd)
	return nil
}

// consentGatewayRestart decides whether setup restarts the OpenShell
// gateway to apply its configuration. The gateway is shared: a restart
// drops the connections of every sandbox on it, of every owner and data
// dir. With none running it restarts; otherwise the user is asked (no by
// default), and --yes, --non-interactive or no terminal restart only with
// --restart-gateway. A gateway whose sandboxes cannot be listed counts as
// running some.
func (a *App) consentGatewayRestart(ctx context.Context, o SetupOptions, assume bool) (bool, error) {
	if o.RestartGateway {
		return true, nil
	}
	running, known := a.runningSandboxes(ctx)
	if known && len(running) == 0 {
		return true, nil
	}
	what := "the sandboxes on it could not be listed, so some may be running"
	if known {
		shown := running
		if len(shown) > 5 {
			shown = append(slices.Clip(shown[:5]), fmt.Sprintf("%d more", len(running)-5))
		}
		what = plural(int64(len(running)), "sandbox runs", "sandboxes run") + " on it (" + strings.Join(shown, ", ") + ")"
	}
	a.warn("applying this restarts the OpenShell gateway, which drops the connections of every sandbox on it, and " + what)
	return a.ask("Restart the OpenShell gateway now?", false, assume)
}

// runningSandboxes names the sandboxes on the OpenShell gateway that a
// restart would disrupt, of every owner. known is false when the gateway
// could not list them.
func (a *App) runningSandboxes(ctx context.Context) (names []string, known bool) {
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
		if sb.Status.Phase == openshell.PhaseReady || sb.Status.Phase == openshell.PhaseProvisioning {
			names = append(names, sb.Name)
		}
	}
	sort.Strings(names)
	return names, true
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

// HarnessArg is how a user names spec on the command line (`sandbox run`,
// --harness): the command they type for it (claude, codex, agy), or its
// connector name when that command is one they never type (kiro).
func HarnessArg(spec *harness.Spec) string {
	if _, ok := launchedCommands[spec.Command]; ok {
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
// next step when there is none.
func (a *App) credentialText(s *harness.Spec) string {
	if llm, err := a.detectLLM(s, LLMAuto, "", nil); err == nil && llm.Credential != nil {
		return "model credential " + llm.Source + " " + a.style("✓", ansiGreen)
	}
	next := "you log in inside the sandbox on the first run"
	if hint := llmHint(s.Name, LLMAuto); hint != llmHint("", LLMAuto) {
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
