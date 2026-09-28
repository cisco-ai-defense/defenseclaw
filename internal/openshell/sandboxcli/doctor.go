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
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/wrapper"
)

// DefenseClaw doctor check IDs (the host checks are openshell.CheckID*).
const (
	CheckIDDaemon   = "defenseclaw-daemon"
	CheckIDImages   = "overlay-images"
	CheckIDWrappers = "shell-wrappers"
	CheckIDAdmin    = "admin-policy"
	CheckIDHooks    = "sandbox-hooks"
)

// DoctorOptions are the `sandbox doctor` flags.
type DoctorOptions struct {
	Output OutputFormat
	Fix    bool
	Yes    bool
}

func (a *App) defaultDoctor() *openshell.Doctor {
	d := &openshell.Doctor{}
	if a.Cfg != nil {
		o := a.Cfg.OpenShell
		d.CLI = o.EffectiveBinary()
		d.Discover = openshell.DiscoverOptions{Gateway: o.Gateway.Name}
		want := o.UpstreamTelemetry
		d.WantTelemetry = &want
		d.BindMountsOptional = o.Workdir.Mode == config.OpenShellWorkdirCopy
		d.Ports = []openshell.PortRequirement{
			{Name: "ingress", Port: a.Cfg.OpenShellIngressPort()},
			{Name: "egress", Port: a.Cfg.OpenShellEgressPort()},
		}
	}
	return d
}

// runDoctor runs the host checks plus DefenseClaw's own.
func (a *App) runDoctor(ctx context.Context) *openshell.DoctorReport {
	a.defaults()
	d := a.defaultDoctor()
	var st *statusProbe
	if a.Cfg != nil {
		st = a.probeDaemon(ctx)
		for i := range d.Ports {
			// The running daemon holds its own listeners.
			d.Ports[i].ServedByDaemon = st.listening
		}
		if st.listening {
			uid := os.Getuid()
			d.DaemonUID = &uid
		}
	}
	rep := a.HostDoctor(ctx, d)
	if st != nil {
		rep.Checks = append(rep.Checks, st.check)
		if st.available {
			rep.Checks = append(rep.Checks, a.hooksCheck(ctx, st.ingress))
		}
		rep.Checks = append(rep.Checks, a.imagesCheck(), a.wrappersCheck(), a.adminCheck())
	}
	return rep
}

type statusProbe struct {
	listening bool
	// available is set when the daemon serves sandboxes; ingress is its
	// hook ingress address.
	available bool
	ingress   string
	check     openshell.Check
}

// hooksCheck reports the sandboxes whose current session's hooks do not
// reach DefenseClaw, with the daemon's reason for each.
func (a *App) hooksCheck(ctx context.Context, ingress string) openshell.Check {
	c := openshell.Check{ID: CheckIDHooks, Title: "Sandbox hooks", Status: openshell.StatusPass}
	api, err := a.api()
	if err != nil {
		c.Status, c.Detail = openshell.StatusSkip, err.Error()
		return c
	}
	list, err := api.List(ctx)
	if err != nil {
		c.Status, c.Detail = openshell.StatusWarn, "could not list the sandboxes: "+apiError(err).Error()
		return c
	}
	var bad []string
	running := 0
	for _, sb := range list {
		if sb.Phase == "ready" {
			running++
		}
		if sb.Hooks.Unreachable {
			bad = append(bad, sb.Name+": "+firstNonEmpty(sb.Hooks.UnreachableReason, "no hook request reaches DefenseClaw"))
		}
	}
	switch {
	case len(bad) > 0:
		c.Status = openshell.StatusFail
		c.Detail = "hooks do not reach the ingress " + firstNonEmpty(ingress, "(unknown)") + ", so every tool call fails closed: " + strings.Join(bad, "; ")
		c.Fix = &openshell.Fix{Summary: "fix the cause above, then start the session again"}
	case running == 0:
		c.Detail = "no sandbox is running"
	default:
		c.Detail = fmt.Sprintf("the hooks of %s reach DefenseClaw (ingress %s)", plural(int64(running), "running sandbox", "running sandboxes"), firstNonEmpty(ingress, "(unknown)"))
	}
	return c
}

func (a *App) probeDaemon(ctx context.Context) *statusProbe {
	c := openshell.Check{ID: CheckIDDaemon, Title: "DefenseClaw daemon"}
	p := &statusProbe{}
	api, err := a.api()
	if err == nil {
		st, serr := api.Status(ctx)
		switch {
		case serr != nil:
			c.Status, c.Detail = openshell.StatusFail, apiError(serr).Error()
			c.Fix = &openshell.Fix{Summary: "start the daemon", Command: "defenseclaw-gateway start"}
		case !st.Enabled:
			c.Status, c.Detail = openshell.StatusWarn, "openshell.enabled is false: sandboxes are off"
			c.Fix = &openshell.Fix{Summary: "turn sandboxes on", Command: CommandName + " setup"}
		case !st.Available:
			p.listening = st.IngressAddr != ""
			c.Status, c.Detail = openshell.StatusFail, "running, but sandboxes are unavailable: "+firstNonEmpty(st.Reason, "not connected to OpenShell")
		default:
			p.listening, p.available, p.ingress = true, true, st.IngressAddr
			c.Status = openshell.StatusPass
			c.Detail = fmt.Sprintf("connected to %s; ingress %s, egress proxy %s", gatewayText(st.Gateway), st.IngressAddr, st.EgressAddr)
		}
	} else {
		c.Status, c.Detail = openshell.StatusFail, err.Error()
	}
	p.check = c
	return p
}

func gatewayText(g *sandboxapi.Gateway) string {
	if g == nil {
		return "the OpenShell gateway"
	}
	return "OpenShell " + g.Version + " gateway " + g.Name
}

func (a *App) imagesCheck() openshell.Check {
	c := openshell.Check{ID: CheckIDImages, Title: "Harness images"}
	specs, err := a.harnesses(nil)
	if err != nil {
		c.Status, c.Detail = openshell.StatusFail, err.Error()
		return c
	}
	specs, forbidden := a.allowedHarnesses(specs)
	if len(specs) == 0 {
		c.Status, c.Detail = openshell.StatusWarn, "no configured harness may run: "+forbidden
		return c
	}
	recs, err := a.Images.List()
	if err != nil {
		c.Status, c.Detail = openshell.StatusWarn, err.Error()
		return c
	}
	var ready, missing []string
	for _, spec := range specs {
		found := false
		for _, r := range recs {
			if r.Connector == spec.Name && r.HookFireVerified && r.UID == os.Getuid() &&
				r.DefenseClawVersion == manager.ImageVersion() && (a.Cfg == nil || r.IngressPort == a.Cfg.OpenShellIngressPort()) {
				found = true
				ready = append(ready, spec.Name+" "+r.HarnessVersion)
				break
			}
		}
		if !found {
			missing = append(missing, spec.Name)
		}
	}
	switch {
	case len(missing) == 0:
		c.Status, c.Detail = openshell.StatusPass, "hook-verified: "+strings.Join(ready, ", ")
	default:
		c.Status = openshell.StatusWarn
		c.Detail = "not built yet: " + strings.Join(missing, ", ") + " (the first run builds it, which takes a while)"
		c.Fix = &openshell.Fix{Summary: "build the images now", Command: CommandName + " image build " + strings.Join(missing, " ")}
	}
	if forbidden != "" {
		c.Detail += "; " + forbidden
	}
	return c
}

// allowedHarnesses drops the harnesses the sandbox policy (the pack's
// harness.allowed and openshell.admin.allowed_harnesses) does not let run:
// building their images would be for nothing. forbidden says which went,
// and whose policy refuses them; "" when none did. A policy that does not
// resolve filters nothing (the admin check reports it).
func (a *App) allowedHarnesses(specs []*harness.Spec) (allowed []*harness.Spec, forbidden string) {
	if a.Cfg == nil {
		return specs, ""
	}
	eff, _, err := packs.Resolve(a.Cfg, packs.Flags{})
	if err != nil {
		return specs, ""
	}
	var org, pack []string
	for _, s := range specs {
		err := eff.Allow(packs.Action{Kind: packs.ActionHarness, Harness: s.Name})
		var v *packs.Violation
		switch {
		case err == nil:
			allowed = append(allowed, s)
		case errors.As(err, &v) && v.Admin():
			org = append(org, s.Name)
		default:
			pack = append(pack, s.Name)
		}
	}
	var parts []string
	if len(org) > 0 {
		parts = append(parts, strings.Join(org, ", ")+" not allowed by your organization's policy (openshell.admin.allowed_harnesses)")
	}
	if len(pack) > 0 {
		parts = append(parts, strings.Join(pack, ", ")+" not allowed by the sandbox pack (harness.allowed)")
	}
	return allowed, strings.Join(parts, "; ")
}

func (a *App) wrappersCheck() openshell.Check {
	c := openshell.Check{ID: CheckIDWrappers, Title: "Shell wrappers", Status: openshell.StatusPass}
	if _, err := a.Home(); err != nil {
		c.Status, c.Detail = openshell.StatusSkip, err.Error()
		return c
	}
	var parts, broken []string
	for _, in := range a.wrapperFiles() {
		if in.Err != nil {
			broken = append(broken, a.tildePath(in.Path)+": "+in.Err.Error())
			continue
		}
		parts = append(parts, strings.Join(in.Block.Commands(), ", ")+" in "+a.tildePath(in.Path))
		if _, err := os.Stat(in.Block.Binary); err != nil {
			broken = append(broken, a.tildePath(in.Path)+" calls "+in.Block.Binary+", which is missing")
		}
	}
	switch {
	case len(broken) > 0:
		c.Status, c.Detail = openshell.StatusFail, strings.Join(broken, "; ")
		c.Fix = &openshell.Fix{Summary: "re-enable the wrappers (or disable them)", Command: CommandName + " enable <harness>"}
	case len(parts) == 0:
		c.Detail = "none (`" + CommandName + " enable claude` makes `claude` run sandboxed)"
	default:
		c.Detail = strings.Join(parts, "; ") + " (" + wrapper.EnvBypass + "=1 bypasses)"
	}
	return c
}

func (a *App) adminCheck() openshell.Check {
	c := openshell.Check{ID: CheckIDAdmin, Title: "Organization policy", Status: openshell.StatusPass}
	s := packs.AdminStatusFor(a.Cfg)
	if !s.Configured {
		c.Detail = "no openshell.admin constraints"
		return c
	}
	c.Detail = string(s.Authority)
	if s.Detail != "" {
		c.Detail += ": " + s.Detail
	}
	if warnings := a.adminWarnings(); len(warnings) > 0 {
		c.Status = openshell.StatusWarn
		c.Detail += "; " + strings.Join(warnings, "; ")
	}
	return c
}

// Doctor is `sandbox doctor`.
func (a *App) RunDoctor(ctx context.Context, o DoctorOptions) error {
	a.defaults()
	rep := a.runDoctor(ctx)
	if o.Fix {
		outcomes, err := rep.ApplyFixes(ctx, func(c openshell.Check) (bool, error) {
			if o.Output == OutputJSON {
				return o.Yes, nil
			}
			return a.ask(fmt.Sprintf("Fix %q: %s?", c.Title, c.Fix.Summary), true, o.Yes)
		})
		if err != nil {
			return err
		}
		if o.Output != OutputJSON {
			for _, out := range outcomes {
				if out.Applied {
					a.ok("fixed " + out.ID)
				} else if out.Error != "" {
					a.bad(out.ID + ": " + out.Error)
				}
			}
		}
		if len(outcomes) > 0 {
			rep = a.runDoctor(ctx)
		}
	}
	if o.Output == OutputJSON {
		_, off := sandboxesOff(rep)
		return writeJSON(a.IO.Out, struct {
			OK bool `json:"ok"`
			// Ready is OK with sandboxes turned on (sandboxesOff).
			Ready bool `json:"ready"`
			*openshell.DoctorReport
		}{rep.OK(), rep.OK() && !off, rep})
	}
	a.printDoctor(rep)
	if !rep.OK() {
		return &ExitError{Code: 1, Err: &Silent{Err: errors.New("sandbox doctor found problems")}}
	}
	return nil
}

func (a *App) printDoctor(rep *openshell.DoctorReport) {
	for _, c := range rep.Checks {
		var mark string
		switch c.Status {
		case openshell.StatusPass:
			mark = a.style("✓", ansiGreen)
		case openshell.StatusWarn:
			mark = a.style("⚠", ansiYellow)
		case openshell.StatusFail:
			mark = a.style("✗", ansiRed)
		default:
			mark = a.dim("-")
		}
		a.line(fmt.Sprintf("%s %-26s %s", mark, c.Title, c.Detail))
		if c.Fix != nil && c.Status != openshell.StatusPass {
			fix := c.Fix.Summary
			if c.Fix.Command != "" {
				fix += ": " + c.Fix.Command
			}
			if c.Fix.Automatic {
				fix += "  (" + CommandName + " doctor --fix)"
			}
			a.line("  " + a.dim("→ "+fix))
		}
	}
	if rep.OK() {
		a.println()
		if why, off := sandboxesOff(rep); off {
			a.warn("not ready for sandboxes yet: " + why)
		} else {
			a.ok("ready for sandboxes")
		}
	}
}

// sandboxesOff reports a report without failures whose sandboxes are still
// turned off (openshell.enabled is false, a warning of the daemon check):
// the machine can run them, but no sandbox starts until they are on.
func sandboxesOff(rep *openshell.DoctorReport) (string, bool) {
	c := rep.Get(CheckIDDaemon)
	if c == nil || c.Status != openshell.StatusWarn {
		return "", false
	}
	why := c.Detail
	if c.Fix != nil && c.Fix.Command != "" {
		why += " (" + c.Fix.Command + ")"
	}
	return why, true
}
