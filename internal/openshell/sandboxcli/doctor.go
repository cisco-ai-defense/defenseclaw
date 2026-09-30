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
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
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
		// Every MicroVM gets the gateway-wide resources, which an
		// organization's maximum must allow. The resolver refuses a
		// malformed one on its own.
		if n, err := config.ParseOpenShellCPU(o.Admin.MaxResources.CPU); err == nil {
			d.MaxCPUMillis = n
		}
		if n, err := config.ParseOpenShellMemory(o.Admin.MaxResources.Memory); err == nil {
			d.MaxMemoryBytes = n
		}
		d.Ports = []openshell.PortRequirement{
			{Name: "ingress", Port: a.Cfg.OpenShellIngressPort()},
			{Name: "egress", Port: a.Cfg.OpenShellEgressPort()},
		}
	}
	// Off Linux the Docker VM's kernel is checked in a local image: the
	// base image, else an overlay image built on it.
	if recs, err := a.Images.List(); err == nil {
		for _, r := range recs {
			d.ProbeImages = append(d.ProbeImages, r.Tag)
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
		// The uid the daemon reports (an older one reports none, and the
		// check then has nothing to compare).
		d.DaemonUID = st.daemonUID
	}
	rep := a.HostDoctor(ctx, d)
	if st != nil {
		rep.Checks = append(rep.Checks, st.check)
		if st.available {
			rep.Checks = append(rep.Checks, a.hooksCheck(ctx, st.ingress))
		}
		d, _ := openshell.LookupDriver(string(rep.Driver))
		rep.Checks = append(rep.Checks, a.imagesCheck(ctx, image.MicroVMTarget(d)), a.wrappersCheck(), a.adminCheck())
	}
	return rep
}

type statusProbe struct {
	listening bool
	// available is set when the daemon serves sandboxes; ingress is its
	// hook ingress address.
	available bool
	ingress   string
	// daemonUID is the uid the answering daemon runs as, when it says.
	daemonUID *int
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
		if serr == nil {
			p.daemonUID = st.DaemonUID
		}
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
	if g.Driver == string(openshell.DriverVM) {
		return "OpenShell " + g.Version + " gateway " + g.Name + " (MicroVM driver)"
	}
	return "OpenShell " + g.Version + " gateway " + g.Name
}

// imagesCheck reports the hook-verified harness images a sandbox can start
// from on the driver the gateway runs: the MicroVM ones (microVM) on the vm
// driver, which boots no other, else the docker ones. It covers the
// configured harnesses' (openshell.harnesses, else defaultHarnesses), which
// it warns about when one is not built, and every other harness built for
// this user and DefenseClaw (`sandbox run kiro` builds one without
// configuring it). An image Docker no longer has does not count, whatever
// its record says; a MicroVM image whose MicroVM check refused it, or
// settled nothing yet, is named apart with the command that checks it
// again.
func (a *App) imagesCheck(ctx context.Context, microVM bool) openshell.Check {
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
	// Docker unreachable: the Docker check says so, and the records stand.
	gone, _ := a.Images.Gone(ctx, recs)
	newest := map[string]image.Record{}
	for _, r := range recs {
		if r.HookFireVerified && r.MicroVM == microVM && r.UID == os.Getuid() && !gone[r.Tag] &&
			r.DefenseClawVersion == manager.ImageVersion() && (a.Cfg == nil || r.IngressPort == a.Cfg.OpenShellIngressPort()) {
			if cur, ok := newest[r.Connector]; !ok || r.BuiltAt.After(cur.BuiltAt) {
				newest[r.Connector] = r
			}
		}
	}
	var ready, missing, unchecked, refused []string
	// verdict files the harness name's newest image by its MicroVM check.
	verdict := func(name string) {
		r := newest[name]
		switch {
		case r.MicroVMProblem != "":
			// Every run of it on the MicroVM driver is refused.
			refused = append(refused, name)
		case r.MicroVMUnchecked():
			// Its next run checks it again first, which takes a while.
			unchecked = append(unchecked, name)
		default:
			ready = append(ready, name+" "+r.HarnessVersion)
		}
	}
	covered := map[string]bool{}
	for _, spec := range specs {
		covered[spec.Name] = true
		if _, ok := newest[spec.Name]; ok {
			verdict(spec.Name)
		} else {
			missing = append(missing, spec.Name)
		}
	}
	var others []*harness.Spec
	for name := range newest {
		if spec, ok := harness.Get(name); ok && !covered[name] {
			others = append(others, spec)
		}
	}
	others, _ = a.allowedHarnesses(others)
	sort.Slice(others, func(i, j int) bool { return others[i].Name < others[j].Name })
	for _, spec := range others {
		verdict(spec.Name)
	}
	var notes []string
	if len(missing) > 0 {
		notes = append(notes, "not built yet: "+strings.Join(missing, ", ")+" (the first run builds it, which takes a while)")
	}
	if len(refused) > 0 {
		notes = append(notes, "cannot start in an OpenShell MicroVM: "+strings.Join(refused, ", ")+
			" (the image build's MicroVM check says why; a gateway on the docker driver runs it)")
	}
	if len(unchecked) > 0 {
		notes = append(notes, "not checked for an OpenShell MicroVM yet: "+strings.Join(unchecked, ", ")+
			" (the next run checks it first, which takes a while)")
	}
	if len(notes) > 0 && len(ready) > 0 {
		notes = append(notes, "hook-verified: "+strings.Join(ready, ", "))
	}
	switch {
	case len(notes) == 0:
		c.Status, c.Detail = openshell.StatusPass, "hook-verified: "+strings.Join(ready, ", ")
	case len(missing) > 0:
		c.Status, c.Detail = openshell.StatusWarn, strings.Join(notes, "; ")
		c.Fix = &openshell.Fix{Summary: "build the images now", Command: CommandName + " image build " + strings.Join(missing, " ")}
	default:
		c.Status, c.Detail = openshell.StatusWarn, strings.Join(notes, "; ")
		recheck := append(append([]string{}, refused...), unchecked...)
		c.Fix = &openshell.Fix{Summary: "check them again", Command: CommandName + " image build " + strings.Join(recheck, " ") + " --force"}
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
		c.Detail = "none"
		if s := a.wrapperExample(); s != nil {
			c.Detail += " (`" + CommandName + " enable " + HarnessArg(s) + "` makes `" + s.Command + "` run sandboxed)"
		}
	default:
		c.Detail = strings.Join(parts, "; ") + " (" + wrapper.EnvBypass + "=1 bypasses)"
	}
	return c
}

// wrapperExample is the harness the wrapper hint names: the first
// configured one that may run and whose command people type (nil when
// none is).
func (a *App) wrapperExample() *harness.Spec {
	specs, err := a.harnesses(nil)
	if err != nil {
		return nil
	}
	specs, _ = a.allowedHarnesses(specs)
	for _, s := range specs {
		if _, launched := launchedCommands[s.Command]; !launched {
			return s
		}
	}
	return nil
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
	return c
}

// Doctor is `sandbox doctor`.
func (a *App) RunDoctor(ctx context.Context, o DoctorOptions) error {
	a.defaults()
	rep := a.runDoctor(ctx)
	if o.Fix {
		outcomes, err := rep.ApplyFixes(ctx, func(c openshell.Check) (bool, error) {
			// A fix that restarts the gateway stops every sandbox running
			// on it, of every owner. Where the driver's stop keeps only
			// what was flushed (MicroVMs), with any running (or none
			// known) it is a no by default, and --yes takes that default.
			def := true
			if d, _ := openshell.LookupDriver(string(rep.Driver)); c.Fix.RestartsGateway && !d.StopFlushes {
				if why := a.restartStops(ctx); why != "" {
					def = false
					if o.Output != OutputJSON {
						a.warn(c.Title + ": " + why)
						if o.Yes {
							a.note("not fixed with --yes while sandboxes run on the gateway; stop them, or run `" + CommandName + " doctor --fix` on a terminal")
						}
					}
				}
			}
			if o.Output == OutputJSON {
				return o.Yes && def, nil
			}
			return a.ask(fmt.Sprintf("Fix %q: %s?", c.Title, c.Fix.Summary), def, o.Yes)
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
	// The last line is the verdict, a failing one too (it ended on the
	// last check's line, with only the exit status to tell).
	a.println()
	if failed := failedChecks(rep); failed > 0 {
		a.bad("not ready for sandboxes: " + plural(int64(failed), "check", "checks") + " failed")
	} else if why, off := sandboxesOff(rep); off {
		a.warn("not ready for sandboxes yet: " + why)
	} else {
		a.ok("ready for sandboxes")
	}
}

// failedChecks counts the checks of rep that failed.
func failedChecks(rep *openshell.DoctorReport) int {
	n := 0
	for _, c := range rep.Checks {
		if c.Status == openshell.StatusFail {
			n++
		}
	}
	return n
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
