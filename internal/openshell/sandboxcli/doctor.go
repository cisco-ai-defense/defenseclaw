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
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/wrapper"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// DefenseClaw doctor check IDs (the host checks are openshell.CheckID*).
const (
	CheckIDDaemon   = "defenseclaw-daemon"
	CheckIDImages   = "overlay-images"
	CheckIDWrappers = "shell-wrappers"
	CheckIDAdmin    = "admin-policy"
	CheckIDHooks    = "sandbox-hooks"
	// CheckIDLegacySandbox fails while a sandbox runs the supervisor of an
	// OpenShell release older than openshell.SupportedMin
	// (sandboxapi.Sandbox.OldSupervisor).
	CheckIDLegacySandbox = "legacy-sandbox"
	// CheckIDManagedRuntime is a managed computer's OpenShell as the
	// account's daemon reports it.
	CheckIDManagedRuntime = "managed-runtime"
)

// DoctorOptions are the `sandbox doctor` flags.
type DoctorOptions struct {
	Output OutputFormat
	Fix    bool
	Yes    bool
}

func (a *App) defaultDoctor() *openshell.Doctor {
	d := &openshell.Doctor{GatewayApplied: func(res *openshell.GatewayApplyResult) {
		// A fix's gateway edit is DefenseClaw's, as setup's is: teardown
		// restores the file only while it holds what DefenseClaw last wrote.
		if err := a.recordGatewayApply(res); err != nil {
			a.warnErr("could not record the gateway change for teardown: " + err.Error())
		}
	}}
	if onManagedHost() {
		// The account's gateway runs on the administrator's rendered
		// configuration, not on files of the account's own (GAP-0254).
		d.Rendered = managedRenderedGateway()
	}
	if a.Cfg != nil {
		o := a.Cfg.OpenShell
		d.CLI = o.EffectiveBinary()
		d.Discover = openshell.DiscoverOptions{Gateway: o.Gateway.Name}
		want := o.UpstreamTelemetry
		d.WantTelemetry = &want
		d.BindMountsOptional = o.Workdir.Mode == config.OpenShellWorkdirCopy && len(mountedSettingsHarnesses(o.Harnesses)) == 0
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
	managed := onManagedHost()
	if a.Cfg != nil || managed {
		st = a.probeDaemon(ctx, managed)
		for i := range d.Ports {
			// A daemon can hold one port while another program owns the other.
			switch d.Ports[i].Name {
			case "ingress":
				d.Ports[i].ServedByDaemon = st.ingressListening
			case "egress":
				d.Ports[i].ServedByDaemon = st.egressListening
			}
		}
		// The uid the daemon reports (an older one reports none, and the
		// check then has nothing to compare).
		d.DaemonUID = st.daemonUID
		managed = managed || st.managed != nil
	}
	// On a managed computer the host checks are of this account's own
	// process only: OpenShell, its port and its prerequisites are the
	// administrator's, and the daemon's rows below report them as it got
	// them from the managed gateway, the facts the administrator's verify
	// reads (GAP-0173, GAP-0174, GAP-0215, GAP-0367).
	d.Managed = managed
	if managed && a.ManagedAccountHome != nil {
		d.HomeDir = a.ManagedAccountHome
	}
	if managed && a.GOOS == "darwin" && a.ManagedE2fsprogsDir != nil {
		d.AdminE2fsprogsDir, d.AdminE2fsprogsKnown = a.ManagedE2fsprogsDir(ctx)
	}
	rep := a.HostDoctor(ctx, d)
	rep.Managed = rep.Managed || managed
	// The host checks set it; the Docker access row below asks it again.
	dockerGroup := d.DockerGroup
	if managed && st != nil && st.managed != nil {
		rep.ConfiguredDriver = openshell.ComputeDriver(sandboxapi.DisplayText(st.managed.Driver))
		rep.Driver = rep.ConfiguredDriver
	} else if managed && a.GOOS == "darwin" {
		// The daemon may be stopped while the administrator's rendered
		// gateway still selects Docker. Use the same applied configuration
		// as the exec shim before deciding which prerequisites to check.
		if driver, err := managedRenderedDoctorDriver(d.Rendered); err == nil {
			rep.ConfiguredDriver, rep.Driver = driver, driver
		} else {
			rep.ConfiguredDriver, rep.Driver = "", ""
			rep.Checks = append(rep.Checks, openshell.Check{
				ID: openshell.CheckIDManagedE2fsprogs, Title: "Sandbox prerequisites",
				Status: openshell.StatusFail,
				Detail: "cannot determine the applied sandbox driver: " + err.Error(),
			})
		}
	}
	if st != nil {
		switch gw := rep.Get(openshell.CheckIDGatewayVersion); {
		case st.unavailable && rep.GatewayPortElsewhere:
			// The daemon's connection error is the other account's
			// certificate refusal (GAP-0201): say what it means, as a
			// consequence of that one cause (GAP-0288).
			st.check.Status, st.check.Fix = openshell.StatusSkip, nil
			st.check.Detail = "running, but sandboxes are unavailable: the OpenShell gateway on its port is another account's (see Gateway service)"
		case st.unavailable && gw != nil && gw.Status == openshell.StatusFail:
			// The daemon's reason repeats the Gateway check's error: one
			// cause, counted once, with its fix there (GAP-0226).
			st.check.Status, st.check.Fix = openshell.StatusSkip, nil
			st.check.Detail = "running; it serves sandboxes once the OpenShell gateway answers (see Gateway)"
		}
		rep.Checks = append(rep.Checks, st.check)
		if st.available {
			rep.Checks = append(rep.Checks, a.hooksCheck(ctx, st.ingress))
			if c := a.legacySandboxCheck(ctx); c != nil {
				rep.Checks = append(rep.Checks, *c)
			}
		}
		runDriver, _ := openshell.LookupDriver(string(rep.Driver))
		images := a.imagesCheck(ctx, image.MicroVMTarget(runDriver))
		if st.managed != nil && st.managed.Unavailable != "" && images.Status == openshell.StatusWarn {
			// Nothing builds while sandboxes can't run for the account (no
			// docker or kvm access): the Sandbox runtime row names why and
			// whom to ask, and a build now would only fail (GAP-0460).
			images.Status, images.Fix = openshell.StatusSkip, nil
			images.Detail += "; they are built once sandboxes are available for your account (see Sandbox runtime)"
		}
		rep.Checks = append(rep.Checks, images, a.wrappersCheck(ctx, managed))
		switch {
		case st.managed != nil:
			// A user on a managed computer reads the organization's policy
			// from the daemon, never from a configuration they cannot read.
			rep.Checks = append(rep.Checks, a.managedPolicyCheck(ctx, st.managed), managedRuntimeCheck(st.managed))
			if c := a.withAdminVMDriver(managedDriverCheck(st.managed), st.managed); c != nil {
				c = a.withRenderedVMDriver(c, st.managed, d.Rendered)
				rep.Checks = append(rep.Checks, *c)
			}
			if c := otherGatewaysCheck(st.managed); c != nil {
				rep.Checks = append(rep.Checks, *c)
			}
			if a.GOOS == "darwin" {
				rep.Checks = append(rep.Checks, a.managedDockerCheck(ctx, st.managed))
			}
			if c := managedDockerGroupCheck(a.GOOS, st.managed, dockerGroup); c != nil {
				rep.Checks = append(rep.Checks, *c)
			}
		case managed:
			// Without the daemon's answer the policy and the runtime are not
			// known here: the defaults of a configuration this account does
			// not have would misstate them ("no openshell.admin constraints").
			const unknown = "not known here: your sandbox service did not answer (see DefenseClaw daemon)"
			rep.Checks = append(rep.Checks,
				openshell.Check{ID: CheckIDAdmin, Title: "Organization policy", Status: openshell.StatusSkip, Detail: unknown},
				openshell.Check{ID: CheckIDManagedRuntime, Title: "Sandbox runtime", Status: openshell.StatusSkip, Detail: unknown})
		default:
			rep.Checks = append(rep.Checks, a.adminCheck())
		}
	}
	if a.Cfg != nil || managed {
		rep.Checks = append(rep.Checks, a.tlsTrustCheck(ctx, managed))
	}
	if managed && a.GOOS == "darwin" {
		if rep.Driver == openshell.DriverVM || (st.managed != nil && rep.Driver != openshell.DriverDocker) {
			rep.Checks = append(rep.Checks, d.ManagedE2fsprogsCheck())
		}
		// The per-user job is outside the root gateway's readiness report.
		// Read only this account's gui domain through the host doctor's runner.
		d.GOOS, d.Geteuid = a.GOOS, a.Geteuid
		if c := d.ManagedLaunchAgentCheck(ctx); c != nil {
			rep.Checks = append(rep.Checks, *c)
		}
	}
	return rep
}

func managedRenderedDoctorDriver(paths *openshell.RenderedPaths) (openshell.ComputeDriver, error) {
	if paths == nil || paths.TOML == "" {
		return "", errors.New("the administrator's rendered gateway configuration is unavailable")
	}
	if err := managedRenderedVMConfigTrust(paths.TOML, "OpenShell gateway configuration"); err != nil {
		return "", fmt.Errorf("the administrator's rendered gateway configuration is not trusted: %w", err)
	}
	data, err := os.ReadFile(paths.TOML)
	if err != nil {
		return "", fmt.Errorf("read the administrator's rendered gateway configuration: %w", err)
	}
	rendered, err := openshell.ParseRenderedGateway(data, nil)
	if err != nil {
		return "", err
	}
	if err := rendered.Validate(); err != nil {
		return "", err
	}
	return rendered.ComputeDriver, nil
}

type statusProbe struct {
	// A configured port is not proof the daemon holds it.
	ingressListening, egressListening bool
	unavailable                       bool
	// available is set when the daemon serves sandboxes; ingress is its
	// hook ingress address.
	available bool
	ingress   string
	// daemonUID is the uid the answering daemon runs as, when it says.
	daemonUID *int
	// managed is the managed part of the daemon's status (managed computers).
	managed *sandboxapi.ManagedStatus
	check   openshell.Check
}

// isAre is " is" for one name, " are" for more.
func isAre(names []string) string {
	if len(names) == 1 {
		return " is"
	}
	return " are"
}

// itsTheir is "its" for one name, "their" for more.
func itsTheir(names []string) string {
	if len(names) == 1 {
		return "its"
	}
	return "their"
}

// legacySandboxCheck fails while a sandbox runs the supervisor of an
// OpenShell release older than openshell.SupportedMin
// (sandboxapi.Sandbox.OldSupervisor): that release's network broker can let
// its connections bypass sandbox policy, DefenseClaw cannot contain it, and
// the daemon creates and starts no sandbox while it runs. DefenseClaw stops
// none itself, so the fix names the command that ends each. nil when none
// runs, or when the list cannot be read (the hooks check says so).
func (a *App) legacySandboxCheck(ctx context.Context) *openshell.Check {
	api, err := a.api()
	if err != nil {
		return nil
	}
	list, err := api.List(ctx)
	if err != nil {
		return nil
	}
	var names, ways []string
	for i := range list {
		if sb := &list[i]; sb.OldSupervisor {
			names = append(names, sb.Name)
			ways = append(ways, legacyStopWay(sb))
		}
	}
	if len(names) == 0 {
		return nil
	}
	gone := "it is gone"
	if len(names) > 1 {
		gone = "they are gone"
	}
	return &openshell.Check{ID: CheckIDLegacySandbox, Title: "Legacy sandboxes", Status: openshell.StatusFail,
		Detail: strings.Join(names, ", ") + ": legacy sandbox running, not protected by the 1.0.4 egress policy (" + itsTheir(names) +
			" session runs the supervisor of an OpenShell release older than " + openshell.SupportedMin + ", whose network broker can let connections " +
			"bypass sandbox policy, NVIDIA/OpenShell#4494, and DefenseClaw cannot contain it); DefenseClaw stops " + itThem(names) +
			" for nobody, and creates and starts no sandbox until " + gone,
		Fix: &openshell.Fix{Summary: strings.Join(ways, "; ")}}
}

// legacyStopWay is how the user ends the legacy sandbox sb
// (sandboxapi.Sandbox.OldSupervisor): the stop of a ready one, which on a
// MicroVM syncs its disk first because that release's stop does not, and
// the delete of a MicroVM whose workload ended, which OpenShell does not
// stop (or its start with --end-vm on OpenShell SupportedMin or later).
func legacyStopWay(sb *sandboxapi.Sandbox) string {
	if sb.Phase == "ready" {
		way := "save the work you need in " + sb.Name + ", then run `" + CommandName + " stop " + sb.Name + "`"
		if d, ok := openshell.LookupDriver(sb.Driver); !ok || !d.StopFlushes {
			way += ", which syncs the VM's disk first (that release's stop does not flush it, so what the guest writes after the sync may be lost)"
		}
		return way
	}
	return "`" + CommandName + " delete " + sb.Name + "` deletes " + sb.Name + " and its work, or on OpenShell " + openshell.SupportedMin + " or later `" +
		CommandName + " start " + sb.Name + " --end-vm` ends its VM, losing what it has not written to its disk"
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
	var bad, stopped, stoppedSilent, errored, timedOut, lingeringVMs, lingeringWayOn []string
	running := 0
	// A sandbox of the compute driver the gateway ran before a switch is in
	// OpenShell's error state because the gateway cannot run it, not because a
	// container stopped or Docker restarted (GAP-0455). A gateway older than
	// openshell.SupportedMin can neither stop nor start a sandbox in that state.
	liveDriver, oldGateway, managed := "", false, false
	if st, serr := api.Status(ctx); serr == nil && st.Gateway != nil {
		liveDriver = st.Gateway.Driver
		oldGateway = !openshell.RunsSandboxes(st.Gateway.Version)
		managed = st.Managed != nil
	}
	// The MicroVMs in the error state that hold the gateway
	// (openshell.HoldsGateway): an OpenShell older than SupportedMin neither
	// stops nor starts them, so the upgrade is refused until they are
	// deleted.
	var heldVMs []string
	otherDriver := otherDriverSandboxes(list, liveDriver)
	otherDriverNames := map[string]bool{}
	for _, sb := range otherDriver {
		otherDriverNames[sb.Name] = true
	}
	for _, sb := range list {
		if sb.Phase == "ready" {
			running++
		}
		switch {
		case sb.Phase != "error" || otherDriverNames[sb.Name]:
		case openshell.ProvisioningTimedOut(sb.PhaseReason):
			timedOut = append(timedOut, sb.Name)
		case sb.Driver == "vm" && openshell.LingeringVM(openshell.PhaseError, sb.PhaseReason, false) && openshell.MainProcessFailed(sb.PhaseReason):
			lingeringVMs = append(lingeringVMs, sb.Name)
			lingeringWayOn = append(lingeringWayOn, sb.Name+": "+openshell.StopWayOn(sb.Name, openshell.PhaseError, sb.PhaseReason, true))
		default:
			errored = append(errored, sb.Name)
		}
		if d, ok := openshell.LookupDriver(sb.Driver); sb.Phase == "error" && !otherDriverNames[sb.Name] && (!ok || !d.StopFlushes) &&
			openshell.HoldsGateway(openshell.PhaseError, sb.PhaseReason, false) {
			heldVMs = append(heldVMs, sb.Name)
		}
		if sb.Phase != "ready" && sb.Phase != "error" && sb.Hooks.Silent && sb.Hooks.OnSilence == "stop" {
			stoppedSilent = append(stoppedSilent, sb.Name)
		}
		switch {
		case !sb.Hooks.Unreachable:
		case sb.Phase == "ready":
			bad = append(bad, sb.Name+": "+firstNonEmpty(sb.Hooks.UnreachableReason, "no hook request reaches DefenseClaw"))
		case sb.Phase != "error":
			// A stopped sandbox keeps its last session's verdict (GAP-0186),
			// and nothing of it runs that could fail closed: it fails no
			// machine check (GAP-0384).
			stopped = append(stopped, sb.Name)
		}
	}
	switch {
	case len(bad) > 0:
		c.Status = openshell.StatusFail
		c.Detail = "hooks do not reach the ingress " + firstNonEmpty(ingress, "(unknown)") + ", so every tool call fails closed: " + strings.Join(bad, "; ")
		c.Fix = &openshell.Fix{Summary: "fix the cause above, then start the session again"}
	case len(errored) > 0 || len(timedOut) > 0 || len(lingeringVMs) > 0:
		// A Docker sandbox whose container stopped can stop and start
		// again. A MicroVM whose main process failed needs a lossy end or delete;
		// one whose provisioning timed out starts again without a stop,
		// which OpenShell refuses for it (NVIDIA/OpenShell#4231, GAP-0278).
		c.Status = openshell.StatusWarn
		var details, fixes []string
		if len(errored) > 0 {
			details = append(details, strings.Join(errored, ", ")+isAre(errored)+" in OpenShell's error state (the container stopped: Docker restarted, or the workload failed)")
			fixes = append(fixes, "fix what stopped "+itThem(errored)+", then `"+CommandName+" stop NAME` and `"+CommandName+
				" start NAME`, which keep the sandbox and its work")
		}
		if len(lingeringVMs) > 0 {
			details = append(details, strings.Join(lingeringVMs, ", ")+isAre(lingeringVMs)+" in OpenShell's error state; "+itThem(lingeringVMs)+" may still have a running MicroVM")
			fixes = append(fixes, lingeringWayOn...)
		}
		if len(timedOut) > 0 {
			details = append(details, strings.Join(timedOut, ", ")+isAre(timedOut)+" in OpenShell's error state because "+
				itsTheir(timedOut)+" provisioning timed out")
			fixes = append(fixes, "for "+strings.Join(timedOut, ", ")+", wait a minute for OpenShell's cleanup, then `"+CommandName+
				" start NAME` with no stop: OpenShell refuses to stop a sandbox whose provisioning timed out")
		}
		c.Detail = strings.Join(details, "; ")
		c.Fix = &openshell.Fix{Summary: strings.Join(fixes, "; ")}
		if oldGateway {
			// The upgrade first; after it, the way on of the upgraded
			// gateway, which still refuses to stop a sandbox whose
			// provisioning timed out. The upgrade (per user, or the
			// administrator's pin move on a managed computer) is refused
			// while OpenShell does not report a MicroVM in the error state
			// stopped (heldVMs), which this OpenShell neither stops nor
			// starts: only its delete lets the upgrade go ahead.
			allErrored := append(slices.Clone(errored), lingeringVMs...)
			allErrored = append(allErrored, timedOut...)
			c.Detail += ", where this OpenShell can neither stop nor start " + itThem(allErrored)
			upgrade, move, waits := "upgrade OpenShell to "+openshell.InstallerVersion, "the upgrade", []string{"see Gateway"}
			if managed {
				upgrade, move, waits = "your organization's OpenShell setting moves this account to "+openshell.InstallerVersion+
					" on its own where DefenseClaw installs OpenShell (ask IT otherwise)", "the move", nil
			}
			if len(heldVMs) > 0 {
				waits = append(waits, move+" is refused while OpenShell does not report "+strings.Join(heldVMs, ", ")+" stopped, and this OpenShell neither "+
					"stops nor starts a MicroVM in its error state: `"+CommandName+" delete NAME` deletes "+itThem(heldVMs)+" with "+itsTheir(heldVMs)+" work")
			}
			if len(waits) > 0 {
				upgrade += " (" + strings.Join(waits, "; ") + ")"
			}
			// What survives the upgrade: not the MicroVMs deleted for it.
			deleted := func(name string) bool { return slices.Contains(heldVMs, name) }
			errored, timedOut = slices.DeleteFunc(errored, deleted), slices.DeleteFunc(timedOut, deleted)
			var after []string
			if len(errored) > 0 {
				after = append(after, "`"+CommandName+" stop NAME` and `"+CommandName+" start NAME` for "+strings.Join(errored, ", ")+
					", which keep the sandbox and its work")
			}
			if len(timedOut) > 0 {
				after = append(after, "for "+strings.Join(timedOut, ", ")+" wait a minute for OpenShell's cleanup, then `"+CommandName+
					" start NAME` with no stop: OpenShell "+openshell.SupportedMin+" refuses to stop a sandbox whose provisioning timed out")
			}
			if len(after) > 0 {
				upgrade += ", then " + strings.Join(after, "; ")
			}
			c.Fix = &openshell.Fix{Summary: upgrade}
		}
	case len(stoppedSilent) > 0:
		c.Status = openshell.StatusWarn
		c.Detail = strings.Join(stoppedSilent, ", ") + " stopped after its harness worked without hooks reaching DefenseClaw (hooks.on_silence: stop); no sandbox work runs now"
		c.Fix = &openshell.Fix{Summary: "fix the sandbox harness's hook configuration before starting it again, or delete it"}
	case len(otherDriver) > 0 && len(stopped) == 0:
		c.Status = openshell.StatusWarn
		c.Detail = otherDriverNote(list, liveDriver)
		c.Fix = &openshell.Fix{Summary: "nothing is wrong with the gateway: delete " + itThem(make([]string, len(otherDriver))) + " (`" + CommandName +
			" delete NAME`)"}
	case len(stopped) > 0:
		c.Status = openshell.StatusWarn
		verb, its := " is stopped", "its"
		if len(stopped) > 1 {
			verb, its = " are stopped", "their"
		}
		c.Detail = strings.Join(stopped, ", ") + verb + ", and the hooks of " + its + " last session did not reach DefenseClaw (`" + CommandName +
			" status NAME` says why); nothing of " + itThem(stopped) + " runs now"
		if running > 0 {
			c.Detail = fmt.Sprintf("the hooks of %s reach DefenseClaw (ingress %s); ", plural(int64(running), "running sandbox", "running sandboxes"),
				firstNonEmpty(ingress, "(unknown)")) + c.Detail
		}
		c.Fix = &openshell.Fix{Summary: "fix that cause before you start " + itThem(stopped) + " again, or delete " + itThem(stopped)}
	case running == 0:
		c.Detail = "no sandbox is running"
	default:
		c.Detail = fmt.Sprintf("the hooks of %s reach DefenseClaw (ingress %s)", plural(int64(running), "running sandbox", "running sandboxes"), firstNonEmpty(ingress, "(unknown)"))
	}
	return c
}

// probeDaemon asks the daemon for its status. On a managed computer
// (managed) the daemon is the account's sandbox service, which the
// organization installs and every sandbox command starts: what is wrong
// with it is said as it is, and the way on is the IT help desk, never a
// command for an unmanaged install.
func (a *App) probeDaemon(ctx context.Context, managed bool) *statusProbe {
	c := openshell.Check{ID: CheckIDDaemon, Title: "DefenseClaw daemon"}
	p := &statusProbe{}
	api, err := a.api()
	if err == nil {
		st, serr := api.Status(ctx)
		if serr == nil {
			p.daemonUID = st.DaemonUID
			p.managed = st.Managed
			p.ingressListening = st.IngressAddr != ""
			p.egressListening = st.EgressAddr != ""
		}
		managed = managed || (serr == nil && st.Managed != nil)
		switch {
		case serr != nil && managed:
			c.Status, c.Detail = openshell.StatusFail, "your sandbox service does not answer: "+managedDaemonError(serr)
			c.Fix = &openshell.Fix{Summary: managedServiceFix}
		case serr != nil:
			c.Status, c.Detail = openshell.StatusFail, apiError(serr).Error()
			c.Fix = &openshell.Fix{Summary: "start the daemon", Command: "defenseclaw-gateway start"}
		case !st.Enabled && st.Managed != nil:
			// Nothing the user can turn on or hand over: the organization
			// manages it, and another account is only ever "another account".
			c.Status, c.Detail = openshell.StatusSkip, "running; "+managedOffState(st)
		case !st.Enabled && st.GatewayElsewhere != "":
			// The Gateway service row names the one cause and the way on;
			// setup would stop there (GAP-0307).
			c.Status, c.Detail = openshell.StatusSkip, "running; sandboxes are off for this account: the OpenShell gateway on this machine is another account's (see Gateway service)"
		case !st.Enabled:
			c.Status, c.Detail = openshell.StatusWarn, "openshell.enabled is false: sandboxes are off"
			c.Fix = &openshell.Fix{Summary: "turn sandboxes on", Command: CommandName + " setup"}
		case !st.Available && st.Managed != nil && st.Managed.Unavailable == "" && st.Running == 0 && st.GatewayElsewhere == "":
			// Before the first sandbox, and after an idle daemon stopped it,
			// the account's OpenShell gateway is not running: the next run
			// starts it, installing OpenShell first in setup mode. Nothing
			// failed (GAP-0439, GAP-0441). Another account's sandboxes
			// holding the port are the busy row below (GAP-0461).
			if st.DockerGroupMissing {
				// Nothing has failed yet, but the first run's image build will
				// (GAP-0556): the daemon cannot reach Docker.
				c.Status, c.Detail, c.Fix = dockerGroupMissingRow(true)
				break
			}
			c.Status, c.Detail = openshell.StatusPass, "running; "+a.managedFirstRunText(st.Managed)
		case !st.Available:
			p.unavailable = true
			c.Status, c.Detail = openshell.StatusFail, "running, but sandboxes are unavailable: "+sandboxapi.DisplayText(firstNonEmpty(st.Reason, "not connected to OpenShell"))
			switch {
			case st.Managed != nil && st.GatewayElsewhere != "":
				// Another account's sandboxes hold the one gateway port: no
				// fault of this account's, and it clears (GAP-0461).
				c.Status, c.Detail = openshell.StatusWarn, "running; OpenShell is "+managedAccountBusyText
				c.Fix = &openshell.Fix{Summary: "try again when that account has no sandbox running; " + busyContact(st.Managed.RequestAccess)}
			case st.Managed != nil && st.Managed.Unavailable != "":
				// The Sandbox runtime row names the one cause, with the
				// organization's contact: counted once.
				c.Status, c.Detail = openshell.StatusSkip, "running; sandboxes are unavailable (see Sandbox runtime)"
			}
		case st.DockerGroupMissing && managed:
			// The account's user services started before the group was
			// given, and a restart of one keeps their groups: a new login
			// gives them (GAP-0367).
			p.available, p.ingress = true, st.IngressAddr
			c.Status, c.Detail, c.Fix = dockerGroupMissingRow(true)
		case st.DockerGroupMissing:
			p.available, p.ingress = true, st.IngressAddr
			c.Status, c.Detail, c.Fix = dockerGroupMissingRow(false)
		default:
			p.available, p.ingress = true, st.IngressAddr
			c.Status = openshell.StatusPass
			c.Detail = fmt.Sprintf("connected to %s; ingress %s, egress proxy %s", gatewayText(st.Gateway), st.IngressAddr, st.EgressAddr)
		}
	} else {
		c.Status, c.Detail = openshell.StatusFail, err.Error()
		if managed {
			c.Fix = &openshell.Fix{Summary: managedServiceFix}
		}
	}
	p.check = c
	return p
}

// dockerGroupMissingRow is the daemon row of a daemon that runs, but started
// before its user joined the docker group, so it cannot reach Docker. A
// managed computer's services start with a new login, and the user has no
// `defenseclaw-gateway` to restart (GAP-0367, GAP-0556).
func dockerGroupMissingRow(managed bool) (openshell.CheckStatus, string, *openshell.Fix) {
	const detail = "running, but it started before you joined the docker group, so it cannot reach Docker"
	if managed {
		// The account's user services started before the group was given,
		// and a restart of one keeps their groups: a new login gives them.
		return openshell.StatusFail, detail, &openshell.Fix{Summary: "sign out of every session of this account and sign in again, " +
			"which starts your sandbox service with the group; if it persists, " + sandboxapi.RequestAccessFallback}
	}
	return openshell.StatusFail, detail, &openshell.Fix{Summary: "restart it so it picks up the group", Command: "defenseclaw-gateway restart"}
}

// managedServiceFix is the way on when a managed computer's sandbox service
// does not answer: the organization installs it, and every sandbox command
// starts it.
const managedServiceFix = "your organization installs this service and every sandbox command starts it: if it still does not answer, " +
	sandboxapi.RequestAccessFallback + " with this output"

// managedDaemonError is why a managed computer's sandbox service did not
// answer, without the HTTP request the client made (`Get "http://…": `).
func managedDaemonError(err error) string {
	text := err.Error()
	if i := strings.Index(text, `Get "`); i >= 0 {
		if j := strings.Index(text[i:], `": `); j >= 0 {
			text = text[:i] + text[i+j+3:]
		}
	}
	return sandboxapi.DisplayText(text)
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
	// The daemon's store of a managed computer holds the images of one
	// account's one daemon, whose ports are the organization's: the
	// configuration here is not the one they were built under (GAP-0548).
	managed := a.ManagedHost() || onManagedHost()
	// Docker unreachable: the Docker check says so, and the records stand.
	gone, _ := a.Images.Gone(ctx, recs)
	newest := map[string]image.Record{}
	// earlier are the harnesses with an image only another DefenseClaw build
	// made: after an upgrade they read "not built yet" (GAP-0320).
	earlier := map[string]bool{}
	for _, r := range recs {
		if r.HookFireVerified && r.MicroVM == microVM && r.UID == os.Getuid() && !gone[r.Tag] &&
			(a.Cfg == nil || managed || r.IngressPort == a.Cfg.OpenShellIngressPort()) {
			if r.DefenseClawVersion != manager.ImageVersion() {
				earlier[r.Connector] = true
				continue
			}
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
	var notes, never, rebuild []string
	for _, name := range missing {
		if earlier[name] {
			rebuild = append(rebuild, name)
		} else {
			never = append(never, name)
		}
	}
	if len(never) > 0 {
		notes = append(notes, "not built yet: "+strings.Join(never, ", ")+" (the first run builds it, which takes a while)")
	}
	if len(rebuild) > 0 {
		notes = append(notes, "built by an earlier DefenseClaw build only: "+strings.Join(rebuild, ", ")+
			" (the next run builds it for this one, which takes a while; then `"+CommandName+" image prune` frees the old one)")
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

// wrappersCheck reports the shell wrappers; managed marks a managed
// computer, where the bypass of a wrapper is offered only for an agent the
// organization does not require in a sandbox (wrapperBypassHint).
func (a *App) wrappersCheck(ctx context.Context, managed bool) openshell.Check {
	c := openshell.Check{ID: CheckIDWrappers, Title: "Shell wrappers", Status: openshell.StatusPass}
	if _, err := a.Home(); err != nil {
		c.Status, c.Detail = openshell.StatusSkip, err.Error()
		return c
	}
	var parts, broken, commands []string
	for _, in := range a.wrapperFiles() {
		if in.Err != nil {
			broken = append(broken, a.tildePath(in.Path)+": "+in.Err.Error())
			continue
		}
		parts = append(parts, strings.Join(in.Block.Commands(), ", ")+" in "+a.tildePath(in.Path))
		for _, cmd := range in.Block.Commands() {
			if !slices.Contains(commands, cmd) {
				commands = append(commands, cmd)
			}
		}
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
		c.Detail = strings.Join(parts, "; ")
		if hint := a.wrapperBypassHint(ctx, commands, managed); hint != "" {
			c.Detail += " (" + hint + ")"
		}
	}
	return c
}

// wrapperBypassHint is how the wrapped commands run on the host once. On a
// managed computer the hooks refuse a host run of an agent the
// organization requires in a sandbox, so the hint names only the others,
// and none when the daemon does not say which those are (GAP-0489).
func (a *App) wrapperBypassHint(ctx context.Context, commands []string, managed bool) string {
	if !managed {
		return wrapper.EnvBypass + "=1 bypasses"
	}
	api, err := a.api()
	if err != nil {
		return ""
	}
	ex, err := api.Explain(ctx, sandboxapi.ExplainRequest{})
	if err != nil || ex.Managed == nil {
		return ""
	}
	var open []string
	for _, cmd := range commands {
		spec, err := ResolveHarness(cmd)
		if err != nil || ex.Managed.HostRunRefused(spec.Name) {
			continue
		}
		open = append(open, cmd)
	}
	if len(open) == 0 {
		return ""
	}
	return wrapper.EnvBypass + "=1 runs " + strings.Join(open, ", ") + " on the host"
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
	// What is in force, and once whose it is: the row said "advisory:
	// openshell.admin is enforced but advisory" and named no constraint
	// (GAP-0252).
	whose := "advisory (you own config.yaml and can change it)"
	if s.Authority == packs.AuthorityAuthoritative {
		whose = "authoritative (an administrator owns config.yaml)"
	}
	floor := packs.BaseFloor(a.Cfg)
	c.Detail = whose + ": " + strings.Join(adminConstraints(floor), ", ")
	if len(floor.RequiredFor) > 0 && !a.Cfg.StandaloneEnterprise() {
		// Only a managed gateway refuses the host runs of a required agent
		// (requireSandboxDecision); here the key changes nothing (#1209).
		c.Detail += "; required_for has no effect on a per-user gateway: only a managed computer refuses host runs"
	}
	return c
}

// adminConstraints names each openshell.admin constraint in force, briefly.
func adminConstraints(ad config.OpenShellAdminConfig) []string {
	var out []string
	no := func(allowed *bool, what string) {
		if allowed != nil && !*allowed {
			out = append(out, what)
		}
	}
	if ad.RequiredPack != "" {
		p := "pack " + ad.RequiredPack + " required"
		if ad.RequiredPackDigest != "" {
			p += " (pinned)"
		}
		out = append(out, p)
	}
	if len(ad.RequiredFor) > 0 {
		out = append(out, "sandbox required for "+strings.Join(ad.RequiredFor, ", "))
	}
	if ad.MinProfile != "" {
		out = append(out, "profile "+ad.MinProfile+" or stricter")
	}
	if len(ad.AllowedHarnesses) > 0 {
		out = append(out, "harnesses "+strings.Join(ad.AllowedHarnesses, ", ")+" only")
	}
	no(ad.AllowYolo, "no skip-permissions")
	no(ad.AllowMount, "copy mode only")
	no(ad.AllowHostPorts, "no --host-port")
	no(ad.AllowUnblock, "no unblocks")
	no(ad.AllowLearnMode, "no learn mode")
	if len(ad.RequireCopyFor) > 0 {
		out = append(out, "copy mode for "+strings.Join(firstN(ad.RequireCopyFor, 2), ", "))
	}
	if n := len(ad.EgressBlock); n > 0 {
		out = append(out, plural(int64(n), "blocked host", "blocked hosts"))
	}
	if n := len(ad.EgressAllowOnly); n > 0 {
		out = append(out, "only "+plural(int64(n), "allowed host", "allowed hosts"))
	}
	if ad.BlockLargeUploads {
		out = append(out, "large uploads blocked")
	}
	if r := ad.MaxResources; r != (config.OpenShellResourcesConfig{}) {
		var caps []string
		if r.CPU != "" {
			caps = append(caps, r.CPU+" CPUs")
		}
		if r.Memory != "" {
			caps = append(caps, r.Memory+" memory")
		}
		out = append(out, "at most "+strings.Join(caps, " and "))
	}
	if len(ad.Locked) > 0 {
		out = append(out, "locked: "+strings.Join(ad.Locked, ", "))
	}
	return out
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
				why, held := a.restartStops(ctx)
				if held != "" {
					// The restart's own gate refuses it under them.
					def = false
					if o.Output != OutputJSON {
						a.warn(c.Title + ": this restarts the OpenShell gateway, and " + held)
						if o.Yes {
							a.note("not fixed with --yes while OpenShell does not report every MicroVM sandbox on the gateway stopped")
						}
					}
				}
				if why != "" {
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
			yes, err := a.ask(fmt.Sprintf("Fix %q: %s?", c.Title, c.Fix.Summary), def, o.Yes)
			if yes && err == nil {
				// A fix that starts or restarts the gateway waits for it.
				a.note(fmt.Sprintf("fixing %q…", c.Title))
			}
			return yes, err
		})
		if err != nil {
			return err
		}
		if o.Output != OutputJSON {
			// Named as the question named them (`Fix "Gateway": …?`), not
			// by their ids.
			for _, out := range outcomes {
				switch {
				case out.Applied:
					a.ok(fmt.Sprintf("fixed %q", out.Title))
				case out.Error != "":
					a.bad(fmt.Sprintf("could not fix %q: %s", out.Title, out.Error))
				case out.Skipped != "":
					a.warn(fmt.Sprintf("did not fix %q: %s", out.Title, out.Skipped))
				}
			}
		}
		restarted := false
		for _, out := range outcomes {
			if c := rep.Get(out.ID); out.Applied && c != nil && c.Fix != nil && c.Fix.RestartsGateway {
				restarted = true
			}
		}
		if restarted && a.Cfg != nil {
			// The daemon reconnects to a restarted gateway a few seconds
			// later; until then it says sandboxes are unavailable.
			if o.Output != OutputJSON {
				a.note("waiting for the DefenseClaw daemon to reconnect to the restarted gateway…")
			}
			a.waitReconnect(ctx)
		}
		if len(outcomes) > 0 {
			rep = a.runDoctor(ctx)
		}
	}
	if o.Output == OutputJSON {
		_, off := sandboxesOff(rep)
		// One exit contract: a failed check exits 1 in either format, so a
		// script that checks the status alone is not told a host that
		// cannot run sandboxes is fine (GAP-0308).
		if err := writeJSON(a.IO.Out, struct {
			OK bool `json:"ok"`
			// Ready is OK with sandboxes turned on (sandboxesOff).
			Ready bool `json:"ready"`
			// OpenShellInstall is when setup offers the OpenShell install
			// (DoctorReport.OpenShellInstallNeeded), which the TUI presets.
			OpenShellInstall bool `json:"openshell_install"`
			// OpenShellUpgrade is when setup offers the in-place upgrade
			// of a supported OpenShell (DoctorReport.OpenShellUpgradeAvailable),
			// which the TUI shows with the install toggle off.
			OpenShellUpgrade bool `json:"openshell_upgrade"`
			// OpenShellInstallVersion is the release setup installs.
			OpenShellInstallVersion string `json:"openshell_install_version"`
			*openshell.DoctorReport
		}{rep.OK(), rep.OK() && !off, rep.OpenShellInstallNeeded(), rep.OpenShellUpgradeAvailable(), openshell.InstallerVersion, rep}); err != nil {
			return err
		}
	} else {
		a.printDoctor(rep)
	}
	if !rep.OK() {
		return &ExitError{Code: 1, Err: &Silent{Err: errors.New("sandbox doctor found problems")}}
	}
	return nil
}

// waitReconnect waits, at most 30 s, while the daemon runs with sandboxes
// on but unavailable: after a gateway restart it reconnects on its own.
func (a *App) waitReconnect(ctx context.Context) {
	api, err := a.api()
	if err != nil {
		return
	}
	const wait, poll = 30 * time.Second, 2 * time.Second
	deadline := a.Now().Add(wait)
	for polls := 1; ; polls++ {
		if st, err := api.Status(ctx); err != nil || !st.Enabled || st.Available {
			return
		}
		// The polls bound the wait when the clock does not move.
		if a.Now().After(deadline) || time.Duration(polls)*poll >= wait || a.Sleep(ctx, poll) != nil {
			return
		}
	}
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
			if c.Fix.Automatic && c.Fix.Command != CommandName+" doctor --fix" {
				fix += "  (" + CommandName + " doctor --fix)"
			}
			a.line("  " + a.dim("→ "+fix))
		}
	}
	// The last line is the verdict, a failing one too (it ended on the
	// last check's line, with only the exit status to tell).
	a.println()
	why, off := sandboxesOff(rep)
	failed := failedChecks(rep)
	setupChanging := rep.Get(CheckIDManagedRuntime)
	if off && (failed == 0 || failed == 1 && setupChanging != nil && setupChanging.Status == openshell.StatusFail && setupChanging.Detail == sandboxrelay.UnavailableSetupChanging) {
		a.warn("not ready for sandboxes yet: " + why)
	} else if failed > 0 {
		a.bad("not ready for sandboxes: " + plural(int64(failed), "check", "checks") + " failed")
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

// sandboxesOff reports a daemon whose sandboxes are turned off or a managed
// setup change that has not finished: a run refuses in either state.
func sandboxesOff(rep *openshell.DoctorReport) (string, bool) {
	if c := rep.Get(CheckIDManagedRuntime); c != nil && c.Status == openshell.StatusFail && c.Detail == sandboxrelay.UnavailableSetupChanging {
		return c.Detail, true
	}
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
