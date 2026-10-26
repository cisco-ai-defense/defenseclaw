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
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// List is `sandbox list`.
func (a *App) List(ctx context.Context, format OutputFormat) error {
	api, err := a.api()
	if err != nil {
		return err
	}
	list, err := api.List(ctx)
	if err != nil {
		return apiError(err)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	if format == OutputJSON {
		if list == nil {
			list = []sandboxapi.Sandbox{}
		}
		return writeJSON(a.IO.Out, map[string]any{"sandboxes": list})
	}
	a.printStoppedNotices(ctx, api)
	if len(list) == 0 {
		a.note("no sandboxes; start one with `" + CommandName + " run claude` in a project folder")
		return nil
	}
	rows := make([][]string, 0, len(list))
	for _, sb := range list {
		rows = append(rows, []string{
			sb.Name, firstNonEmpty(sb.HarnessName, sb.Harness), phaseText(sb), sb.WorkdirMode, networkText(sb),
			humanDuration(time.Duration(sb.UptimeSeconds) * time.Second), hooksText(sb), a.tildePath(sb.Project),
		})
	}
	a.table([]string{"NAME", "HARNESS", "PHASE", "MODE", "NETWORK", "UPTIME", "HOOKS", "PROJECT"}, rows)
	if st, err := api.Status(ctx); err == nil && st.Gateway != nil {
		if note := otherDriverNote(list, st.Gateway.Driver); note != "" {
			a.note(note)
		}
	}
	return nil
}

// createdDriver is the compute driver sb was created on: docker for a
// record from before the driver was kept.
func createdDriver(sb sandboxapi.Sandbox) string {
	return firstNonEmpty(sb.Driver, string(openshell.DriverDocker))
}

// otherDriverSandboxes are the sandboxes created on another compute driver
// than the one the gateway runs now (live): one gateway runs one driver, so
// after a switch the others cannot start, and OpenShell lists them as
// missing or in error (GAP-0455).
func otherDriverSandboxes(list []sandboxapi.Sandbox, live string) []sandboxapi.Sandbox {
	if live == "" {
		return nil
	}
	var out []sandboxapi.Sandbox
	for _, sb := range list {
		if sb.Phase != "deleted" && !beingCreated(sb) && createdDriver(sb) != live {
			out = append(out, sb)
		}
	}
	return out
}

// beingCreated reports a sandbox whose create is still under way and has
// recorded no driver yet: it is being made on the driver the gateway runs
// now, never an old record of the docker driver (GAP-1431).
func beingCreated(sb sandboxapi.Sandbox) bool {
	return sb.Driver == "" && (sb.Phase == "creating" || sb.Phase == "provisioning" || sb.Phase == "pending")
}

// otherDriverNote says which sandboxes belong to a driver the gateway no
// longer runs, and what that means ("" when none does).
func otherDriverNote(list []sandboxapi.Sandbox, live string) string {
	other := otherDriverSandboxes(list, live)
	if len(other) == 0 {
		return ""
	}
	names := make([]string, 0, len(other))
	for _, sb := range other {
		names = append(names, sb.Name+" ("+createdDriver(sb)+")")
	}
	was := "was"
	if len(other) > 1 {
		was = "were"
	}
	// OpenShell's gateway drops a sandbox its driver does not run a few
	// minutes after the switch, and a switch back does not bring it back:
	// promising that it can run again lost a stopped sandbox's work
	// (GAP-0663).
	return strings.Join(names, ", ") + " " + was + " created on a compute driver the gateway no longer runs: the gateway runs " + live +
		" now, and one gateway runs one driver, so " + itThem(names) + " cannot start, and OpenShell drops " + itThem(names) +
		" a few minutes after the switch, with any work in " + itThem(names) + " that was not brought back; `" + CommandName +
		" delete NAME` releases DefenseClaw's side"
}

func phaseText(sb sandboxapi.Sandbox) string {
	p := sb.Phase
	if sb.Orphaned {
		p += " (orphaned)"
	}
	if sb.PendingApprovals > 0 {
		p += fmt.Sprintf(" (%d ask)", sb.PendingApprovals)
	}
	return p
}

// networkText is the NETWORK cell: the sandbox's network profile, and the
// pack when its name differs. The assigned organization profile is separate.
func networkText(sb sandboxapi.Sandbox) string {
	if sandboxPolicyPending(sb) {
		return "pending"
	}
	if sb.Pack != "" && sb.Pack != sb.Profile {
		return sb.Profile + " (pack " + sb.Pack + ")"
	}
	return sb.Profile
}

// sandboxPolicyPending reports a creation that has not received a complete
// resolved policy yet. Empty fields do not imply an open policy.
func sandboxPolicyPending(sb sandboxapi.Sandbox) bool {
	return sb.Phase == "creating" && (sb.Pack == "" || sb.Profile == "" || sb.NetworkMode == "" || sb.Approvals == "")
}

func hooksText(sb sandboxapi.Sandbox) string {
	switch {
	case sb.Hooks.Tampered > 0:
		// A tool call ran without a DefenseClaw verdict: the most urgent
		// thing the column can say.
		return "tamper!"
	case sb.Hooks.Unreachable:
		return "unreachable!"
	case sb.Hooks.Silent:
		return "silent!"
	case sb.Hooks.HookRequests == 0 && sb.Hooks.ToolCalls == 0:
		// No hook reached DefenseClaw yet. A restarted daemon keeps the
		// counts, not the time of the last hook (GAP-0166).
		return "-"
	}
	s := plural(sb.Hooks.ToolCalls, "call", "calls")
	if sb.Hooks.ToolBlocked > 0 {
		s += fmt.Sprintf(", %d blocked", sb.Hooks.ToolBlocked)
	}
	if sb.Hooks.ToolAsked > 0 {
		s += fmt.Sprintf(", %d asked", sb.Hooks.ToolAsked)
	}
	if sb.Hooks.PromptBlocked > 0 {
		s += ", " + plural(sb.Hooks.PromptBlocked, "prompt", "prompts") + " blocked"
	}
	if sb.Hooks.HookFailed > 0 {
		s += fmt.Sprintf(", %d failed", sb.Hooks.HookFailed)
	}
	return s
}

// Status is `sandbox status [name]`.
func (a *App) Status(ctx context.Context, name string, format OutputFormat) error {
	api, err := a.api()
	if err != nil {
		return err
	}
	if name == "" {
		st, err := api.Status(ctx)
		if err != nil {
			return apiError(err)
		}
		if format == OutputJSON {
			return writeJSON(a.IO.Out, neutralStatus(st))
		}
		a.printStoppedNotices(ctx, api)
		a.printStatus(st)
		return nil
	}
	sb, err := api.GetConfirmed(ctx, name)
	if err != nil {
		return apiError(err)
	}
	if format == OutputJSON {
		return writeJSON(a.IO.Out, sb)
	}
	a.printSandbox(sb)
	if sb.Phase == "ready" {
		a.printDetachedRun(ctx, sb)
		a.printOverlayDisk(ctx, sb)
	}
	if sb.Phase == "stopped" {
		if why := startRefusal(keptPolicy(ctx, api, sb), sb); why != "" {
			a.warn(sb.Name + " cannot start under the current policy: " + why + "; delete it (`" + CommandName + " delete " + sb.Name +
				"`) and run again")
		}
	}
	return nil
}

// printDetachedRun says where a running sandbox's detached run is: one that
// finished left the sandbox ready (and holding a mounted folder) with
// nothing saying the job was done (GAP-0231).
func (a *App) printDetachedRun(ctx context.Context, sb *sandboxapi.Sandbox) {
	gateway, err := a.gatewayName(ctx)
	if err != nil {
		return
	}
	run, err := a.detachedRun(ctx, a.cli(gateway), sb)
	if err != nil {
		return
	}
	logs := "`" + CommandName + " logs " + sb.Name + "`"
	switch run.State {
	case sandboxapi.RunRunning:
		a.note("its detached run" + a.startedText(run.Started) + " is still going; " + logs + " -f follows it")
	case sandboxapi.RunExited:
		exit := ""
		if run.Exit != "" {
			exit = " (exit status " + run.Exit + ")"
		}
		a.note("its detached run" + a.startedText(run.Started) + " finished" + exit + "; " + logs + " shows it. " + sb.Name +
			" keeps running until you stop it: `" + CommandName + " stop " + sb.Name + "` (or delete it). A detached run may leave no conversation to continue; connect normally to start a new one")
	}
}

func (a *App) printStatus(st *sandboxapi.Status) {
	row := func(k, v string) { a.line(fmt.Sprintf("%-16s%s", k, v)) }
	state := "off (run `" + CommandName + " setup`)"
	switch {
	case st.Managed != nil:
		state = managedOffState(st)
	case st.GatewayElsewhere != "":
		// Setup would stop at the other account's gateway (GAP-0307).
		state = "off: another account runs this machine's OpenShell gateway (" + st.GatewayElsewhere + "); see `" + CommandName + " doctor`"
	}
	if st.Enabled {
		state = "on"
	}
	row("Sandboxes", state)
	if st.Enabled {
		if st.Available {
			row("OpenShell", "connected")
		} else if st.Managed != nil && st.GatewayElsewhere != "" {
			row("OpenShell", managedAccountBusyText)
		} else if st.Managed != nil && st.Managed.Unavailable == "" {
			row("OpenShell", a.managedFirstRunText(st.Managed))
		} else {
			row("OpenShell", "unavailable: "+firstNonEmpty(st.Reason, "not connected"))
		}
	}
	if g := st.Gateway; g != nil {
		health := "healthy"
		if !g.Healthy {
			health = "unhealthy"
		}
		row("Gateway", fmt.Sprintf("%s %s (%s, workspace %s) %s", g.Name, g.Version, g.Endpoint, firstNonEmpty(g.Workspace, "default"), health))
	}
	if st.IngressAddr != "" {
		row("Hook ingress", st.IngressAddr)
	}
	if st.EgressAddr != "" {
		row("Egress proxy", st.EgressAddr)
	}
	if st.Pack != "" || st.Profile != "" {
		row("Policy", "pack "+firstNonEmpty(st.Pack, "open")+", network "+firstNonEmpty(st.Profile, "open"))
	}
	if st.Admin.Configured && st.Managed == nil {
		row("Organization", adminText(st.Admin))
	}
	if m := st.Managed; m != nil {
		for _, r := range managedStatusRows(m, a.Now()) {
			row(r[0], r[1])
		}
	}
	row("Running", fmt.Sprintf("%d of %d", st.Running, st.Sandboxes))
	if st.PendingApprovals > 0 {
		row("Asks", fmt.Sprintf("%d waiting (`%s approvals`)", st.PendingApprovals, CommandName))
	}
	if st.TelemetryFailures > 0 {
		row("Telemetry", a.style(fmt.Sprintf("%s refused since the daemon started; last: %s",
			plural(st.TelemetryFailures, "record", "records"), truncate(sandboxapi.DisplayText(st.TelemetryError), 200)), ansiRed))
	}
}

func (a *App) printSandbox(sb *sandboxapi.Sandbox) {
	row := func(k, v string) {
		if v != "" {
			a.line(fmt.Sprintf("%-14s%s", k, v))
		}
	}
	a.println(a.bold(sb.Name))
	row("Harness", strings.TrimSpace(firstNonEmpty(sb.HarnessName, sb.Harness)+" "+sb.HarnessVersion))
	phase := phaseText(*sb)
	if sb.PhaseReason != "" && sb.Phase == "error" {
		// Why, in words (GAP-0297): the phase alone said nothing.
		phase += ": " + sb.PhaseReason
	}
	row("Phase", phase)
	if sb.UptimeSeconds > 0 {
		row("Uptime", humanDuration(time.Duration(sb.UptimeSeconds)*time.Second))
	}
	row("Project", a.tildePath(sb.Project)+" → "+sb.Workdir+" ("+sb.WorkdirMode+")")
	yolo := "skip-permissions on"
	if !sb.Launch.Yolo {
		yolo = "skip-permissions off (harness prompts kept)"
	}
	row("Permissions", yolo)
	approvals := sb.Approvals
	if refusesAsks(sb) {
		// The floor refuses every ask, whatever triage's mode (GAP-0468).
		approvals = "refused (your profile doesn't let you approve asks)"
	}
	if sandboxPolicyPending(*sb) {
		row("Policy", "pending (resolving policy)")
	} else {
		row("Policy", fmt.Sprintf("pack %s, network %s, approvals %s", joinNonEmpty(" ", firstNonEmpty(sb.Pack, "open"), shortDigest(sb.PackDigest)), networkLabel(sb), approvals))
	}
	// On a managed computer: the organization profile the sandbox's
	// registration matches now, with the digest of the same match, so a
	// regroup shows here as in `policy explain` (#1199); and the
	// organization's words for a stop its policy made.
	if sb.OrganizationProfile != "" {
		row("Your policy", organizationPolicyText(sb.OrganizationProfile, sb.Provisional, sb.PolicyDigest)+" — "+CommandName+" policy explain")
	}
	row("Stopped", sb.StopReason)
	// What it was created with beyond the policy, which a resume keeps.
	for _, c := range grantTexts(sb.Credentials) {
		row("Secret", c)
	}
	if len(sb.HostPorts) > 0 {
		var hosts []string
		for _, p := range sb.HostPorts {
			hosts = append(hosts, fmt.Sprintf("localhost:%d", p))
		}
		if refusesAsks(sb) {
			row("Host ports", strings.Join(hosts, " ")+" (closed: your profile doesn't let you approve them)")
		} else {
			row("Host ports", strings.Join(hosts, " ")+" (each an ask at the sandbox's first connection)")
		}
	}
	row("Hooks", fmt.Sprintf("%s tier, contract %s", firstNonEmpty(sb.TamperTier, "unknown"), firstNonEmpty(sb.HookContract, "-")))
	cov := plural(sb.Hooks.HookRequests, "request", "requests") + ", " + plural(sb.Hooks.ToolCalls, "tool call", "tool calls") +
		fmt.Sprintf(", %d blocked", sb.Hooks.ToolBlocked)
	if sb.Hooks.ToolAsked > 0 {
		cov += fmt.Sprintf(", %d asked", sb.Hooks.ToolAsked)
	}
	if sb.Hooks.PromptBlocked > 0 {
		cov += ", " + plural(sb.Hooks.PromptBlocked, "prompt", "prompts") + " blocked"
	}
	if sb.Hooks.HookFailed > 0 {
		cov += fmt.Sprintf(", %d failed (fail closed)", sb.Hooks.HookFailed)
	}
	if !sb.Hooks.LastHookAt.IsZero() {
		cov += ", last " + sb.Hooks.LastHookAt.Local().Format("15:04:05")
	}
	if sb.Hooks.IngressRefused > 0 {
		cov += fmt.Sprintf(", %d refused by OpenShell", sb.Hooks.IngressRefused)
	}
	if sb.Hooks.Silent {
		cov += a.style(" — SILENT since "+sb.Hooks.SilentSince.Local().Format("15:04:05"), ansiRed)
	}
	if sb.Hooks.Unreachable {
		cov += a.style(" — NOT REACHING DefenseClaw since "+sb.Hooks.UnreachableSince.Local().Format("15:04:05"), ansiRed)
	}
	row("Hook traffic", cov)
	row("Hook events", hookEventsText(sb.Hooks))
	if n := sb.Hooks.Tampered; n > 0 {
		// A post-tool hook whose tool DefenseClaw denied or never saw: the
		// hooks were tampered with (hooks.on_tamper decides what follows).
		tamper := plural(n, "tool call", "tool calls") + " ran without a DefenseClaw verdict"
		if !sb.Hooks.LastTamperAt.IsZero() {
			tamper += ", last " + sb.Hooks.LastTamperAt.Local().Format("15:04:05")
		}
		row("Tamper", a.style(tamper+" (`"+CommandName+" activity --sandbox "+sb.Name+"` has each)", ansiRed))
	}
	if sb.Hooks.LastBlocked != "" {
		row("Last blocked", truncate(sb.Hooks.LastBlocked, 100))
	}
	if sb.Hooks.LastHookFailure != "" {
		at := ""
		if !sb.Hooks.LastHookFailureAt.IsZero() {
			at = " at " + sb.Hooks.LastHookFailureAt.Local().Format("15:04:05")
		}
		last := "DefenseClaw answered " + sb.Hooks.LastHookFailure + at + " (the hook failed closed)"
		if sb.Hooks.LastHookFailureCause == sandboxapi.ReasonPlaceholderRefused {
			// OpenShell refused that conversation's requests, not DefenseClaw
			// the hook (GAP-0377).
			last = "a hook post of a conversation that held a sandbox credential placeholder failed" + at + " (" +
				sb.Hooks.LastHookFailure + "; OpenShell refuses such a conversation's requests; the hook failed closed)"
		}
		if !sb.Hooks.HooksAnsweredAt.IsZero() {
			last += "; hooks answered again since " + sb.Hooks.HooksAnsweredAt.Local().Format("15:04:05")
		}
		row("Hook error", last)
	}
	if sb.Hooks.ModelKeyRejected != "" {
		row("Model key", a.style(sb.Hooks.ModelKeyRejected+" (last rejected "+sb.Hooks.ModelKeyRejectedAt.Local().Format("15:04:05")+")", ansiRed))
	}
	if at := sb.Hooks.PlaceholderRefusedAt; !at.IsZero() {
		row("Conversation", a.style(sandboxapi.PlaceholderConversationText(sb.Name)+" (last refused "+at.Local().Format("15:04:05")+")", ansiRed))
	}
	failed := ""
	if n := sb.Egress.UpstreamFailed; n > 0 {
		// Allowed, and the host did not take them: an outage, not a block.
		failed = fmt.Sprintf(", %d failed upstream", n)
	}
	row("Egress", fmt.Sprintf("%s contacted, %d blocked%s, %s up, %s down", plural(int64(sb.Egress.Destinations), "destination", "destinations"), sb.Egress.Blocked,
		failed, humanBytes(sb.Egress.BytesUp), humanBytes(sb.Egress.BytesDown))+egressAIText(sb))
	for _, ep := range sb.Endpoints {
		row("Endpoint", ep.Host+" "+ep.Result)
	}
	if sb.Snapshot != nil {
		snap := "taken " + sb.Snapshot.CreatedAt.Local().Format("2006-01-02 15:04") + " (" + firstNonEmpty(sb.Snapshot.Kind, "a") + " snapshot)"
		if !sb.Snapshot.UndoneAt.IsZero() {
			snap += ", undone " + sb.Snapshot.UndoneAt.Local().Format("15:04")
		}
		row("Undo point", snap)
	}
	if sb.PendingApprovals > 0 {
		row("Asks", fmt.Sprintf("%d waiting (`%s approvals --sandbox %s`)", sb.PendingApprovals, CommandName, sb.Name))
	}
	(&session{app: a}).printNested(sb)
	for _, v := range sb.Violations {
		a.warn(a.violationText(&v, v.Message, v.Detail, v.Admin))
	}
	for _, w := range sb.Warnings {
		a.warn(w)
	}
	if !sb.UnflushedAt.IsZero() {
		a.warn(sandboxapi.UnflushedText(sb.Name, sb.UnflushedAt))
	}
	if sb.Hooks.Unreachable {
		a.warn(hooksWarningText(sb.Hooks.UnreachableReason))
	}
	if sb.Orphaned {
		a.warn("DefenseClaw holds no binding for this sandbox; its hooks cannot authenticate. Delete it.")
	}
}

// hookEventsText is the verdicts per hook event, the most frequent first:
// "PreToolUse 12 · PostToolUse 11 · Stop 2"; "" before the first verdict.
func hookEventsText(h sandboxapi.HookCoverage) string {
	names := make([]string, 0, len(h.Events))
	for name := range h.Events {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if ni, nj := h.Events[names[i]], h.Events[names[j]]; ni != nj {
			return ni > nj
		}
		return names[i] < names[j]
	})
	parts := make([]string, 0, len(names)+1)
	for _, name := range names {
		parts = append(parts, fmt.Sprintf("%s %d", sandboxapi.DisplayText(name), h.Events[name]))
	}
	if h.OtherEvents > 0 {
		parts = append(parts, fmt.Sprintf("other events %d", h.OtherEvents))
	}
	return strings.Join(parts, " · ")
}

func shortDigest(d string) string {
	if strings.HasPrefix(d, "sha256:") && len(d) > 19 {
		return "(" + d[:19] + "…)"
	}
	return ""
}

// ConnectOptions are the `sandbox connect` flags.
type ConnectOptions struct {
	Name    string
	Shell   bool
	Refresh bool
	Rm      bool
	Yes     bool
	// Prompt runs the harness headless with one prompt (no terminal
	// needed).
	Prompt string
	Args   []string
}

// Connect resumes a sandbox: it starts it when stopped and attaches the
// harness (or, with Shell, a login shell) to the terminal, or runs one
// prompt headless (Prompt, or the harness's own print flag in Args).
func (a *App) Connect(ctx context.Context, o ConnectOptions) (err error) {
	a.defaults()
	// An interrupt ends the session through its cleanup (interrupt.go).
	ctx, done := a.interruptible(ctx)
	defer func() {
		err = a.interruptedExit(err)
		done()
	}()
	if o.Shell && (o.Prompt != "" || len(o.Args) > 0) {
		return errors.New("--shell opens a shell; it takes no --prompt or harness arguments")
	}
	api, err := a.api()
	if err != nil {
		return err
	}
	sb, err := api.Get(ctx, o.Name)
	if err != nil {
		return apiError(err)
	}
	if sb.Phase == "ready" && sb.OldSupervisor {
		// Its session runs a supervisor whose network broker can let its
		// connections bypass its policy. DefenseClaw stops no such sandbox
		// on its own, a connect included: only the user's own stop, once
		// they saved their work, ends it.
		return oldSupervisorRefusal(sb)
	}
	spec, err := ResolveHarness(sb.Harness)
	if err != nil {
		return err
	}
	headless := !o.Shell && (o.Prompt != "" || printMode(spec, o.Args))
	if !a.IO.TTY && !headless {
		if o.Shell {
			return errors.New("`sandbox connect --shell` needs a terminal; run one command with `" + CommandName + " exec " + sb.Name + " -- COMMAND`")
		}
		return fmt.Errorf("`sandbox connect` attaches %s to your terminal, and there is none; pass --prompt TEXT to run one prompt headless", spec.DisplayName)
	}
	gateway, err := a.gatewayName(ctx)
	if err != nil {
		return err
	}
	cli := a.cli(gateway)
	// The run's harness options come first, then the ones given now; its
	// banner lines come back too.
	run := a.runLaunchOf(sb)
	args := o.Args
	shown := RunOptions{Args: args, Prompt: o.Prompt}
	if run != nil {
		if !o.Shell {
			args = sessionArgs(run.Args, o.Args)
		}
		shown = RunOptions{Args: args, Prompt: o.Prompt, Credentials: run.Credentials, GitHubWrite: run.GitHubWrite, HostPorts: run.HostPorts}
	}
	started, kept := false, sb.Phase == "ready"
	if sb.Phase != "ready" {
		a.note("starting " + sb.Name + "…")
		before := sb
		startedSandbox, retained, startErr := a.startSandbox(ctx, api, before, StartOptions{}, true)
		if startErr != nil {
			// A pull may have started this stopped copy after our first get.
			// Attach to the now-ready sandbox; this connect did not start it.
			if !sandboxapi.IsCode(startErr, sandboxapi.CodeConflict) {
				return startErr
			}
			if sb, err = api.Get(ctx, before.Name); err != nil {
				return startErr
			}
			sb = a.settledSandbox(ctx, api, sb)
			if sb.Phase != "ready" {
				return startErr
			}
			a.note(before.Name + " is running now; attaching…")
		} else {
			sb, kept, started = startedSandbox, retained, true
		}
	}
	continueAfterDetached := false
	if spec.Name == "claudecode" && slices.Contains(o.Args, "--continue") {
		if prior, priorErr := a.detachedRun(ctx, cli, sb); priorErr == nil && prior.State == sandboxapi.RunExited {
			continueAfterDetached = true
		}
	}
	s := &session{app: a, api: api, cli: cli, spec: spec, sb: sb, rm: o.Rm, yes: o.Yes, started: started, headless: headless, shell: o.Shell,
		continueAfterDetached: continueAfterDetached,
		passArgs:              len(o.Args) > 0}
	// fail stops the sandbox this command started for a session that never
	// began: the probe, the refresh or the harness's start failed.
	fail := func(err error) error {
		if started {
			switch keep, serr := a.stopIfAlone(context.WithoutCancel(ctx), api, sb.Name, nil); {
			case keep != "":
				a.warn(sb.Name + " keeps running after the failure: " + keep)
			case serr != nil:
				a.warn("could not stop " + sb.Name + " after the failure: " + apiError(serr).Error())
			default:
				a.warn("stopped " + sb.Name + " after the failure")
			}
		}
		return err
	}
	if o.Refresh && sb.WorkdirMode == config.OpenShellWorkdirCopy {
		// The refresh replaces the copy, workdir included (a failed refresh
		// may have left none): probe outside it, and the refresh's baseline
		// checks the new workdir.
		if err := s.probe(ctx, ""); err != nil {
			return fail(err)
		}
		if err := a.refreshCopy(ctx, s); err != nil {
			return fail(err)
		}
	} else if err := s.probe(ctx, sb.Workdir); err != nil {
		return fail(err)
	}
	// The policy the sandbox runs under, for the banner's Uploads line; a
	// daemon that cannot say leaves the line out.
	var policy []sandboxapi.Setting
	var repo *sandboxapi.RepoPolicy
	var managedPolicy *sandboxapi.ManagedStatus
	if ex, err := api.Explain(ctx, sandboxapi.ExplainRequest{Sandbox: sb.Name}); err == nil {
		policy, repo, managedPolicy = ex.Settings, ex.RepoPolicy, managedStatusOfExplain(ex.Managed)
	}
	a.banner(sb, bannerInfo{llm: a.sandboxLLM(spec, sb, run), o: shown, keptSnapshot: kept, policy: policy, repo: repo, managed: managedPolicy})
	var code int
	if o.Shell {
		// A shell in the project, reviewed at its end like a harness
		// session: what it changed is kept or undone the same way.
		if _, err = s.attachShell(ctx); err != nil {
			return fail(err)
		}
		code = 0
	} else {
		opts := harness.LaunchOptions{Mode: harness.Interactive, Yolo: sb.Launch.Yolo,
			CredentialProfile: sb.Launch.CredentialProfile, BedrockRegion: sb.Launch.BedrockRegion,
			Args: a.filterBypass(spec, sb, args)}
		if o.Prompt != "" {
			opts.Mode, opts.Prompt = harness.Headless, o.Prompt
		}
		if code, err = s.attach(ctx, opts, headless); err != nil {
			return fail(err)
		}
	}
	if err := s.end(ctx); err != nil {
		return err
	}
	return s.exit(code)
}

// oldSupervisorRefusal refuses an exec or a connect of the ready sandbox
// sb, whose session runs the supervisor of an OpenShell release older than
// openshell.SupportedMin (sandboxapi.Sandbox.OldSupervisor): its network
// broker can let its connections bypass its policy (NVIDIA/OpenShell#4494),
// and DefenseClaw cannot contain it. DefenseClaw stops it for nobody: the
// refusal names the user's own stop, which on a MicroVM syncs its disk
// first because that release's stop does not.
func oldSupervisorRefusal(sb *sandboxapi.Sandbox) error {
	name := sb.Name
	stop := "save the work you need, then run `" + CommandName + " stop " + name + "`"
	if d, ok := openshell.LookupDriver(sb.Driver); !ok || !d.StopFlushes {
		stop += ", which syncs the VM's disk first (that release's stop does not flush it, so what the guest writes after the sync may be lost)"
	}
	return fmt.Errorf("%s: legacy sandbox running, not protected by the 1.0.4 egress policy: its session runs the supervisor of an OpenShell release older than %s, "+
		"whose network broker can let the sandbox's connections bypass its policy (NVIDIA/OpenShell#4494), so DefenseClaw runs nothing in it and does not stop it for you: "+
		"%s; then `%s start %s` (or `connect`) runs it on the gateway's own supervisor",
		name, openshell.SupportedMin, stop, CommandName, name)
}

// refreshCopy re-stages a copy-mode sandbox's project and uploads it.
func (a *App) refreshCopy(ctx context.Context, s *session) error {
	// The sandbox's own policy decides what is held back, as at its run,
	// its repository policy (the one its run read) included.
	repo, err := a.sandboxRepoPolicy(ctx, s.api, s.sb.Name)
	if err != nil {
		return err
	}
	var ws *sandboxapi.WorkspacePolicy
	if a.ManagedHost() {
		// The sandbox's copy policy, as its daemon resolves it (GAP-0478).
		ex, err := s.api.Explain(ctx, sandboxapi.ExplainRequest{Sandbox: s.sb.Name})
		if err != nil {
			return apiError(err)
		}
		ws = ex.Workspace
	}
	stage, err := a.copyStageOptions(packs.Flags{Pack: s.sb.Pack, Harness: s.sb.Harness, Project: s.sb.Project, Profile: s.sb.Profile,
		RepoPolicy: repo}, s.sb.Name, ws)
	if err != nil {
		return err
	}
	t := a.transport(s.cli)
	a.note("refreshing the project copy in " + s.sb.Name + "…")
	rec, err := a.Workspace.Refresh(ctx, workspace.RefreshOptions{Stage: stage, Exec: t, Upload: t})
	if err != nil {
		hint := a.diskFullHint(err)
		switch {
		case errors.Is(err, workspace.ErrUploadNotArrived):
			hint = strayUploadHint
		case errors.Is(err, workspace.ErrUnpulledChanges):
			// One sentence: connect and run take no flag that discards it.
			return &wsError{msg: s.sb.Name + " has work that was not pulled: bring it back with `" + CommandName + " pull " + s.sb.Name +
				" --apply` (or --branch, or --patch-out FILE), or connect without --refresh to go on with the copy as it is", err: err}
		case errors.Is(err, workspace.ErrUnappliedPull):
			hint = "bring the work back first (`" + CommandName + " pull " + s.sb.Name + " --apply`, --branch or --patch-out FILE), " +
				"or connect without --refresh to go on with the copy as it is"
		}
		return workspaceFailure("refresh the copy", err, hint)
	}
	files, b := int64(rec.Files), rec.Bytes
	_ = s.api.ReportWorkspace(ctx, s.sb.Name, sandboxapi.WorkspaceReport{Operation: sandboxapi.WorkspaceUpload, Result: "completed", FileCount: &files, ByteCount: &b})
	a.copyWarnings(rec)
	return nil
}

// ExecOptions are the `sandbox exec` flags.
type ExecOptions struct {
	Name    string
	Workdir string
	TTY     bool
	NoTTY   bool
	Command []string
}

// Exec runs a command in a sandbox, through the image's sandbox-env
// wrapper (harness.SandboxEnvPath).
func (a *App) Exec(ctx context.Context, o ExecOptions) error {
	a.defaults()
	if len(o.Command) == 0 {
		return errors.New("name the command to run after --")
	}
	api, err := a.api()
	if err != nil {
		return err
	}
	sb, err := api.Get(ctx, o.Name)
	if err != nil {
		return apiError(err)
	}
	if sb.Phase == "ready" && sb.OldSupervisor {
		return oldSupervisorRefusal(sb)
	}
	if sb.Phase != "ready" {
		return fmt.Errorf("%s is %s; start it with `%s start %s`", sb.Name, sb.Phase, CommandName, sb.Name)
	}
	gateway, err := a.gatewayName(ctx)
	if err != nil {
		return err
	}
	cli := a.cli(gateway)
	tty := (a.IO.TTY || o.TTY) && !o.NoTTY
	// OpenShell starts the command without a login shell; the image's
	// wrapper gives it the egress proxy and the harness shim the connect
	// shell gets from /etc/profile.d.
	session, err := newExecSession()
	if err != nil {
		return err
	}
	command := execSessionArgv(session, append([]string{harness.SandboxEnvPath}, o.Command...))
	inv, err := cli.Exec(sb.Name, command, openshell.CLIExecOptions{TTY: tty, WorkDir: firstNonEmpty(o.Workdir, sb.Workdir)})
	if err != nil {
		return err
	}
	// The command can change a copy: what it held as the sandbox last
	// stopped is no longer known, and a look at it made before is not
	// recorded at its stop (copyBase; best effort: exec holds no lease).
	a.forgetStoppedCopy(sb.Name)
	_ = a.bumpAttachStamp(sb.Name)
	// The command outlives a client that is ended (execreap.go): one told
	// to end stops what the command left running before it exits.
	runCtx, stop := untilTerminated(ctx, tty)
	var code int
	if tty {
		code, err = a.Terminal.Run(runCtx, inv)
	} else {
		code, err = a.Streamer.Stream(runCtx, inv, a.IO.Out, a.IO.Err)
	}
	ended := runCtx.Err() != nil
	sig := stop()
	if ended {
		a.reapExec(ctx, cli, sb.Name, session)
		if sig != nil {
			return &ExitError{Code: signalExitCode(sig)}
		}
		return ctx.Err()
	}
	if err != nil {
		return err
	}
	if code != 0 {
		// OpenShell's own line ("exec relay closed before the command
		// reported an exit status") does not say why: the sandbox stopped
		// under the command, or the gateway restarted.
		if after, err := api.Get(ctx, sb.Name); err == nil && after.Phase != "ready" {
			a.warn(execEndedText(after))
		}
		return &ExitError{Code: code}
	}
	return nil
}

// execEndedText says why a command in sb ended with it: sb is not ready
// any more.
func execEndedText(sb *sandboxapi.Sandbox) string {
	switch h := sb.Hooks; {
	case h.Silent && h.OnSilence == packs.OnSilenceStop:
		return "DefenseClaw stopped " + sb.Name + " while the command ran: its harness worked for " + firstNonEmpty(h.SilenceAfter, "a while") +
			" without a hook reaching DefenseClaw (hooks.on_silence: stop)"
	case sb.Phase == "unknown" || sb.Phase == "provisioning" || sb.Phase == "starting":
		return "the connection to " + sb.Name + " was lost while the command ran (the OpenShell gateway restarted, for one); `" +
			CommandName + " status " + sb.Name + "` shows whether it runs"
	}
	// A session that started the sandbox stops it as it ends, a command in
	// another terminal running or not; one that found it running leaves it
	// running (GAP-0390).
	return sb.Name + " is " + sb.Phase + ": it stopped while the command ran (an agent session that started it ended, or `" + CommandName +
		" stop`, the TUI, or DefenseClaw stopped it); start it with `" + CommandName + " start " + sb.Name +
		"` before the session and the command, and it keeps running when the session ends"
}

// StopOptions are the `sandbox stop` flags.
type StopOptions struct {
	Name string
	// Yes stops a sandbox whose detached run is still going, or a MicroVM
	// whose own disk could not be looked at, without asking, and stops a
	// MicroVM whose earlier stop was held because its disk sync failed
	// even when the sync fails again (StopAcceptingUnsynced). A copy-mode
	// MicroVM whose disk is full keeps running even so (fullDiskStop).
	Yes bool
}

// ExitStopKept is the exit status of a `sandbox stop` that kept the
// sandbox running because stopping it would lose work (fullDiskStop): the
// TUI says why from it.
const ExitStopKept = 5

// Stop is `sandbox stop`. A detached run the stop would end is confirmed
// on a terminal (said otherwise); the daemon's stop marks it interrupted
// and keeps its log for `sandbox logs`.
// The copy of a copy-mode sandbox nothing runs in any more is looked at
// first: what it holds as it stops is remembered (markStoppedCopy), so
// `delete` need not warn about work that came back already, and the next
// pull need not start it. A copy-mode MicroVM whose own disk is full keeps
// running while its copy holds work that was not pulled (fullDiskStop).
func (a *App) Stop(ctx context.Context, o StopOptions) error {
	a.defaults()
	api, err := a.api()
	if err != nil {
		return err
	}
	sb, err := api.Get(ctx, o.Name)
	if err != nil {
		return apiError(err)
	}
	var copyAt *workspace.CopyStatus
	var base copyBase
	asked := 0
	if sb.Phase == "ready" {
		if gateway, err := a.gatewayName(ctx); err == nil {
			cli := a.cli(gateway)
			ok, idle, attached, err := a.beforeStop(ctx, cli, sb, o.Yes)
			asked = attached
			if err != nil {
				return err
			}
			if !ok {
				a.note(sb.Name + " keeps running")
				return nil
			}
			// A detached run or a session still going can change the copy
			// between the look and the stop.
			if sb.WorkdirMode == config.OpenShellWorkdirCopy && idle {
				base = a.copyBaseOf(sb)
				n, err := a.attachedSessions(sb.Name)
				if err != nil {
					return attachedUnknown(sb.Name, err)
				}
				if n == 0 {
					copyAt = a.copyAtStop(ctx, cli, sb)
				}
			}
			if ok, err := a.fullDiskStop(ctx, cli, sb, copyAt, o.Yes); err != nil || !ok {
				if err == nil {
					a.note(sb.Name + " keeps running")
				}
				return err
			}
		}
	}
	// The stop is decided under the sandbox's exclusive gate: a session that
	// attached since the question above is named and asked about again
	// (with no lock held while the question is open), and none attaches
	// between the last count and OpenShell's stop. What the look found is
	// recorded under the gate too, unless something ran in the copy after
	// it: a session that attached since (also one that has ended) or a hook
	// request (copyBase).
	var stopped *sandboxapi.Sandbox
	var stopErr error
	err = a.endAsked(ctx, o.Name, asked, func(others int) (bool, error) {
		copyAt = nil
		return a.confirmEnding(attachedText(o.Name, others)+" now; stopping the sandbox ends "+them(others), "Stop anyway?", o.Yes)
	}, func() {
		if o.Yes {
			stopped, stopErr = api.StopAcceptingUnsynced(ctx, o.Name)
		} else {
			stopped, stopErr = api.Stop(ctx, o.Name)
		}
		if stopErr == nil && copyAt != nil && base.unchanged(a, o.Name, stopped) {
			a.markStoppedCopy(sb, copyAt.Work == workspace.CopyWorkNone, copyAt.Pulled)
		}
	})
	switch {
	case errors.Is(err, errKept):
		a.note(o.Name + " keeps running")
		return nil
	case err != nil:
		return err
	case stopErr != nil:
		return stopFailure(ctx, api, o.Name, stopErr)
	}
	if note := notStoppedNote(ctx, api, stopped); note != "" {
		a.warn(note)
		return nil
	}
	a.ok(stopped.Name + " is " + stopped.Phase)
	return nil
}

// stopFailure is the error of the stop of the sandbox name that the daemon
// refused (err). A daemon before DefenseClaw 1.0.4 (one an upgrade left
// running) answers the stop of a MicroVM in OpenShell's error state with
// OpenShell's words alone ("sandbox ... is in error state"), which name no
// way on (GAP-0871): when its error has no detail and the sandbox is such a
// MicroVM, the error goes on with the sandbox, why OpenShell holds it and
// the command that ends it (notStoppedNote), as the 1.0.4 daemon's does.
func stopFailure(ctx context.Context, api API, name string, err error) error {
	var e *sandboxapi.Error
	if !errors.As(err, &e) || e.Detail != "" || e.Code == sandboxapi.CodeNotFound || daemonUnreachable(e) {
		return apiError(err)
	}
	sb, gerr := api.Get(ctx, name)
	if gerr != nil {
		return apiError(err)
	}
	note := notStoppedNote(ctx, api, sb)
	if note == "" {
		return apiError(err)
	}
	return fmt.Errorf("%w; %s", apiError(err), note)
}

// notStoppedNote is what a stop that OpenShell returned as it was leaves
// the user to do, "" when sb stopped or holds nothing: OpenShell does not
// stop a MicroVM whose main process completed or failed, which may still
// run, and DefenseClaw stops, restarts or upgrades no OpenShell gateway,
// and moves no account to another OpenShell setup, while one does
// (openshell.HoldsGateway). It names how to bring it to stopped
// (openshell.StopWayOn) on the release the daemon's gateway reports.
func notStoppedNote(ctx context.Context, api API, sb *sandboxapi.Sandbox) string {
	var phase openshell.SandboxPhase
	is := "completed"
	switch sb.Phase {
	case "completed":
		phase = openshell.PhaseCompleted
	case "error":
		phase, is = openshell.PhaseError, "in OpenShell's error state"
		if sb.PhaseReason != "" {
			is += " (" + sb.PhaseReason + ")"
		}
	default:
		return ""
	}
	if d, ok := openshell.LookupDriver(sb.Driver); ok && d.StopFlushes || !openshell.HoldsGateway(phase, sb.PhaseReason, false) {
		return ""
	}
	release := ""
	if st, err := api.Status(ctx); err == nil && st.Gateway != nil {
		release = st.Gateway.Version
	}
	return sb.Name + " is " + is + ": OpenShell does not stop it, so its MicroVM may still run, and DefenseClaw stops, restarts and upgrades " +
		"no OpenShell gateway under it, nor moves this account to another OpenShell setup, until OpenShell reports it stopped: " +
		openshell.StopWayOn(sb.Name, phase, sb.PhaseReason, release)
}

// copyAtStop looks at the copy of sb, which is about to stop, within a
// minute: nil when it could not be looked at.
func (a *App) copyAtStop(ctx context.Context, cli openshell.CLI, sb *sandboxapi.Sandbox) *workspace.CopyStatus {
	look, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	st, err := a.Workspace.PendingWork(look, a.dataDir(), sb.Name, a.transport(cli))
	if err != nil {
		return nil
	}
	return &st
}

// fullDiskStop looks, before sb stops, at the own disk of a copy-mode
// MicroVM whose copy may hold work that was not pulled (look, what
// copyAtStop found, is nil or says so): a MicroVM stopped with that disk
// full cannot start again, so that work could not be read any more
// (#1144). A full disk keeps it running, with what to do first; a disk the
// bounded look could not read (a MicroVM that does not answer) is
// confirmed on a terminal unless yes and said otherwise, so a hung MicroVM
// still stops. It reports whether the stop goes ahead.
func (a *App) fullDiskStop(ctx context.Context, cli openshell.CLI, sb *sandboxapi.Sandbox, look *workspace.CopyStatus, yes bool) (bool, error) {
	if sb.WorkdirMode != config.OpenShellWorkdirCopy || createdDriver(*sb) != string(openshell.DriverVM) || look != nil && !unpulledWork(look.Work) {
		return true, nil
	}
	disk := a.overlayDiskOf(ctx, cli, sb.Name)
	if !disk.known {
		return a.confirmEnding("could not read how full "+sb.Name+"'s own disk is (it did not answer within "+overlayDiskLook.String()+
			"); a MicroVM stopped with its disk full cannot start again, and its work that was not pulled would be lost", "Stop anyway?", yes)
	}
	if !disk.full() {
		return true, nil
	}
	if look == nil {
		// A detached run or another session kept it from being looked at
		// before: what matters now is whether anything would be lost.
		if look = a.copyAtStop(ctx, cli, sb); look != nil && !unpulledWork(look.Work) {
			return true, nil
		}
	}
	// Not even with --yes, which the macOS app and scripts pass to skip the
	// question about a detached run: stopped now, the MicroVM could never
	// start again, so a stop would only lose the work. Deleting it is the
	// way to give the work up.
	a.warn(fullDiskKeepText(sb.Name) + "; to give that work up, delete it: `" + CommandName + " delete " + sb.Name + "`")
	return false, &ExitError{Code: ExitStopKept, Err: &Silent{Err: errors.New(sb.Name + " keeps running: its own disk is full")}}
}

// unpulledWork reports copy work a stopped MicroVM with a full disk would
// lose: changes never pulled, or a copy that could not be looked at. A pull
// that was not applied is on this machine already.
func unpulledWork(w workspace.CopyWork) bool {
	return w == workspace.CopyWorkUnpulled || w == workspace.CopyWorkUnknown
}

// overlayDisk is a running MicroVM's own disk as `df` inside it reads it
// (overlayDiskOf). A MicroVM writes its changes to an overlay disk of its
// own ([openshell.drivers.vm] overlay_disk_mib), and one stopped with that
// disk full cannot start again (GAP-0297).
type overlayDisk struct {
	// known reports that the look answered in time.
	known bool
	// size and avail are in bytes.
	size, avail int64
}

// overlayDiskLook bounds the look at a MicroVM's own disk: one that hangs
// answers nothing, and the stop does not wait on it.
const overlayDiskLook = 15 * time.Second

// overlayDiskWarnPercent is how full a MicroVM's own disk is when a
// session and `sandbox status` say it is filling (#1148).
const overlayDiskWarnPercent = 90

// full reports a disk with no room left to start the MicroVM again on.
func (d overlayDisk) full() bool { return d.known && d.avail < lowDiskBytes }

// percent is how much of the disk is used.
func (d overlayDisk) percent() int64 {
	if d.size <= 0 {
		return 0
	}
	return (d.size - d.avail) * 100 / d.size
}

// filling reports a disk that is full or nearly so.
func (d overlayDisk) filling() bool {
	return d.known && (d.full() || d.percent() >= overlayDiskWarnPercent)
}

// overlayDiskOf looks at the own disk of the running MicroVM name with
// `df -Pk /` in it, within overlayDiskLook.
func (a *App) overlayDiskOf(ctx context.Context, cli openshell.CLI, name string) overlayDisk {
	inv, err := cli.Exec(name, []string{"df", "-Pk", "/"}, openshell.CLIExecOptions{Timeout: overlayDiskLook})
	if err != nil {
		return overlayDisk{}
	}
	var out strings.Builder
	if code, err := a.Streamer.Stream(ctx, inv, &out, io.Discard); err != nil || code != 0 {
		return overlayDisk{}
	}
	return parseOverlayDF(out.String())
}

// parseOverlayDF reads the size and the space left from `df -Pk` output:
// the last line's fields, counted from its end (the file system's name may
// hold spaces).
func parseOverlayDF(out string) overlayDisk {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 2 {
		return overlayDisk{}
	}
	f := strings.Fields(lines[len(lines)-1])
	if len(f) < 6 {
		return overlayDisk{}
	}
	size, err := strconv.ParseInt(f[len(f)-5], 10, 64)
	if err != nil || size <= 0 {
		return overlayDisk{}
	}
	avail, err := strconv.ParseInt(f[len(f)-3], 10, 64)
	if err != nil || avail < 0 {
		return overlayDisk{}
	}
	return overlayDisk{known: true, size: size << 10, avail: avail << 10}
}

// overlayDiskFillingText says that the MicroVM name's own disk is full or
// filling, and what to do before it stops; copyMode names a copy-mode
// sandbox, whose work a pull brings back.
func overlayDiskFillingText(name string, d overlayDisk, copyMode bool) string {
	text := fmt.Sprintf("%s's own disk is %d%% full (%s of %s free): a MicroVM stopped with its disk full cannot start again → `%s exec %s -- df -h /` shows it",
		name, d.percent(), humanBytes(d.avail), humanBytes(d.size), CommandName, name)
	if copyMode {
		text += "; `" + CommandName + " pull " + name + "` brings its work back before it fills"
	}
	return text
}

// printOverlayDisk warns in `sandbox status` when the running MicroVM sb's
// own disk is full or filling (#1148).
func (a *App) printOverlayDisk(ctx context.Context, sb *sandboxapi.Sandbox) {
	if createdDriver(*sb) != string(openshell.DriverVM) {
		return
	}
	gateway, err := a.gatewayName(ctx)
	if err != nil {
		return
	}
	if disk := a.overlayDiskOf(ctx, a.cli(gateway), sb.Name); disk.filling() {
		a.warn(overlayDiskFillingText(sb.Name, disk, sb.WorkdirMode == config.OpenShellWorkdirCopy))
	}
}

// StartOptions are the `sandbox start` flags.
type StartOptions struct {
	// NoSnapshot keeps the previous snapshot; NewSnapshot replaces it even
	// when the folder still holds an earlier session's changes.
	NoSnapshot  bool
	NewSnapshot bool
	// EndVM starts a MicroVM whose workload ended though its VM may still
	// run, which OpenShell's start ends with no flush
	// (sandboxapi.StartRequest.EndVM).
	EndVM bool
}

// Start is `sandbox start`.
func (a *App) Start(ctx context.Context, name string, o StartOptions) error {
	if o.NoSnapshot && o.NewSnapshot {
		return errors.New("--no-snapshot and --new-snapshot are exclusive")
	}
	api, err := a.api()
	if err != nil {
		return err
	}
	sb, err := api.Get(ctx, name)
	if err != nil {
		return apiError(err)
	}
	sb = a.settledSandbox(ctx, api, sb)
	if sb.Phase == "ready" {
		a.ok(sb.Name + " is already running → attach with `" + CommandName + " connect " + sb.Name + "`")
		return nil
	}
	kept := false
	if sb, kept, err = a.startSandbox(ctx, api, sb, o, false); err != nil {
		return err
	}
	a.ok(sb.Name + " is " + sb.Phase + " → attach with `" + CommandName + " connect " + sb.Name + "`")
	// A kept undo point was explained as the start kept it.
	if sb.WorkdirMode == config.OpenShellWorkdirMount && sb.Snapshot != nil && (!kept || o.NoSnapshot) {
		a.note(a.undoPointText(sb, kept))
	}
	return nil
}

// sandboxSettlePolls and sandboxSettleInterval bound how long a start or a
// pull waits for a sandbox OpenShell is still starting on its own.
const (
	sandboxSettlePolls    = 90
	sandboxSettleInterval = time.Second
)

// settledSandbox waits while OpenShell is still starting sb on its own: a
// gateway that restarts resumes a sandbox it kept, and a `start` or `pull`
// right then failed with "is starting, not stopped; stop it before starting
// a new session", which a stop could not do either (rel-1-0-3 BR-04 pass
// point A). It returns the sandbox as it settled, or as last seen when it
// did not settle in time or could not be read.
func (a *App) settledSandbox(ctx context.Context, api API, sb *sandboxapi.Sandbox) *sandboxapi.Sandbox {
	a.defaults()
	for poll := 0; poll < sandboxSettlePolls && (sb.Phase == "starting" || sb.Phase == "provisioning"); poll++ {
		if poll == 0 {
			a.note(sb.Name + " is " + sb.Phase + " (OpenShell is starting it); waiting for it…")
		}
		if err := a.Sleep(ctx, sandboxSettleInterval); err != nil {
			return sb
		}
		now, err := api.Get(ctx, sb.Name)
		if err != nil {
			return sb
		}
		sb = now
	}
	return sb
}

// DeleteOptions are the `sandbox delete` flags.
type DeleteOptions struct {
	Names        []string
	Yes          bool
	KeepSnapshot bool
}

// Delete is `sandbox delete`.
func (a *App) Delete(ctx context.Context, o DeleteOptions) error {
	api, err := a.api()
	if err != nil {
		return err
	}
	if len(o.Names) > 0 && (a.ManagedHost() || onManagedHost()) {
		st, statusErr := api.Status(ctx)
		if statusErr != nil {
			return apiError(statusErr)
		}
		if st != nil && !st.Enabled {
			// Concatenated, so the hint scan reads the suggested command
			// (TestSandboxHintsNameCommandsThatExist).
			return errors.New("the administrator has turned sandboxes off (openshell.enabled); kept sandboxes cannot be deleted until the account gateway runs. Ask the administrator to turn sandboxes on temporarily, then run `" + CommandName + " delete " + strings.Join(o.Names, " ") + "` again")
		}
	}
	var errs []error
	for _, name := range o.Names {
		question := "Delete sandbox " + name + " (its providers, credentials and, unless --keep-snapshot, its undo point)?"
		if sb, err := api.Get(ctx, name); err == nil {
			if sb.WorkdirMode == config.OpenShellWorkdirCopy {
				// A copy has no undo point: the folder was never mounted.
				question = "Delete sandbox " + name + " (its providers and credentials)?"
			}
			if lost := a.unhandedWork(ctx, sb); lost != "" {
				question = "Sandbox " + name + " " + lost + ". Delete it and discard that work?"
				if o.Yes {
					a.warn("sandbox " + name + " " + lost + "; deleting it discards that work (--yes)")
				}
			} else if h := a.lastHandover(sb); h != nil {
				a.note(name + "'s work was last " + a.handoverText(h) + "; nothing newer is left in it")
			}
		}
		n, err := a.attachedSessions(name)
		if err != nil {
			errs = append(errs, attachedUnknown(name, err))
			continue
		}
		if n > 0 {
			// Its sessions in other terminals end with it (GAP-0285).
			what := attachedText(name, n) + "; deleting it ends " + them(n)
			question = what + ". " + question
			if o.Yes {
				a.warn(what + " (--yes)")
			}
		}
		yes, err := a.confirm(question, o.Yes)
		if err != nil {
			return err
		}
		if !yes {
			continue
		}
		res, err := a.deleteAsked(ctx, api, name, n, o)
		if errors.Is(err, errKept) {
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, apiError(err)))
			continue
		}
		a.ok("deleted " + res.Name)
		a.forgetCLIState(name)
		for _, w := range res.Warnings {
			a.warn(w)
		}
	}
	return errors.Join(errs...)
}

// errKept is a stop or a delete the user declined once asked again.
var errKept = errors.New("kept")

// deleteAsked deletes sandbox name, whose deletion the user confirmed with
// asked sessions attached to it, under the sandbox's exclusive gate: one
// that attached since is named and asked about again (errKept when the
// answer is no), and none attaches between the last count and OpenShell's
// delete (endAsked).
func (a *App) deleteAsked(ctx context.Context, api API, name string, asked int, o DeleteOptions) (*sandboxapi.DeleteResponse, error) {
	var res *sandboxapi.DeleteResponse
	var deleteErr error
	err := a.endAsked(ctx, name, asked, func(others int) (bool, error) {
		ok, err := a.confirmEnding(attachedText(name, others)+" now; deleting it ends "+them(others), "Delete anyway?", o.Yes)
		if err == nil && !ok {
			a.note(name + " is kept")
		}
		return ok, err
	}, func() { res, deleteErr = api.Delete(ctx, name, sandboxapi.DeleteRequest{KeepSnapshot: o.KeepSnapshot}) })
	if err != nil {
		return nil, err
	}
	return res, deleteErr
}

// endAsked runs end, a stop or a delete of sandbox name that the user
// confirmed with asked sessions attached, under the sandbox's exclusive
// gate (lockForStop), once a count under it finds no more sessions than the
// answer covered. When it finds more, it lets the gate and the account's
// lifecycle lock go before it asks about them (ask; an open question must
// not hold up an attach, a gateway restart, Apply, Rollback, an upgrade or
// a managed drain of the account), then takes the gate and counts again.
// errKept when the answer is no; a count that cannot be made leaves the
// sandbox as it is (attachedUnknown).
func (a *App) endAsked(ctx context.Context, name string, asked int, ask func(others int) (bool, error), end func()) error {
	for {
		others, release, err := a.lockForStop(ctx, name)
		if err != nil {
			return attachedUnknown(name, err)
		}
		if others <= asked {
			end()
			release()
			return nil
		}
		release()
		ok, err := ask(others)
		if err != nil {
			return err
		}
		if !ok {
			return errKept
		}
		asked = others
	}
}

// deleteIfAlone deletes sandbox name, which this command created, unless a
// session is attached to it, deciding under the sandbox's exclusive gate
// (lockForStop): keep says why it was kept (sessions attached, or a count
// that could not be made), "" when OpenShell was asked to delete it.
func (a *App) deleteIfAlone(ctx context.Context, api API, name string) (keep string, err error) {
	others, release, err := a.lockForStop(ctx, name)
	if err != nil {
		return attachedUnknown(name, err).Error(), nil
	}
	defer release()
	if others > 0 {
		return attachedText(name, others) + " → delete it once " + map[bool]string{true: "it ends", false: "they end"}[others == 1] + ": " + CommandName + " delete " + name, nil
	}
	_, err = api.Delete(ctx, name, sandboxapi.DeleteRequest{})
	return "", err
}

// stopIfAlone stops sandbox name, which this command started, unless a
// session is attached to it, deciding under the sandbox's exclusive gate
// (lockForStop): keep says why it was left running (sessions attached, or
// a count that could not be made), "" when OpenShell was asked to stop it.
// then, when set, runs under the gate once the stop succeeded.
func (a *App) stopIfAlone(ctx context.Context, api API, name string, then func(stopped *sandboxapi.Sandbox)) (keep string, err error) {
	others, release, err := a.lockForStop(ctx, name)
	if err != nil {
		return attachedUnknown(name, err).Error(), nil
	}
	defer release()
	if others > 0 {
		return attachedText(name, others) + " → stop it once " + map[bool]string{true: "it ends", false: "they end"}[others == 1] + ": " + CommandName + " stop " + name, nil
	}
	stopped, err := api.Stop(ctx, name)
	if err == nil && then != nil {
		then(stopped)
	}
	return "", err
}

// unhandedWork says what work a copy-mode sandbox holds that never came
// back to the folder, which deleting the sandbox discards, and where its
// work last went: "" when there is none. A running sandbox's copy is looked
// at; a stopped one is judged by its last pull, and by what its copy held
// as it stopped.
func (a *App) unhandedWork(ctx context.Context, sb *sandboxapi.Sandbox) string {
	if sb == nil || sb.WorkdirMode != config.OpenShellWorkdirCopy {
		return ""
	}
	var ex workspace.Execer
	if sb.Phase == "ready" {
		if gateway, err := a.gatewayName(ctx); err == nil {
			ex = a.transport(a.cli(gateway))
		}
	}
	st, err := a.Workspace.PendingWork(ctx, a.dataDir(), sb.Name, ex)
	work := st.Work
	if ex == nil && (err != nil || work == workspace.CopyWorkUnknown) && a.cleanCopy(sb) {
		// What stopped it found nothing left to bring back, and it has not
		// run since.
		return ""
	}
	pull := "`" + CommandName + " pull " + sb.Name + " --apply|--branch|--patch-out FILE`"
	last := ""
	if h := a.lastHandover(sb); h != nil {
		last = "its work was last " + a.handoverText(h)
	}
	why := func(reasons ...string) string {
		var out []string
		for _, r := range append(reasons, last) {
			if r != "" {
				out = append(out, r)
			}
		}
		if len(out) == 0 {
			return ""
		}
		return " (" + strings.Join(out, "; ") + ")"
	}
	switch {
	case err != nil:
		return "may hold work that was never pulled back" + why("it could not be checked: "+truncate(gatewayTransportText(err.Error()), 120)) + "; " + pull + " brings it back"
	case work == workspace.CopyWorkUnpulled:
		return "holds work that was never pulled back" + why() + "; " + pull + " brings it back"
	case work == workspace.CopyWorkUnapplied:
		return "holds a pull that was never applied" + why() + "; " + pull + " applies it"
	case work == workspace.CopyWorkUnknown:
		return "may hold work that was never pulled back" + why("it is not running, so it was not checked") + "; " + pull + " looks"
	}
	return ""
}

// lastHandover is where a copy-mode sandbox's work last went, or nil.
func (a *App) lastHandover(sb *sandboxapi.Sandbox) *handover {
	if sb == nil || sb.WorkdirMode != config.OpenShellWorkdirCopy {
		return nil
	}
	if rec := a.copyHandoverOf(sb); rec != nil {
		return rec.Last
	}
	return nil
}

// LogsOptions are the `sandbox logs` flags.
type LogsOptions struct {
	Name   string
	Follow bool
	Lines  int
}

// Logs prints the output of a sandbox's detached run.
func (a *App) Logs(ctx context.Context, o LogsOptions) error {
	a.defaults()
	api, err := a.api()
	if err != nil {
		return err
	}
	sb, err := api.Get(ctx, o.Name)
	if err != nil {
		return apiError(err)
	}
	lines := o.Lines
	if lines <= 0 {
		lines = 200
	}
	out, flush := a.runLogWriter(sb)
	if sb.Phase != "ready" {
		return a.keptLogs(ctx, api, sb, lines, out, flush)
	}
	gateway, err := a.gatewayName(ctx)
	if err != nil {
		return err
	}
	cli := a.cli(gateway)
	var inv openshell.Invocation
	if o.Follow {
		// Follows the log until the run ends, then the status below.
		inv, err = cli.Exec(sb.Name, []string{"sh", "-c", runFollowScript, "sh", RunDir, strconv.Itoa(lines)},
			openshell.CLIExecOptions{WorkDir: sb.Workdir})
	} else {
		inv, err = cli.Exec(sb.Name, []string{"sh", "-c", runTailScript, "sh", RunDir, strconv.Itoa(lines)},
			openshell.CLIExecOptions{WorkDir: sb.Workdir, Timeout: time.Minute})
	}
	if err != nil {
		return err
	}
	// Only the OpenShell CLI's own messages reach stderr: both scripts keep
	// tail's inside the sandbox and exit runNoLog without a log.
	code, err := a.Streamer.Stream(ctx, inv, out, a.IO.Err)
	_ = flush()
	if o.Follow && ctx.Err() == nil {
		// A stop under the follower ends its stream: it says so, as a later
		// `sandbox logs` does, where it ended without a word (GAP-0318).
		if now, gerr := api.Get(ctx, o.Name); gerr == nil && now.Phase != "ready" {
			a.stoppedUnderFollower(ctx, api, now)
			return nil
		}
	}
	if err != nil {
		return err
	}
	switch code {
	case 0:
	case runNoLog:
		return fmt.Errorf("%s has no detached run output (start one with `%s run <harness> --detach --prompt TEXT`)", sb.Name, CommandName)
	default:
		return fmt.Errorf("could not read the run log of %s (exit status %d)", sb.Name, code)
	}
	run, err := a.detachedRun(ctx, cli, sb)
	if err != nil {
		return nil
	}
	switch run.State {
	case sandboxapi.RunRunning:
		a.note("the run is still going (follow it with -f)")
		if sb.Hooks.Unreachable {
			a.warn(hooksWarningText(sb.Hooks.UnreachableReason))
		}
		return nil
	case sandboxapi.RunInterrupted, sandboxapi.RunNone:
		a.warn("the run did not finish: the sandbox stopped while it ran")
		return nil
	}
	a.note("the run exited with status " + run.Exit)
	// The hooks of a finished run: read after it ended.
	if now, err := api.Get(ctx, o.Name); err == nil {
		sb = now
	}
	if !runReachedHooks(sb, run.Started) {
		a.warn(hooksWarningText(firstNonEmpty(sb.Hooks.UnreachableReason, "not one hook request of this run reached DefenseClaw")))
		return errNoHooks()
	}
	return nil
}

// runLogWriter is where a run's log goes: Claude Code's streamed events are
// rendered as lines, and on a terminal nothing in it drives the terminal
// (sandboxOutput).
func (a *App) runLogWriter(sb *sandboxapi.Sandbox) (io.Writer, func() error) {
	out, flush := sandboxOutput(a.IO.Out, a.IO.OutTTY)
	if sb.Harness != "claudecode" {
		return out, flush
	}
	r := &streamRenderer{w: out}
	return r, func() error { return errors.Join(r.Flush(), flush()) }
}

// keptLogs prints the run log DefenseClaw kept when it stopped the sandbox.
func (a *App) keptLogs(ctx context.Context, api API, sb *sandboxapi.Sandbox, lines int, out io.Writer, flush func() error) error {
	kept, err := api.RunLog(ctx, sb.Name, lines)
	if err != nil && !sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
		return apiError(err)
	}
	if kept == nil {
		return fmt.Errorf("%s is %s, and no log of a detached run was kept when it stopped; its log is inside it (`%s start %s`, then `%s logs %s`)",
			sb.Name, sb.Phase, CommandName, sb.Name, CommandName, sb.Name)
	}
	if _, err := io.WriteString(out, kept.Log); err != nil {
		return err
	}
	_ = flush()
	// Which run it is of: a stop that could not look at the run keeps the
	// log an earlier stop kept.
	what := "the log"
	if !kept.StartedAt.IsZero() {
		what = "the log of its detached run started " + a.clock(kept.StartedAt) + ","
	}
	a.note(fmt.Sprintf("%s is %s; this is %s kept when it stopped (%s)", sb.Name, sb.Phase, what, a.clock(kept.KeptAt)))
	a.keptRunState(kept)
	return nil
}

// keptRunState says how the run of a kept log ended.
func (a *App) keptRunState(kept *sandboxapi.RunLog) {
	switch kept.State {
	case sandboxapi.RunExited:
		a.note("the run exited with status " + kept.Exit)
	case sandboxapi.RunInterrupted:
		a.warn("the run did not finish: the sandbox stopped while it ran")
	case sandboxapi.RunRunning:
		a.note("the run was still going when the log was kept")
	}
}

// stoppedUnderFollower ends `sandbox logs -f` of a sandbox that stopped
// while it followed: what stopped, and how the run ended, from the log
// DefenseClaw kept.
func (a *App) stoppedUnderFollower(ctx context.Context, api API, sb *sandboxapi.Sandbox) {
	kept, err := api.RunLog(ctx, sb.Name, 1)
	if err != nil || kept == nil {
		a.warn(sb.Name + " is " + sb.Phase + ", so its run log ends here")
		return
	}
	a.note(fmt.Sprintf("%s is %s (%s); DefenseClaw kept the log of its detached run (`%s logs %s` shows it)",
		sb.Name, sb.Phase, a.clock(kept.KeptAt), CommandName, sb.Name))
	a.keptRunState(kept)
}
