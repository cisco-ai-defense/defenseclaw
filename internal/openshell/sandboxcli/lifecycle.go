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
	if len(list) == 0 {
		a.note("no sandboxes; start one with `" + CommandName + " run claude` in a project folder")
		return nil
	}
	rows := make([][]string, 0, len(list))
	for _, sb := range list {
		rows = append(rows, []string{
			sb.Name, firstNonEmpty(sb.HarnessName, sb.Harness), phaseText(sb), sb.WorkdirMode, profileText(sb),
			humanDuration(time.Duration(sb.UptimeSeconds) * time.Second), hooksText(sb), a.tildePath(sb.Project),
		})
	}
	a.table([]string{"NAME", "HARNESS", "PHASE", "MODE", "PROFILE", "UPTIME", "HOOKS", "PROJECT"}, rows)
	return nil
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

func profileText(sb sandboxapi.Sandbox) string {
	if sb.Pack != "" && sb.Pack != sb.Profile {
		return sb.Profile + " (" + sb.Pack + ")"
	}
	return sb.Profile
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
	case sb.Hooks.LastHookAt.IsZero():
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
			return writeJSON(a.IO.Out, st)
		}
		a.printStatus(st)
		return nil
	}
	sb, err := api.Get(ctx, name)
	if err != nil {
		return apiError(err)
	}
	if format == OutputJSON {
		return writeJSON(a.IO.Out, sb)
	}
	a.printSandbox(sb)
	if sb.Phase == "stopped" {
		if why := a.startRefusal(ctx, api, sb); why != "" {
			a.warn(sb.Name + " cannot start under the current policy: " + why + "; delete it (`" + CommandName + " delete " + sb.Name +
				"`) and run again")
		}
	}
	return nil
}

func (a *App) printStatus(st *sandboxapi.Status) {
	row := func(k, v string) { a.line(fmt.Sprintf("%-16s%s", k, v)) }
	state := "off (run `" + CommandName + " setup`)"
	if st.Enabled {
		state = "on"
	}
	row("Sandboxes", state)
	if st.Enabled {
		if st.Available {
			row("OpenShell", "connected")
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
		row("Policy", "pack "+firstNonEmpty(st.Pack, "open")+", profile "+firstNonEmpty(st.Profile, "open"))
	}
	if st.Admin.Configured {
		row("Organization", adminText(st.Admin))
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
	row("Phase", phaseText(*sb))
	if sb.UptimeSeconds > 0 {
		row("Uptime", humanDuration(time.Duration(sb.UptimeSeconds)*time.Second))
	}
	row("Project", a.tildePath(sb.Project)+" → "+sb.Workdir+" ("+sb.WorkdirMode+")")
	yolo := "skip-permissions on"
	switch text, own := ownApprovals[sb.Harness]; {
	case own:
		yolo = text
	case !sb.Launch.Yolo:
		yolo = "skip-permissions off (harness prompts kept)"
	}
	row("Permissions", yolo)
	row("Policy", fmt.Sprintf("profile %s, pack %s %s, network %s, approvals %s", sb.Profile, firstNonEmpty(sb.Pack, "open"), shortDigest(sb.PackDigest), networkLabel(sb), sb.Approvals))
	// What it was created with beyond the policy, which a resume keeps.
	for _, c := range grantTexts(sb.Credentials) {
		row("Secret", c)
	}
	if len(sb.HostPorts) > 0 {
		var hosts []string
		for _, p := range sb.HostPorts {
			hosts = append(hosts, fmt.Sprintf("localhost:%d", p))
		}
		row("Host ports", strings.Join(hosts, " ")+" (each an ask at the sandbox's first connection)")
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
		last := "DefenseClaw answered " + sb.Hooks.LastHookFailure
		if !sb.Hooks.LastHookFailureAt.IsZero() {
			last += " at " + sb.Hooks.LastHookFailureAt.Local().Format("15:04:05")
		}
		row("Hook error", last+" (the hook failed closed)")
	}
	row("Egress", fmt.Sprintf("%s contacted, %d blocked, %s up, %s down", plural(int64(sb.Egress.Destinations), "destination", "destinations"), sb.Egress.Blocked,
		humanBytes(sb.Egress.BytesUp), humanBytes(sb.Egress.BytesDown))+egressAIText(sb))
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
		a.warn(violationMessage(&v, v.Message, v.Detail, v.Admin))
	}
	for _, w := range sb.Warnings {
		a.warn(w)
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
		if sb, kept, err = a.startSandbox(ctx, api, sb, StartOptions{}, true); err != nil {
			return err
		}
		started = true
	}
	s := &session{app: a, api: api, cli: cli, spec: spec, sb: sb, rm: o.Rm, yes: o.Yes, started: started, headless: headless, shell: o.Shell}
	// fail stops the sandbox this command started for a session that never
	// began: the probe, the refresh or the harness's start failed.
	fail := func(err error) error {
		if started {
			a.warn("stopping " + sb.Name + " after the failure")
			if _, serr := api.Stop(context.WithoutCancel(ctx), sb.Name); serr != nil {
				a.warn("could not stop " + sb.Name + ": " + apiError(serr).Error())
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
	if ex, err := api.Explain(ctx, sandboxapi.ExplainRequest{Sandbox: sb.Name}); err == nil {
		policy = ex.Settings
	}
	a.banner(sb, bannerInfo{llm: a.sandboxLLM(spec, sb, run), o: shown, keptSnapshot: kept, policy: policy})
	var code int
	if o.Shell {
		// A shell in the project, reviewed at its end like a harness
		// session: what it changed is kept or undone the same way.
		if code, err = s.attachShell(ctx); err != nil {
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

// refreshCopy re-stages a copy-mode sandbox's project and uploads it.
func (a *App) refreshCopy(ctx context.Context, s *session) error {
	// The sandbox's own policy decides what is held back, as at its run.
	stage, err := a.copyStageOptions(packs.Flags{Pack: s.sb.Pack, Harness: s.sb.Harness, Project: s.sb.Project, Profile: s.sb.Profile}, s.sb.Name)
	if err != nil {
		return err
	}
	t := a.transport(s.cli)
	a.note("refreshing the project copy in " + s.sb.Name + "…")
	rec, err := a.Workspace.Refresh(ctx, workspace.RefreshOptions{Stage: stage, Exec: t, Upload: t})
	if err != nil {
		hint := a.diskFullHint(err)
		if errors.Is(err, workspace.ErrUploadNotArrived) {
			hint = strayUploadHint
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
	// stopped is no longer known.
	a.forgetStoppedCopy(sb.Name)
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
		return &ExitError{Code: code}
	}
	return nil
}

// StopOptions are the `sandbox stop` flags.
type StopOptions struct {
	Name string
	// Yes stops a sandbox whose detached run is still going without
	// asking.
	Yes bool
}

// Stop is `sandbox stop`. A detached run the stop would end is confirmed
// on a terminal (said otherwise); the daemon's stop marks it interrupted
// and keeps its log for `sandbox logs`.
// The copy of a copy-mode sandbox nothing runs in any more is looked at
// first: what it holds as it stops is remembered (markStoppedCopy), so
// `delete` need not warn about work that came back already, and the next
// pull need not start it.
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
	if sb.Phase == "ready" {
		if gateway, err := a.gatewayName(ctx); err == nil {
			cli := a.cli(gateway)
			ok, idle, err := a.beforeStop(ctx, cli, sb, o.Yes)
			if err != nil {
				return err
			}
			if !ok {
				a.note(sb.Name + " keeps running")
				return nil
			}
			// A detached run or a session still going can change the copy
			// between the look and the stop.
			if sb.WorkdirMode == config.OpenShellWorkdirCopy && idle && a.attachedSessions(sb.Name) == 0 {
				copyAt = a.copyAtStop(ctx, cli, sb)
			}
		}
	}
	stopped, err := api.Stop(ctx, o.Name)
	if err != nil {
		return apiError(err)
	}
	// A hook request since the look is something that ran in it after all.
	if copyAt != nil && !stopped.Hooks.LastHookAt.After(sb.Hooks.LastHookAt) {
		a.markStoppedCopy(sb, copyAt.Work == workspace.CopyWorkNone, copyAt.Pulled)
	}
	a.ok(stopped.Name + " is " + stopped.Phase)
	return nil
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

// StartOptions are the `sandbox start` flags.
type StartOptions struct {
	// NoSnapshot keeps the previous snapshot; NewSnapshot replaces it even
	// when the folder still holds an earlier session's changes.
	NoSnapshot  bool
	NewSnapshot bool
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
		yes, err := a.confirm(question, o.Yes)
		if err != nil {
			return err
		}
		if !yes {
			continue
		}
		res, err := api.Delete(ctx, name, sandboxapi.DeleteRequest{KeepSnapshot: o.KeepSnapshot})
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
		return "may hold work that was never pulled back" + why("it could not be checked: "+truncate(err.Error(), 120)) + "; " + pull + " brings it back"
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
	kept, legacy, err := a.keptRunLog(ctx, api, sb, lines)
	if err != nil {
		return err
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
	switch {
	case legacy:
		what = "the log an earlier DefenseClaw CLI"
	case !kept.StartedAt.IsZero():
		what = "the log of its detached run started " + a.clock(kept.StartedAt) + ","
	}
	a.note(fmt.Sprintf("%s is %s; this is %s kept when it stopped (%s)", sb.Name, sb.Phase, what, a.clock(kept.KeptAt)))
	switch kept.State {
	case sandboxapi.RunExited:
		a.note("the run exited with status " + kept.Exit)
	case sandboxapi.RunInterrupted:
		a.warn("the run did not finish: the sandbox stopped while it ran")
	case sandboxapi.RunRunning:
		a.note("the run was still going when the log was kept")
	}
	return nil
}

// keptRunLog is the log of sb's latest detached run the daemon kept when it
// stopped the sandbox, its last lines lines; failing that, one an earlier
// CLI kept (legacyRunLog, legacy true) while it is still the log of the
// latest stop. nil when neither kept one.
func (a *App) keptRunLog(ctx context.Context, api API, sb *sandboxapi.Sandbox, lines int) (*sandboxapi.RunLog, bool, error) {
	kept, err := api.RunLog(ctx, sb.Name, lines)
	if err == nil {
		return kept, false, nil
	}
	if !sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
		return nil, false, apiError(err)
	}
	if sb.Session > 0 {
		// The daemon has seen the sandbox start since it began counting
		// sessions, which is since it keeps run logs: every stop after that
		// was its own, so a log an earlier CLI kept is older than the
		// latest stop, which kept none.
		return nil, false, nil
	}
	meta, log, err := a.legacyRunLog(sb)
	if err != nil || meta == nil {
		return nil, false, err
	}
	return &sandboxapi.RunLog{Name: sb.Name, State: meta.State, Exit: meta.Exit, KeptAt: meta.SavedAt,
		Log: string(harness.LastLines(log, lines))}, true, nil
}
