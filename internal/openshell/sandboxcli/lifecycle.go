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
		row("Organization", st.Admin.Authority+" admin policy "+st.Admin.Detail)
	}
	row("Running", fmt.Sprintf("%d of %d", st.Running, st.Sandboxes))
	if st.PendingApprovals > 0 {
		row("Asks", fmt.Sprintf("%d waiting (`%s approvals`)", st.PendingApprovals, CommandName))
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
	yolo := "on"
	if !sb.Launch.Yolo {
		yolo = "off (harness prompts kept)"
	}
	row("Permissions", "skip-permissions "+yolo)
	row("Policy", fmt.Sprintf("profile %s, pack %s %s, network %s, approvals %s", sb.Profile, firstNonEmpty(sb.Pack, "open"), shortDigest(sb.PackDigest), networkLabel(sb), sb.Approvals))
	row("Hooks", fmt.Sprintf("%s tier, contract %s", firstNonEmpty(sb.TamperTier, "unknown"), firstNonEmpty(sb.HookContract, "-")))
	cov := fmt.Sprintf("%d requests, %d tool calls, %d blocked", sb.Hooks.HookRequests, sb.Hooks.ToolCalls, sb.Hooks.ToolBlocked)
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
	if sb.Hooks.LastBlocked != "" {
		row("Last blocked", truncate(sb.Hooks.LastBlocked, 100))
	}
	row("Egress", fmt.Sprintf("%d destinations (%d blocked), %s up, %s down", sb.Egress.Destinations, sb.Egress.Blocked,
		humanBytes(sb.Egress.BytesUp), humanBytes(sb.Egress.BytesDown)))
	for _, ep := range sb.Endpoints {
		row("Endpoint", ep.Host+" "+ep.Result)
	}
	if sb.Snapshot != nil {
		snap := sb.Snapshot.Kind + " snapshot " + sb.Snapshot.CreatedAt.Local().Format("2006-01-02 15:04")
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
func (a *App) Connect(ctx context.Context, o ConnectOptions) error {
	a.defaults()
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
	started, kept := false, sb.Phase == "ready"
	if sb.Phase != "ready" {
		a.note("starting " + sb.Name + "…")
		if sb, kept, err = a.startSandbox(ctx, api, sb, StartOptions{}); err != nil {
			return err
		}
		started = true
	}
	s := &session{app: a, api: api, cli: cli, spec: spec, sb: sb, rm: o.Rm, yes: o.Yes, started: started, headless: headless}
	if o.Refresh && sb.WorkdirMode == config.OpenShellWorkdirCopy {
		// The refresh replaces the copy, workdir included (a failed refresh
		// may have left none): probe outside it, and the refresh's baseline
		// checks the new workdir.
		if err := s.probe(ctx, ""); err != nil {
			return err
		}
		if err := a.refreshCopy(ctx, s); err != nil {
			return err
		}
	} else if err := s.probe(ctx, sb.Workdir); err != nil {
		return err
	}
	if o.Shell {
		inv, err := cli.Connect(sb.Name)
		if err != nil {
			return err
		}
		_, err = a.Terminal.Run(ctx, inv)
		return err
	}
	a.banner(sb, bannerInfo{llm: sandboxLLM(spec, sb), o: RunOptions{Args: o.Args, Prompt: o.Prompt}, keptSnapshot: kept})
	opts := harness.LaunchOptions{Mode: harness.Interactive, Yolo: sb.Launch.Yolo,
		CredentialProfile: sb.Launch.CredentialProfile, BedrockRegion: sb.Launch.BedrockRegion,
		Args: filterBypass(spec, sb.Launch.Yolo, o.Args, a)}
	if o.Prompt != "" {
		opts.Mode, opts.Prompt = harness.Headless, o.Prompt
	}
	code, err := s.attach(ctx, opts, headless)
	if err != nil {
		return err
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
		return workspaceFailure("refresh the copy", err, "")
	}
	files, b := int64(rec.Files), rec.Bytes
	_ = s.api.ReportWorkspace(ctx, s.sb.Name, sandboxapi.WorkspaceReport{Operation: sandboxapi.WorkspaceUpload, Result: "completed", FileCount: &files, ByteCount: &b})
	for _, w := range rec.Warnings {
		a.warn(w)
	}
	if len(rec.HeldBack) > 0 {
		a.note("held back: " + strings.Join(firstN(rec.HeldBack, 8), "  "))
	}
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
	command := append([]string{harness.SandboxEnvPath}, o.Command...)
	inv, err := cli.Exec(sb.Name, command, openshell.CLIExecOptions{TTY: tty, WorkDir: firstNonEmpty(o.Workdir, sb.Workdir)})
	if err != nil {
		return err
	}
	var code int
	if tty {
		code, err = a.Terminal.Run(ctx, inv)
	} else {
		code, err = a.Streamer.Stream(ctx, inv, a.IO.Out, a.IO.Err)
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
// on a terminal (said otherwise), and its log is kept for `sandbox logs`.
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
	if sb.Phase == "ready" {
		if gateway, err := a.gatewayName(ctx); err == nil {
			ok, err := a.beforeStop(ctx, a.cli(gateway), sb, o.Yes)
			if err != nil {
				return err
			}
			if !ok {
				a.note(sb.Name + " keeps running")
				return nil
			}
		}
	}
	sb, err = api.Stop(ctx, o.Name)
	if err != nil {
		return apiError(err)
	}
	a.ok(sb.Name + " is " + sb.Phase)
	return nil
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
	if sb, kept, err = a.startSandbox(ctx, api, sb, o); err != nil {
		return err
	}
	a.ok(sb.Name + " is " + sb.Phase + " → attach with `" + CommandName + " connect " + sb.Name + "`")
	if sb.WorkdirMode == config.OpenShellWorkdirMount && sb.Snapshot != nil {
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
		yes, err := a.confirm("Delete sandbox "+name+" (its providers, credentials and, unless --keep-snapshot, its undo snapshot)?", o.Yes)
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
		return a.keptLogs(sb, lines, out, flush)
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
		inv, err = cli.Exec(sb.Name, []string{"tail", "-n", strconv.Itoa(lines), RunDir + "/latest.log"},
			openshell.CLIExecOptions{WorkDir: sb.Workdir, Timeout: time.Minute})
	}
	if err != nil {
		return err
	}
	code, err := a.Streamer.Stream(ctx, inv, out, a.IO.Err)
	_ = flush()
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("%s has no detached run output (start one with `%s run <harness> --detach --prompt TEXT`)", sb.Name, CommandName)
	}
	run, err := a.detachedRun(ctx, cli, sb)
	if err != nil {
		return nil
	}
	switch run.State {
	case runRunning:
		a.note("the run is still going (follow it with -f)")
		if sb.Hooks.Unreachable {
			a.warn(hooksWarningText(sb.Hooks.UnreachableReason))
		}
		return nil
	case runInterrupted, runNone:
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
// rendered as lines.
func (a *App) runLogWriter(sb *sandboxapi.Sandbox) (io.Writer, func() error) {
	if sb.Harness != "claudecode" {
		return a.IO.Out, func() error { return nil }
	}
	r := &streamRenderer{w: a.IO.Out}
	return r, r.Flush
}

// keptLogs prints the run log DefenseClaw kept when it stopped the sandbox.
func (a *App) keptLogs(sb *sandboxapi.Sandbox, lines int, out io.Writer, flush func() error) error {
	meta, log, err := a.savedRunLog(sb)
	if err != nil {
		return err
	}
	if meta == nil {
		return fmt.Errorf("%s is %s, and no log of a detached run was kept when it stopped; its log is inside it (`%s start %s`, then `%s logs %s`)",
			sb.Name, sb.Phase, CommandName, sb.Name, CommandName, sb.Name)
	}
	if _, err := out.Write(lastLines(log, lines)); err != nil {
		return err
	}
	_ = flush()
	a.note(fmt.Sprintf("%s is %s; this is the log kept when it stopped (%s)", sb.Name, sb.Phase, a.clock(meta.SavedAt)))
	switch meta.State {
	case runExited:
		a.note("the run exited with status " + meta.Exit)
	case runInterrupted:
		a.warn("the run did not finish: the sandbox stopped while it ran")
	case runRunning:
		a.note("the run was still going when the log was kept")
	}
	return nil
}
