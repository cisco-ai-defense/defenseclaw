// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/procboot"
)

// codeAgentSessionsRestart names agent sessions that started before the
// deployment was activated. An agent reads its hook configuration when it
// starts, so a session left open through an uninstall and a reinstall (or
// one started before the first install) runs without DefenseClaw hooks
// until it is restarted, while status and verify showed a healthy
// deployment (GAP-0411).
const codeAgentSessionsRestart = "agent_sessions_restart_required"

// agentCLINames are the command names of the agent CLIs DefenseClaw
// registers hooks for.
var agentCLINames = map[string]bool{
	"claude": true, "codex": true, "cursor-agent": true, "copilot": true, "opencode": true, "amp": true,
	"devin": true, "hermes": true, "agy": true, "kiro-cli": true,
}

// Codex is named like every other agent: a Codex session (TUI only, or
// served by the app-server daemon) keeps the managed requirements it read
// when it started and loads no DefenseClaw hook later (Codex 0.159.3, live
// on RHEL 2026-10-30; private #12). An older allowlist skipped Codex
// sessions on the premise that Codex reads the requirements per turn. A
// Codex background server started before the install is named with how to
// restart it: a new Codex session refuses it ("Cannot use the shared
// background server") until it is restarted (GAP-0988, GAP-0983).

// codexBackgroundServer reports the Codex app-server daemon process (not
// its "app-server daemon" supervisor or an IDE stdio server).
func codexBackgroundServer(argv []string) bool {
	if len(argv) < 2 || filepath.Base(argv[0]) != "codex" || argv[1] != "app-server" {
		return false
	}
	if len(argv) > 2 && !strings.HasPrefix(argv[2], "-") {
		return false
	}
	if strings.Contains(argv[0], "/app-server-daemon/") {
		return true
	}
	for _, argument := range argv[2:] {
		if argument == "--listen" || strings.HasPrefix(argument, "--listen=") {
			return true
		}
	}
	return false
}

// scriptHosts run an agent CLI given as their first argument.
var scriptHosts = map[string]bool{"node": true, "nodejs": true, "bun": true, "deno": true, "python": true, "python3": true}

// agentModuleNames are agents launched through a script host's -c or -m argument.
var agentModuleNames = map[string]string{"hermes_cli": "hermes"}

// packageRunnerTitles are the package runners whose process title names the
// runner first.
var packageRunnerTitles = map[string]bool{"npm": true, "npx": true, "pnpm": true, "pnpx": true, "yarn": true, "bunx": true}

func isScriptHost(name string) bool {
	return scriptHosts[name] || strings.HasPrefix(name, "python3.")
}

// agentCLIOf names the agent CLI a command line runs, or "".
func agentCLIOf(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	if strings.Contains(argv[0], "/.local/share/claude/versions/") {
		return "claude"
	}
	// Node can replace its argv area with a short process title padded by
	// spaces. Claude Code does this during an interactive npm session.
	// npm exec and npx replace their argv with one title, "npm exec <package>
	// <arguments>". That process is the package runner, not the agent: an MCP
	// server it runs for Claude Code ends in a project path that may be named
	// claude (GAP-1273). An agent the runner starts is its own process.
	if title := strings.Fields(argv[0]); len(argv) == 1 && len(title) > 1 && packageRunnerTitles[filepath.Base(title[0])] {
		return ""
	}
	name := strings.TrimSpace(filepath.Base(argv[0]))
	if agentCLINames[name] {
		return name
	}
	if !isScriptHost(name) {
		return ""
	}
	for index, argument := range argv[1:] {
		switch {
		case argument == "-c" || argument == "-m":
			if index+2 < len(argv) {
				for module, agent := range agentModuleNames {
					if strings.Contains(argv[index+2], module) {
						return agent
					}
				}
			}
			return ""
		case strings.HasPrefix(argument, "-"):
			continue
		}
		script := strings.TrimSuffix(filepath.Base(argument), filepath.Ext(argument))
		if filepath.Base(argument) == "cli.js" && strings.Contains(filepath.ToSlash(argument), "/@anthropic-ai/claude-code/") {
			return "claude"
		}
		if agentCLINames[script] {
			return script
		}
		return ""
	}
	return ""
}

// agentSession is a running agent CLI process.
type agentSession struct {
	PID       int
	PPID      int // the parent process; 0 when unknown
	UID       int
	Agent     string
	Started   time.Time
	Args      []string
	ArgsKnown bool
	// Executable is the kernel's executable path, independent of a process
	// title that overwrote argv (notably interactive npm Claude Code).
	Executable string
	Env        map[string]string
	EnvKnown   bool
	// Unknown marks an unreadable agent-shaped command on macOS.
	Unknown bool
	// CodexServer marks the Codex background server.
	CodexServer bool
}

// agentSessionsStartedBefore lists the agent CLI processes of accounts
// other than root and the service account that started before since.
func (e *Env) agentSessionsStartedBefore(ctx context.Context, since time.Time, serviceUID int) []agentSession {
	var all []agentSession
	switch e.GOOS {
	case "linux":
		all = e.linuxAgentSessions()
	case "darwin":
		all = e.darwinAgentSessions(ctx)
	}
	all = oneProcessPerSession(all)
	var out []agentSession
	for _, session := range all {
		if session.UID == 0 || session.UID == serviceUID || !session.Started.Before(since) {
			continue
		}
		out = append(out, session)
	}
	return out
}

// oneProcessPerSession keeps the topmost process of each agent session: an
// agent with a launcher (npm Codex: a node script and the native codex it
// starts) is one session, so a warning names its launcher pid once
// (GAP-2439). The Codex background server is restarted its own way, and an
// unreadable process is not known to be an agent, so both stay listed as
// they are.
func oneProcessPerSession(sessions []agentSession) []agentSession {
	processes := make([]enterprisestatus.SessionProcess, 0, len(sessions))
	for _, session := range sessions {
		if session.Unknown || session.CodexServer {
			continue
		}
		processes = append(processes, enterprisestatus.SessionProcess{PID: session.PID, PPID: session.PPID,
			User: strconv.Itoa(session.UID), Agent: session.Agent})
	}
	leaders := enterprisestatus.SessionLeaders(processes)
	out := make([]agentSession, 0, len(sessions))
	for _, session := range sessions {
		if leader, ok := leaders[session.PID]; ok && !session.Unknown && !session.CodexServer && leader != session.PID {
			continue
		}
		out = append(out, session)
	}
	return out
}

// bootFromClock is procboot.FromClock; tests replace it.
var bootFromClock = procboot.FromClock

// linuxBootSeconds is the boot instant (Unix seconds) that the start times in
// /proc/<pid>/stat count from: the btime line of /proc/stat. A /proc mounted
// with subset=pid has no /proc/stat but still serves the process table, so
// there the instant comes from the clocks, the way the kernel computes btime
// (GAP-2101). Any other unreadable /proc/stat stays an error, and the scan is
// reported as unknown.
func (e *Env) linuxBootSeconds() (int64, error) {
	stat, err := readBounded(e.P("/proc/stat"), 1<<20)
	if err != nil {
		if procboot.SubsetPID(e.P("/proc")) {
			if boot, ok := bootFromClock(); ok {
				return boot, nil
			}
		}
		return 0, err
	}
	var boot int64
	for _, line := range strings.Split(string(stat), "\n") {
		if value, ok := strings.CutPrefix(line, "btime "); ok {
			boot, _ = strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		}
	}
	if boot == 0 {
		return 0, fmt.Errorf("missing Linux boot time")
	}
	return boot, nil
}

// linuxAgentSessions reads the agent processes from /proc: the start time is
// field 22 of /proc/<pid>/stat, in clock ticks (USER_HZ, 100) after btime.
func (e *Env) linuxAgentSessions() []agentSession {
	sessions, _ := e.linuxAgentSessionsWithError()
	return sessions
}

func (e *Env) linuxAgentSessionsWithError() ([]agentSession, error) {
	boot, err := e.linuxBootSeconds()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(e.P("/proc"))
	if err != nil {
		return nil, err
	}
	var out []agentSession
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		dir := filepath.Join(e.P("/proc"), entry.Name())
		cmdline, argvErr := readBounded(filepath.Join(dir, "cmdline"), 64<<10)
		argvKnown := argvErr == nil && len(cmdline) > 0
		var argv []string
		if argvKnown {
			argv = strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
		} else if comm, err := readBounded(filepath.Join(dir, "comm"), 128); err == nil {
			argv = []string{strings.TrimSpace(string(comm))}
		}
		agent := agentCLIOf(argv)
		if agent == "" {
			continue
		}
		data, err := readBounded(filepath.Join(dir, "stat"), 64<<10)
		if err != nil {
			continue
		}
		end := bytes.LastIndex(data, []byte(")"))
		if end < 0 {
			continue
		}
		fields := strings.Fields(string(data[end+1:]))
		if len(fields) < 20 {
			continue
		}
		ticks, err := strconv.ParseInt(fields[19], 10, 64)
		if err != nil {
			continue
		}
		info, err := os.Lstat(dir)
		if err != nil {
			continue
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		started := time.Unix(boot, 0).Add(time.Duration(ticks) * time.Second / 100)
		executable, _ := os.Readlink(filepath.Join(dir, "exe"))
		ppid, _ := strconv.Atoi(fields[1])
		session := agentSession{PID: pid, PPID: ppid, UID: int(owner.Uid), Agent: agent, Started: started, Args: argv, Executable: executable,
			ArgsKnown: argvKnown, CodexServer: codexBackgroundServer(argv)}
		if pluginLaunchConnector(agent) {
			raw, err := readBounded(filepath.Join(dir, "environ"), 64<<10)
			if err == nil {
				session.Env, session.EnvKnown = pluginLaunchEnvironment(raw), true
			}
		}
		out = append(out, session)
	}
	return out, nil
}

// darwinAgentSessions asks ps for every process with its elapsed time.
func (e *Env) darwinAgentSessions(ctx context.Context) []agentSession {
	sessions, _ := e.darwinAgentSessionsWithError(ctx)
	return sessions
}

func (e *Env) darwinAgentSessionsWithError(ctx context.Context) ([]agentSession, error) {
	result, err := e.Runner.Run(ctx, "ps", "-axww", "-o", "pid=,uid=,etime=,args=")
	if err != nil && len(result.Stdout) == 0 {
		return nil, err
	}
	now := e.Now()
	var out []agentSession
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		pid, pidErr := strconv.Atoi(fields[0])
		uid, uidErr := strconv.Atoi(fields[1])
		elapsed, ok := parseElapsed(fields[2])
		if pidErr != nil || uidErr != nil || !ok {
			continue
		}
		argv, argvErr := darwinProcessArgv(pid)
		if argvErr != nil {
			argv = psArgv(fields[3:])
		}
		if agent := agentCLIOf(argv); agent != "" {
			execPath := e.ProcessExecPath
			if execPath == nil {
				execPath = processExecPath
			}
			imagePath := e.ProcessImagePath
			if imagePath == nil {
				imagePath = processImagePath
			}
			executable, _ := execPath(pid)
			executable = absoluteExecPath(executable, func() (string, error) { return imagePath(pid) })
			ppid, _ := darwinProcessParent(pid)
			session := agentSession{PID: pid, PPID: ppid, UID: uid, Agent: agent, Started: now.Add(-elapsed), Args: argv, Executable: executable,
				ArgsKnown: argvErr == nil, CodexServer: codexBackgroundServer(argv)}
			if pluginLaunchConnector(agent) {
				if raw, err := darwinProcessEnv(pid); err == nil {
					session.Env, session.EnvKnown = raw, true
				}
			}
			out = append(out, session)
		} else if argvErr != nil && psUnknownAgent(fields[3:]) {
			name := strings.TrimSuffix(strings.TrimPrefix(fields[3], "("), ")")
			out = append(out, agentSession{PID: pid, UID: uid, Agent: name, Started: now.Add(-elapsed), Unknown: true})
		}
	}
	return out, err
}

// psArgv keeps a script host's command or module argument together when ps
// prints the arguments as text and kern.procargs2 is unavailable.
func psArgv(fields []string) []string {
	if len(fields) == 0 || !isScriptHost(filepath.Base(fields[0])) {
		return fields
	}
	for i := 1; i < len(fields); i++ {
		if fields[i] == "-c" || fields[i] == "-m" {
			return append(append([]string{}, fields[:i+1]...), strings.Join(fields[i+1:], " "))
		}
	}
	return fields
}

// psUnknownAgent accepts only the parenthesized command name ps uses when
// it cannot show arguments, and only for a possible agent or script host.
func psUnknownAgent(fields []string) bool {
	if len(fields) != 1 || !strings.HasPrefix(fields[0], "(") || !strings.HasSuffix(fields[0], ")") {
		return false
	}
	name := strings.TrimSuffix(strings.TrimPrefix(fields[0], "("), ")")
	return isScriptHost(name) || agentCLINames[name]
}

// parseElapsed reads the ps etime format, [[dd-]hh:]mm:ss.
func parseElapsed(text string) (time.Duration, bool) {
	days := 0
	if before, after, found := strings.Cut(text, "-"); found {
		value, err := strconv.Atoi(before)
		if err != nil {
			return 0, false
		}
		days, text = value, after
	}
	parts := strings.Split(text, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return 0, false
	}
	total := 0
	for _, part := range parts {
		value, err := strconv.Atoi(part)
		if err != nil {
			return 0, false
		}
		total = total*60 + value
	}
	return time.Duration(days)*24*time.Hour + time.Duration(total)*time.Second, true
}

// connectorActivations dates the machine-policy connectors this run places
// that the previous record did not have: a config change that enables one
// gives running sessions of that agent no hooks. A first or staged install
// has none (the deployment activation covers it); a connector still placed
// keeps its date; a run that does not start the services dates nothing new.
func connectorActivations(previous *Deployment, placed []string, started bool, now string) map[string]string {
	if previous == nil || previous.NoStart {
		return nil
	}
	before := map[string]bool{}
	for _, name := range previous.MachinePolicyConnectors {
		before[name] = true
	}
	out := map[string]string{}
	for _, name := range placed {
		switch {
		case !before[name] && started:
			out[name] = now
		case before[name] && previous.ConnectorActivatedAt[name] != "":
			out[name] = previous.ConnectorActivatedAt[name]
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// describeAgentSessionsBeforeConnector warns about the sessions of each
// connector a config change enabled after the activation that started
// before that change (GAP-0018).
func (l *lifecycle) describeAgentSessionsBeforeConnector(ctx context.Context, record *Deployment, activated time.Time) {
	names := make([]string, 0, len(record.ConnectorActivatedAt))
	for name := range record.ConnectorActivatedAt {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		raw := record.ConnectorActivatedAt[name]
		at, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil || !at.After(activated) {
			continue
		}
		var stale []agentSession
		for _, session := range l.env.agentSessionsStartedBefore(ctx, at, record.ServiceUID) {
			if session.Unknown || agentConnectors[session.Agent] != name || session.Started.Before(activated) {
				continue
			}
			stale = append(stale, session)
		}
		l.warnAgentSessions(stale, func(sessions string) string {
			return fmt.Sprintf("runs %s, started before its connector was enabled at %s; an agent reads its hooks when it starts, so ask that user to restart these sessions", sessions, raw)
		})
	}
}

// describeAgentSessionsBeforeActivation warns, per account, about agent
// sessions that started before this deployment was activated, about
// sessions that started before the guardian put back hooks a user changed or
// removed, and about Claude Code sessions that were open while the
// DefenseClaw drop-in was changed or removed before DefenseClaw put it back.
func (l *lifecycle) describeAgentSessionsBeforeActivation(ctx context.Context, record *Deployment) {
	if record == nil || record.NoStart {
		return
	}
	activationTime := record.ActivatedAt
	if activationTime == "" {
		activationTime = record.InstalledAt
	}
	activated, err := time.Parse(time.RFC3339Nano, activationTime)
	if err != nil {
		return
	}
	var known, unknown []agentSession
	for _, session := range l.env.agentSessionsStartedBefore(ctx, activated, record.ServiceUID) {
		if session.Unknown {
			unknown = append(unknown, session)
		} else {
			known = append(known, session)
		}
	}
	l.warnAgentSessions(known, func(sessions string) string {
		return fmt.Sprintf("runs %s, started before DefenseClaw was activated on this computer at %s; an agent reads its hooks when it starts, so these sessions run without DefenseClaw until they are restarted: ask that user to restart them", sessions, activationTime)
	})
	l.describeAgentSessionsBeforeConnector(ctx, record, activated)
	if l.env.GOOS == "darwin" {
		// An unreadable record is reported by
		// describeAgentSessionsBeforeGuardianRestore below.
		restores, _ := l.env.guardianRestores()
		latestByUID := map[int]time.Time{}
		latest := time.Time{}
		for key, at := range restores {
			if at.After(latestByUID[key.uid]) {
				latestByUID[key.uid] = at
			}
			if at.After(latest) {
				latest = at
			}
		}
		if latest.After(activated) {
			for _, session := range l.env.agentSessionsStartedBefore(ctx, latest, record.ServiceUID) {
				if session.Unknown && !session.Started.Before(activated) && session.Started.Before(latestByUID[session.UID]) {
					unknown = append(unknown, session)
				}
			}
		}
	}
	l.warnUnknownAgentSessions(unknown)
	l.describeAgentSessionsBeforeGuardianRestore(ctx, record, activated)
	restored := l.env.claudeDropInRestoredAt()
	if !restored.After(activated) {
		return
	}
	var held []agentSession
	for _, session := range l.env.agentSessionsStartedBefore(ctx, restored, record.ServiceUID) {
		if session.Agent == "claude" && !session.Started.Before(activated) {
			held = append(held, session)
		}
	}
	l.warnAgentSessions(held, func(sessions string) string {
		return fmt.Sprintf("runs %s, open while the DefenseClaw Claude Code drop-in was changed or removed; DefenseClaw put it back at %s, but Claude Code keeps the hooks a session loaded, so these sessions can still run a broken hook command without DefenseClaw until they are restarted: ask that user to restart them", sessions, restored.UTC().Format(time.RFC3339))
	})
}

func (l *lifecycle) warnUnknownAgentSessions(sessions []agentSession) {
	if len(sessions) == 0 {
		return
	}
	l.warnAgentSessions(sessions, func(labels string) string {
		return fmt.Sprintf("restart status unknown: the arguments of %s could not be read, so DefenseClaw cannot tell whether these are agents that started before hooks were installed, enabled or put back and run without DefenseClaw; ask that these sessions be restarted", labels)
	})
	l.result.MarkSecurityIncomplete(codeAgentSessionsRestart)
}

// warnAgentSessions adds one agent_sessions_restart_required warning per
// account; reason words the sessions listed. A Codex background server adds
// how to restart it.
func (l *lifecycle) warnAgentSessions(sessions []agentSession, reason func(sessions string) string) {
	byUID := map[int][]string{}
	server := map[int]bool{}
	for _, session := range sessions {
		label := fmt.Sprintf("%s (pid %d)", session.Agent, session.PID)
		if session.Unknown {
			label = fmt.Sprintf("unknown agent (pid %d)", session.PID)
		}
		if session.CodexServer {
			label = fmt.Sprintf("the Codex background server (pid %d)", session.PID)
			server[session.UID] = true
		}
		byUID[session.UID] = append(byUID[session.UID], label)
		connector := ""
		if !session.Unknown {
			connector = agentConnectors[session.Agent]
		}
		l.result.NotePendingSession(connector, session.PID)
	}
	uids := make([]int, 0, len(byUID))
	for uid := range byUID {
		uids = append(uids, uid)
	}
	sort.Ints(uids)
	for _, uid := range uids {
		who := "uid " + strconv.Itoa(uid)
		if account, err := user.LookupId(strconv.Itoa(uid)); err == nil {
			who = account.Username
		}
		message := "user " + who + " " + reason(strings.Join(byUID[uid], ", "))
		if server[uid] {
			message += ". The Codex background server keeps the requirements it read when it started, and a new Codex session refuses it (Cannot use the shared background server) until it is restarted: have that user run `codex app-server daemon restart` (or start Codex with `codex --no-daemon`)"
		}
		l.result.AddWarning(codeAgentSessionsRestart, message)
	}
}

// claudeDropInRestoredAt is when DefenseClaw last put back its Claude Code
// drop-in after another writer changed or removed it, or the zero time.
func (e *Env) claudeDropInRestoredAt() time.Time {
	manager, ok := e.MachinePolicy.(*policyManager)
	if !ok {
		return time.Time{}
	}
	opts, err := manager.options(nil)
	if err != nil {
		return time.Time{}
	}
	return enterprisepolicy.ClaudeDropInRestoredAt(opts)
}

// hostProcess is a running process of this computer.
type hostProcess struct {
	PID     int
	UID     int
	Started time.Time
	Argv    []string
	// ArgvUnread (macOS) marks a process whose kern.procargs2 could not be
	// read: Argv is then psArgv of PSArgs, the argument text ps printed.
	ArgvUnread bool
	PSArgs     []string
}

// hostProcesses lists the running processes with their owner, start time
// and arguments (agent sessions, and the replaced release's hook calls a
// lifecycle run waits for).
func (e *Env) hostProcesses(ctx context.Context) []hostProcess {
	switch e.GOOS {
	case "linux":
		return e.linuxProcesses()
	case "darwin":
		return e.darwinProcesses(ctx)
	}
	return nil
}

// linuxProcesses reads the processes from /proc: the start time is field
// 22 of /proc/<pid>/stat, in clock ticks (USER_HZ, 100) after btime.
func (e *Env) linuxProcesses() []hostProcess {
	boot, err := e.linuxBootSeconds()
	if err != nil {
		return nil
	}
	entries, _ := os.ReadDir(e.P("/proc"))
	var out []hostProcess
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		dir := filepath.Join(e.P("/proc"), entry.Name())
		cmdline, err := readBounded(filepath.Join(dir, "cmdline"), 64<<10)
		if err != nil || len(cmdline) == 0 {
			continue
		}
		argv := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
		data, err := readBounded(filepath.Join(dir, "stat"), 64<<10)
		if err != nil {
			continue
		}
		end := bytes.LastIndex(data, []byte(")"))
		if end < 0 {
			continue
		}
		fields := strings.Fields(string(data[end+1:]))
		if len(fields) < 20 {
			continue
		}
		ticks, err := strconv.ParseInt(fields[19], 10, 64)
		if err != nil {
			continue
		}
		info, err := os.Lstat(dir)
		if err != nil {
			continue
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		started := time.Unix(boot, 0).Add(time.Duration(ticks) * time.Second / 100)
		out = append(out, hostProcess{PID: pid, UID: int(owner.Uid), Started: started, Argv: argv})
	}
	return out
}

// darwinProcesses asks ps for every process with its elapsed time.
func (e *Env) darwinProcesses(ctx context.Context) []hostProcess {
	result, err := e.Runner.Run(ctx, "ps", "-axww", "-o", "pid=,uid=,etime=,args=")
	if err != nil && len(result.Stdout) == 0 {
		return nil
	}
	now := e.Now()
	var out []hostProcess
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		pid, pidErr := strconv.Atoi(fields[0])
		uid, uidErr := strconv.Atoi(fields[1])
		elapsed, ok := parseElapsed(fields[2])
		if pidErr != nil || uidErr != nil || !ok {
			continue
		}
		argv, argvErr := darwinProcessArgv(pid)
		if argvErr != nil {
			argv = psArgv(fields[3:])
		}
		out = append(out, hostProcess{PID: pid, UID: uid, Started: now.Add(-elapsed), Argv: argv, ArgvUnread: argvErr != nil, PSArgs: fields[3:]})
	}
	return out
}
