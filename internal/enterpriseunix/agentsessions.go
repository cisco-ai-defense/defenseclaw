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
	"devin": true, "hermes": true, "openhands": true, "omnigent": true, "agy": true, "kiro-cli": true,
}

// agentsReadingHooksLive pick up DefenseClaw's hooks without a restart: a
// Codex session open before the install was inspected at once (its managed
// requirements are read per turn), so naming it, or the Codex app-server
// daemon an old auto-update left behind, asked users to restart sessions
// that were already inspected (GAP-0936).
var agentsReadingHooksLive = map[string]bool{"codex": true}

// scriptHosts run an agent CLI given as their first argument.
var scriptHosts = map[string]bool{"node": true, "nodejs": true, "bun": true, "deno": true, "python": true, "python3": true}

// agentCLIOf names the agent CLI a command line runs, or "".
func agentCLIOf(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	if strings.Contains(argv[0], "/.local/share/claude/versions/") {
		return "claude"
	}
	name := filepath.Base(argv[0])
	if agentCLINames[name] {
		return name
	}
	if !scriptHosts[name] && !strings.HasPrefix(name, "python3.") {
		return ""
	}
	for index, argument := range argv[1:] {
		switch {
		case argument == "-c" || argument == "-m":
			// Hermes' launcher runs its own Python with `-I -c` and a
			// bootstrap that imports hermes_cli, so no argument names the
			// agent and it was never listed (GAP-0936).
			if index+2 < len(argv) && strings.Contains(argv[index+2], "hermes_cli") {
				return "hermes"
			}
			return ""
		case strings.HasPrefix(argument, "-"):
			continue
		}
		script := strings.TrimSuffix(filepath.Base(argument), filepath.Ext(argument))
		if agentCLINames[script] {
			return script
		}
		return ""
	}
	return ""
}

// agentSession is a running agent CLI process.
type agentSession struct {
	PID     int
	UID     int
	Agent   string
	Started time.Time
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
	var out []agentSession
	for _, session := range all {
		if session.UID == 0 || session.UID == serviceUID || !session.Started.Before(since) || agentsReadingHooksLive[session.Agent] {
			continue
		}
		out = append(out, session)
	}
	return out
}

// linuxAgentSessions reads the agent processes from /proc: the start time is
// field 22 of /proc/<pid>/stat, in clock ticks (USER_HZ, 100) after btime.
func (e *Env) linuxAgentSessions() []agentSession {
	stat, err := readBounded(e.P("/proc/stat"), 1<<20)
	if err != nil {
		return nil
	}
	var boot int64
	for _, line := range strings.Split(string(stat), "\n") {
		if value, ok := strings.CutPrefix(line, "btime "); ok {
			boot, _ = strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		}
	}
	if boot == 0 {
		return nil
	}
	entries, _ := os.ReadDir(e.P("/proc"))
	var out []agentSession
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		dir := filepath.Join(e.P("/proc"), entry.Name())
		cmdline, err := readBounded(filepath.Join(dir, "cmdline"), 64<<10)
		if err != nil {
			continue
		}
		agent := agentCLIOf(strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00"))
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
		out = append(out, agentSession{PID: pid, UID: int(owner.Uid), Agent: agent, Started: started})
	}
	return out
}

// darwinAgentSessions asks ps for every process with its elapsed time.
func (e *Env) darwinAgentSessions(ctx context.Context) []agentSession {
	result, err := e.Runner.Run(ctx, "ps", "-axww", "-o", "pid=,uid=,etime=,args=")
	if err != nil && len(result.Stdout) == 0 {
		return nil
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
		if agent := agentCLIOf(fields[3:]); agent != "" {
			out = append(out, agentSession{PID: pid, UID: uid, Agent: agent, Started: now.Add(-elapsed)})
		}
	}
	return out
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

// describeAgentSessionsBeforeActivation warns, per account, about agent
// sessions that started before this deployment was activated.
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
	byUID := map[int][]string{}
	for _, session := range l.env.agentSessionsStartedBefore(ctx, activated, record.ServiceUID) {
		byUID[session.UID] = append(byUID[session.UID], fmt.Sprintf("%s (pid %d)", session.Agent, session.PID))
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
		l.result.AddWarning(codeAgentSessionsRestart, fmt.Sprintf(
			"user %s runs %s, started before DefenseClaw was activated on this computer at %s; an agent reads its hooks when it starts, so these sessions run without DefenseClaw until they are restarted: ask that user to restart them",
			who, strings.Join(byUID[uid], ", "), activationTime))
	}
}
