// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package agentprocess names the agent process that runs a hook: the
// nearest ancestor of the hook process that is not a shell, a launcher or a
// DefenseClaw binary. Claude Code, Codex, Copilot CLI, OpenCode and Amp load
// their hooks or plugins when the process starts and keep them for its
// lifetime, so the foreign-hook guard binds what it saw to this process: a
// session the agent clears, compacts or resumes in the same process keeps
// the hooks the process loaded.
//
// An identity is "<goos>:<boot>:<pid>:<start>". The start time makes a
// reused process ID a different identity; boot is the Linux boot ID
// (Linux start times count from boot) and empty elsewhere.
package agentprocess

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// Process is one process-table entry.
type Process struct {
	PID    int
	Parent int
	// Name is the executable's base name.
	Name string
	// Start orders processes within one boot (Linux clock ticks since boot,
	// macOS microseconds since the epoch, Windows FILETIME).
	Start int64
	// Boot is the Linux boot ID; empty elsewhere.
	Boot string
	// Exited marks a process that has ended but is still in the table (a
	// zombie, or a Windows process object someone holds open).
	Exited bool
}

func (p Process) identity() string {
	return fmt.Sprintf("%s:%s:%d:%d", runtime.GOOS, p.Boot, p.PID, p.Start)
}

// errNotFound is a lookup of a process that does not exist.
var errNotFound = errors.New("process not found")

// maxHops bounds the walk; a hook sits under at most a shell or two and a
// launcher.
const maxHops = 8

// transparentNames are the processes an agent runs a hook through: shells,
// command wrappers and DefenseClaw's own launchers. None of them outlives
// one hook invocation, so none of them is the agent.
var transparentNames = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "mksh": true, "oksh": true,
	"ash": true, "fish": true, "csh": true, "tcsh": true, "busybox": true,
	"env": true, "nice": true, "nohup": true, "timeout": true, "stdbuf": true,
	"cmd": true, "powershell": true, "pwsh": true,
}

// sessionRootNames are long-lived processes that are never the agent:
// service managers, login and remote sessions, terminal multiplexers and
// terminal emulators. A walk that reaches one found no agent (the hook ran
// from a terminal, or its agent is itself a shell script), so the identity
// is unknown rather than something every terminal shares.
var sessionRootNames = map[string]bool{
	"init": true, "systemd": true, "launchd": true, "login": true, "su": true, "sudo": true,
	"sshd": true, "sshd-session": true, "mosh-server": true, "tmux": true, "screen": true,
	"terminal": true, "iterm2": true, "gnome-terminal-server": true, "konsole": true, "xterm": true,
	"alacritty": true, "kitty": true, "wezterm-gui": true, "tilix": true,
	"system": true, "smss": true, "csrss": true, "wininit": true, "winlogon": true,
	"services": true, "svchost": true, "explorer": true,
	"windowsterminal": true, "openconsole": true, "conhost": true,
}

// normalizedName lower-cases a process name and strips the .exe suffix and
// a login shell's leading dash.
func normalizedName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimPrefix(name, "-")
	return strings.TrimSuffix(name, ".exe")
}

func transparent(name string) bool {
	name = normalizedName(name)
	// macOS truncates command names to 16 bytes (defenseclaw-hook-launcher
	// reads as defenseclaw-hoo).
	return transparentNames[name] || strings.HasPrefix(name, "defenseclaw")
}

// Now returns the current instant in the units of an identity's start time,
// "<goos>:<boot>:<clock>", or "" when it cannot be read (on Linux, also when
// the boot ID is unknown). StartedBefore compares an identity with it.
func Now() string {
	boot, clock, ok := currentClock()
	if !ok {
		return ""
	}
	return fmt.Sprintf("%s:%s:%d", runtime.GOOS, boot, clock)
}

// StartedBefore reports whether the process an identity names started no
// later than mark, a Now value from the same host. A process of another boot
// started after every mark of an earlier one, and an identity or mark that
// does not parse is not known to have started before anything.
func StartedBefore(identity, mark string) bool {
	id, at := strings.Split(identity, ":"), strings.Split(mark, ":")
	if len(id) != 4 || len(at) != 3 || id[0] != at[0] || id[1] != at[1] {
		return false
	}
	start, startErr := strconv.ParseInt(id[3], 10, 64)
	clock, clockErr := strconv.ParseInt(at[2], 10, 64)
	return startErr == nil && clockErr == nil && start <= clock
}

// Identity returns the identity of the agent process that runs this
// process, or "" when no agent ancestor can be named.
func Identity() string {
	lookup, done := newLookup()
	defer done()
	return identityFrom(lookup, os.Getpid())
}

// identityFrom walks up from self. A parent that started after its child
// is a reused process ID (the real parent exited), so the walk stops there.
func identityFrom(lookup func(int) (Process, error), self int) string {
	child, err := lookup(self)
	if err != nil {
		return ""
	}
	for hop := 0; hop < maxHops; hop++ {
		pid := child.Parent
		if pid <= 1 || pid == child.PID {
			return ""
		}
		parent, err := lookup(pid)
		if err != nil || parent.Exited || parent.Start > child.Start {
			return ""
		}
		name := normalizedName(parent.Name)
		if sessionRootNames[name] {
			return ""
		}
		// Some process APIs cannot resolve an executable name even when they
		// return a stable PID and start time. The name is only a hint for
		// skipping wrappers; it must not be required to name the process.
		if !transparent(name) {
			return parent.identity()
		}
		child = parent
	}
	return ""
}
