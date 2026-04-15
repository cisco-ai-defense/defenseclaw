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

package tui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/creack/pty"
)

// CmdEntry describes a TUI command that maps to a CLI invocation.
type CmdEntry struct {
	TUIName     string // short form: "scan skill"
	CLIBinary   string // "defenseclaw" or "defenseclaw-gateway"
	CLIArgs     []string
	Description string
	Category    string // scan, enforce, setup, daemon, info, policy, sandbox, other
	NeedsArg    bool
	ArgHint     string // "<skill-name>", "<url>", "<path>"
}

// CommandOutputMsg carries a single line of output from a running command.
type CommandOutputMsg struct {
	Line      string
	Timestamp time.Time
}

// CommandDoneMsg signals that a command has finished.
type CommandDoneMsg struct {
	Command  string
	ExitCode int
	Duration time.Duration
}

// CommandStartMsg signals that a command has started.
type CommandStartMsg struct {
	Command string
}

// CommandExecutor manages async command execution, shelling out to
// CLI binaries and streaming output via Bubbletea messages.
type CommandExecutor struct {
	mu      sync.Mutex
	running bool
	cancel  chan struct{}
	program *tea.Program
	stdin   io.WriteCloser // non-nil only during interactive execution
}

// NewCommandExecutor creates a new executor.
func NewCommandExecutor() *CommandExecutor {
	return &CommandExecutor{}
}

// SetProgram sets the Bubbletea program reference for sending messages.
func (e *CommandExecutor) SetProgram(p *tea.Program) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.program = p
}

// IsRunning returns whether a command is currently executing.
func (e *CommandExecutor) IsRunning() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}

// Cancel sends an interrupt to the running command.
func (e *CommandExecutor) Cancel() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cancel != nil {
		close(e.cancel)
		e.cancel = nil
	}
}

// WriteInput sends a line of text to the running interactive command's stdin.
func (e *CommandExecutor) WriteInput(line string) {
	e.mu.Lock()
	w := e.stdin
	e.mu.Unlock()
	if w != nil {
		_, _ = io.WriteString(w, line+"\n")
	}
}

// IsInteractive returns true when the currently running command has stdin attached.
func (e *CommandExecutor) IsInteractive() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stdin != nil
}

// ExecuteInteractive runs a command inside a PTY so the child process sees a
// real terminal. This ensures Python and other runtimes use unbuffered/line-
// buffered output, making interactive prompts appear immediately.
func (e *CommandExecutor) ExecuteInteractive(binary string, args []string, displayName string) tea.Cmd {
	return func() tea.Msg {
		e.mu.Lock()
		if e.running {
			e.mu.Unlock()
			return CommandOutputMsg{Line: "A command is already running. Wait for it to finish or press Ctrl+C.", Timestamp: time.Now()}
		}
		e.running = true
		e.cancel = make(chan struct{})
		prog := e.program
		e.mu.Unlock()

		if prog != nil {
			prog.Send(CommandStartMsg{Command: displayName})
		}

		start := time.Now()
		cmd := exec.Command(binary, args...)
		cmd.Env = os.Environ()

		ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 24, Cols: 120})
		if err != nil {
			e.mu.Lock()
			e.running = false
			close(e.cancel)
			e.cancel = nil
			e.mu.Unlock()
			if prog != nil {
				prog.Send(CommandOutputMsg{Line: fmt.Sprintf("Failed to start PTY: %v", err), Timestamp: time.Now()})
			}
			return CommandDoneMsg{Command: displayName, ExitCode: 1, Duration: time.Since(start)}
		}

		e.mu.Lock()
		e.stdin = ptmx
		e.mu.Unlock()

		cancelCh := e.cancel
		go func() {
			<-cancelCh
			if cmd.Process != nil {
				cmd.Process.Signal(os.Interrupt)
			}
		}()

		readInteractiveOutput(ptmx, prog)

		exitCode := 0
		if err := cmd.Wait(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = 1
			}
		}
		ptmx.Close()

		e.mu.Lock()
		e.stdin = nil
		e.running = false
		if e.cancel != nil {
			close(e.cancel)
			e.cancel = nil
		}
		e.mu.Unlock()

		return CommandDoneMsg{Command: displayName, ExitCode: exitCode, Duration: time.Since(start)}
	}
}

// readLineOutput reads from r line-by-line. Used for non-interactive commands
// where output is typically line-buffered and lines should not be split.
func readLineOutput(r io.Reader, program *tea.Program) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if program != nil {
			program.Send(CommandOutputMsg{Line: scanner.Text(), Timestamp: time.Now()})
		}
	}
}

// readInteractiveOutput reads from r using small reads so that partial lines
// (e.g. interactive prompts that don't end with '\n') are delivered to the TUI
// immediately, just like a real terminal would display them.
func readInteractiveOutput(r io.Reader, program *tea.Program) {
	buf := make([]byte, 256)
	var lineBuf strings.Builder
	for {
		n, readErr := r.Read(buf)
		if n > 0 {
			chunk := string(buf[:n])
			for len(chunk) > 0 {
				nlIdx := strings.IndexByte(chunk, '\n')
				if nlIdx >= 0 {
					lineBuf.WriteString(chunk[:nlIdx])
					line := strings.TrimRight(lineBuf.String(), "\r")
					if program != nil {
						program.Send(CommandOutputMsg{Line: line, Timestamp: time.Now()})
					}
					lineBuf.Reset()
					chunk = chunk[nlIdx+1:]
				} else {
					lineBuf.WriteString(chunk)
					chunk = ""
				}
			}
			if lineBuf.Len() > 0 {
				line := strings.TrimRight(lineBuf.String(), "\r")
				if program != nil {
					program.Send(CommandOutputMsg{Line: line, Timestamp: time.Now()})
				}
				lineBuf.Reset()
			}
		}
		if readErr != nil {
			if lineBuf.Len() > 0 {
				line := strings.TrimRight(lineBuf.String(), "\r")
				if program != nil {
					program.Send(CommandOutputMsg{Line: line, Timestamp: time.Now()})
				}
			}
			break
		}
	}
}

// Execute runs a command asynchronously and streams output to the TUI.
func (e *CommandExecutor) Execute(binary string, args []string, displayName string) tea.Cmd {
	return func() tea.Msg {
		e.mu.Lock()
		if e.running {
			e.mu.Unlock()
			return CommandOutputMsg{Line: "A command is already running. Wait for it to finish or press Ctrl+C.", Timestamp: time.Now()}
		}
		e.running = true
		e.cancel = make(chan struct{})
		prog := e.program
		e.mu.Unlock()

		if prog != nil {
			prog.Send(CommandStartMsg{Command: displayName})
		}

		start := time.Now()
		cmd := exec.Command(binary, args...)
		cmd.Env = os.Environ()

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			e.mu.Lock()
			e.running = false
			close(e.cancel)
			e.cancel = nil
			e.mu.Unlock()
			if prog != nil {
				prog.Send(CommandOutputMsg{Line: fmt.Sprintf("Failed to create pipe: %v", err), Timestamp: time.Now()})
			}
			return CommandDoneMsg{Command: displayName, ExitCode: 1, Duration: time.Since(start)}
		}
		cmd.Stderr = cmd.Stdout

		if err := cmd.Start(); err != nil {
			e.mu.Lock()
			e.running = false
			close(e.cancel)
			e.cancel = nil
			e.mu.Unlock()
			if prog != nil {
				prog.Send(CommandOutputMsg{Line: fmt.Sprintf("Failed to start: %v", err), Timestamp: time.Now()})
			}
			return CommandDoneMsg{Command: displayName, ExitCode: 1, Duration: time.Since(start)}
		}

		cancelCh := e.cancel

		go func() {
			<-cancelCh
			if cmd.Process != nil {
				cmd.Process.Signal(os.Interrupt)
			}
		}()

		readLineOutput(stdout, prog)

		exitCode := 0
		if err := cmd.Wait(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = 1
			}
		}

		e.mu.Lock()
		e.running = false
		if e.cancel != nil {
			close(e.cancel)
			e.cancel = nil
		}
		e.mu.Unlock()

		return CommandDoneMsg{Command: displayName, ExitCode: exitCode, Duration: time.Since(start)}
	}
}

// BuildRegistry returns the full command registry with TUI-to-CLI mapping.
func BuildRegistry() []CmdEntry {
	dc := "defenseclaw"
	gw := "defenseclaw-gateway"

	return []CmdEntry{
		// Setup
		{TUIName: "init", CLIBinary: dc, CLIArgs: []string{"init"}, Description: "Initialize DefenseClaw", Category: "setup"},
		{TUIName: "setup skill-scanner", CLIBinary: dc, CLIArgs: []string{"setup", "skill-scanner"}, Description: "Configure skill scanner (interactive)", Category: "setup"},
		{TUIName: "setup mcp-scanner", CLIBinary: dc, CLIArgs: []string{"setup", "mcp-scanner"}, Description: "Configure MCP scanner (interactive)", Category: "setup"},
		{TUIName: "setup gateway", CLIBinary: dc, CLIArgs: []string{"setup", "gateway"}, Description: "Configure gateway connection (interactive)", Category: "setup"},
		{TUIName: "setup guardrail", CLIBinary: dc, CLIArgs: []string{"setup", "guardrail"}, Description: "Configure LLM guardrail", Category: "setup"},
		{TUIName: "setup splunk", CLIBinary: dc, CLIArgs: []string{"setup", "splunk"}, Description: "Configure Splunk / O11y", Category: "setup"},

		// Scan
		{TUIName: "scan skill", CLIBinary: dc, CLIArgs: []string{"skill", "scan"}, Description: "Scan a skill", Category: "scan", NeedsArg: true, ArgHint: "<skill-name>"},
		{TUIName: "scan skill --all", CLIBinary: dc, CLIArgs: []string{"skill", "scan", "--all"}, Description: "Scan all skills", Category: "scan"},
		{TUIName: "scan mcp", CLIBinary: dc, CLIArgs: []string{"mcp", "scan"}, Description: "Scan an MCP server", Category: "scan", NeedsArg: true, ArgHint: "<url>"},
		{TUIName: "scan mcp --all", CLIBinary: dc, CLIArgs: []string{"mcp", "scan", "--all"}, Description: "Scan all MCP servers", Category: "scan"},
		{TUIName: "scan plugin", CLIBinary: dc, CLIArgs: []string{"plugin", "scan"}, Description: "Scan a plugin", Category: "scan", NeedsArg: true, ArgHint: "<plugin-name>"},
		{TUIName: "scan aibom", CLIBinary: dc, CLIArgs: []string{"aibom", "scan"}, Description: "Generate AIBOM inventory", Category: "scan"},
		{TUIName: "scan code", CLIBinary: gw, CLIArgs: []string{"scan", "code"}, Description: "CodeGuard scan", Category: "scan", NeedsArg: true, ArgHint: "<path>"},

		// Enforce (skill)
		{TUIName: "block skill", CLIBinary: dc, CLIArgs: []string{"skill", "block"}, Description: "Block a skill", Category: "enforce", NeedsArg: true, ArgHint: "<skill-name>"},
		{TUIName: "allow skill", CLIBinary: dc, CLIArgs: []string{"skill", "allow"}, Description: "Allow-list a skill", Category: "enforce", NeedsArg: true, ArgHint: "<skill-name>"},
		{TUIName: "unblock skill", CLIBinary: dc, CLIArgs: []string{"skill", "unblock"}, Description: "Unblock a skill", Category: "enforce", NeedsArg: true, ArgHint: "<skill-name>"},
		{TUIName: "disable skill", CLIBinary: dc, CLIArgs: []string{"skill", "disable"}, Description: "Disable a skill at runtime", Category: "enforce", NeedsArg: true, ArgHint: "<skill-name>"},
		{TUIName: "enable skill", CLIBinary: dc, CLIArgs: []string{"skill", "enable"}, Description: "Enable a skill at runtime", Category: "enforce", NeedsArg: true, ArgHint: "<skill-name>"},
		{TUIName: "quarantine skill", CLIBinary: dc, CLIArgs: []string{"skill", "quarantine"}, Description: "Quarantine a skill", Category: "enforce", NeedsArg: true, ArgHint: "<skill-name>"},
		{TUIName: "restore skill", CLIBinary: dc, CLIArgs: []string{"skill", "restore"}, Description: "Restore a quarantined skill", Category: "enforce", NeedsArg: true, ArgHint: "<skill-name>"},

		// Enforce (mcp)
		{TUIName: "block mcp", CLIBinary: dc, CLIArgs: []string{"mcp", "block"}, Description: "Block an MCP server", Category: "enforce", NeedsArg: true, ArgHint: "<url>"},
		{TUIName: "allow mcp", CLIBinary: dc, CLIArgs: []string{"mcp", "allow"}, Description: "Allow-list an MCP server", Category: "enforce", NeedsArg: true, ArgHint: "<url>"},
		{TUIName: "unblock mcp", CLIBinary: dc, CLIArgs: []string{"mcp", "unblock"}, Description: "Unblock an MCP server", Category: "enforce", NeedsArg: true, ArgHint: "<url>"},
		{TUIName: "set mcp", CLIBinary: dc, CLIArgs: []string{"mcp", "set"}, Description: "Scan + set MCP server in OpenClaw", Category: "enforce", NeedsArg: true, ArgHint: "<url>"},
		{TUIName: "unset mcp", CLIBinary: dc, CLIArgs: []string{"mcp", "unset"}, Description: "Unset MCP server from OpenClaw", Category: "enforce", NeedsArg: true, ArgHint: "<url>"},

		// Enforce (plugin)
		{TUIName: "block plugin", CLIBinary: dc, CLIArgs: []string{"plugin", "block"}, Description: "Block a plugin", Category: "enforce", NeedsArg: true, ArgHint: "<plugin-name>"},
		{TUIName: "allow plugin", CLIBinary: dc, CLIArgs: []string{"plugin", "allow"}, Description: "Allow-list a plugin", Category: "enforce", NeedsArg: true, ArgHint: "<plugin-name>"},
		{TUIName: "disable plugin", CLIBinary: dc, CLIArgs: []string{"plugin", "disable"}, Description: "Disable a plugin at runtime", Category: "enforce", NeedsArg: true, ArgHint: "<plugin-name>"},
		{TUIName: "enable plugin", CLIBinary: dc, CLIArgs: []string{"plugin", "enable"}, Description: "Enable a plugin at runtime", Category: "enforce", NeedsArg: true, ArgHint: "<plugin-name>"},
		{TUIName: "quarantine plugin", CLIBinary: dc, CLIArgs: []string{"plugin", "quarantine"}, Description: "Quarantine a plugin", Category: "enforce", NeedsArg: true, ArgHint: "<plugin-name>"},
		{TUIName: "restore plugin", CLIBinary: dc, CLIArgs: []string{"plugin", "restore"}, Description: "Restore a quarantined plugin", Category: "enforce", NeedsArg: true, ArgHint: "<plugin-name>"},
		{TUIName: "remove plugin", CLIBinary: dc, CLIArgs: []string{"plugin", "remove"}, Description: "Remove a plugin", Category: "enforce", NeedsArg: true, ArgHint: "<plugin-name>"},

		// Enforce (tool)
		{TUIName: "block tool", CLIBinary: dc, CLIArgs: []string{"tool", "block"}, Description: "Block a tool", Category: "enforce", NeedsArg: true, ArgHint: "<tool-name>"},
		{TUIName: "allow tool", CLIBinary: dc, CLIArgs: []string{"tool", "allow"}, Description: "Allow-list a tool", Category: "enforce", NeedsArg: true, ArgHint: "<tool-name>"},
		{TUIName: "unblock tool", CLIBinary: dc, CLIArgs: []string{"tool", "unblock"}, Description: "Unblock a tool", Category: "enforce", NeedsArg: true, ArgHint: "<tool-name>"},

		// Install
		{TUIName: "install skill", CLIBinary: dc, CLIArgs: []string{"skill", "install"}, Description: "Install a skill from ClawHub", Category: "install", NeedsArg: true, ArgHint: "<skill-name>"},
		{TUIName: "install plugin", CLIBinary: dc, CLIArgs: []string{"plugin", "install"}, Description: "Install a plugin", Category: "install", NeedsArg: true, ArgHint: "<plugin-name>"},
		{TUIName: "install codeguard", CLIBinary: dc, CLIArgs: []string{"codeguard", "install-skill"}, Description: "Install CodeGuard skill", Category: "install"},

		// Policy
		{TUIName: "policy list", CLIBinary: dc, CLIArgs: []string{"policy", "list"}, Description: "List policies", Category: "policy"},
		{TUIName: "policy show", CLIBinary: dc, CLIArgs: []string{"policy", "show"}, Description: "Show policy details", Category: "policy", NeedsArg: true, ArgHint: "<policy-name>"},
		{TUIName: "policy create", CLIBinary: dc, CLIArgs: []string{"policy", "create"}, Description: "Create a new policy", Category: "policy", NeedsArg: true, ArgHint: "<policy-name>"},
		{TUIName: "policy activate", CLIBinary: dc, CLIArgs: []string{"policy", "activate"}, Description: "Activate a policy", Category: "policy", NeedsArg: true, ArgHint: "<policy-name>"},
		{TUIName: "policy delete", CLIBinary: dc, CLIArgs: []string{"policy", "delete"}, Description: "Delete a user policy", Category: "policy", NeedsArg: true, ArgHint: "<policy-name>"},
		{TUIName: "policy validate", CLIBinary: dc, CLIArgs: []string{"policy", "validate"}, Description: "Validate policy data + Rego", Category: "policy"},
		{TUIName: "policy test", CLIBinary: dc, CLIArgs: []string{"policy", "test"}, Description: "Run OPA policy tests", Category: "policy"},
		{TUIName: "policy edit actions", CLIBinary: dc, CLIArgs: []string{"policy", "edit", "actions"}, Description: "Edit severity action rules", Category: "policy"},
		{TUIName: "policy edit scanner", CLIBinary: dc, CLIArgs: []string{"policy", "edit", "scanner"}, Description: "Edit scanner overrides", Category: "policy"},
		{TUIName: "policy edit guardrail", CLIBinary: dc, CLIArgs: []string{"policy", "edit", "guardrail"}, Description: "Edit guardrail policy", Category: "policy"},
		{TUIName: "policy edit firewall", CLIBinary: dc, CLIArgs: []string{"policy", "edit", "firewall"}, Description: "Edit firewall policy", Category: "policy"},
		{TUIName: "policy evaluate", CLIBinary: gw, CLIArgs: []string{"policy", "evaluate"}, Description: "Dry-run admission evaluation", Category: "policy"},
		{TUIName: "policy evaluate-firewall", CLIBinary: gw, CLIArgs: []string{"policy", "evaluate-firewall"}, Description: "Dry-run firewall evaluation", Category: "policy"},
		{TUIName: "policy reload", CLIBinary: gw, CLIArgs: []string{"policy", "reload"}, Description: "Reload policy in running sidecar", Category: "policy"},
		{TUIName: "policy domains", CLIBinary: gw, CLIArgs: []string{"policy", "domains"}, Description: "Show firewall domain lists", Category: "policy"},

		// Info
		{TUIName: "list skills", CLIBinary: dc, CLIArgs: []string{"skill", "list"}, Description: "List skills with scan status", Category: "info"},
		{TUIName: "list mcps", CLIBinary: dc, CLIArgs: []string{"mcp", "list"}, Description: "List MCP servers with status", Category: "info"},
		{TUIName: "list plugins", CLIBinary: dc, CLIArgs: []string{"plugin", "list"}, Description: "List installed plugins", Category: "info"},
		{TUIName: "list tools", CLIBinary: dc, CLIArgs: []string{"tool", "list"}, Description: "List tool rules", Category: "info"},
		{TUIName: "info skill", CLIBinary: dc, CLIArgs: []string{"skill", "info"}, Description: "Show skill details", Category: "info", NeedsArg: true, ArgHint: "<skill-name>"},
		{TUIName: "info plugin", CLIBinary: dc, CLIArgs: []string{"plugin", "info"}, Description: "Show plugin details", Category: "info", NeedsArg: true, ArgHint: "<plugin-name>"},
		{TUIName: "tool status", CLIBinary: dc, CLIArgs: []string{"tool", "status"}, Description: "Show tool block/allow status", Category: "info", NeedsArg: true, ArgHint: "<tool-name>"},
		{TUIName: "status", CLIBinary: dc, CLIArgs: []string{"status"}, Description: "Show DefenseClaw status", Category: "info"},
		{TUIName: "doctor", CLIBinary: dc, CLIArgs: []string{"doctor"}, Description: "Run health checks", Category: "info"},

		// Daemon
		{TUIName: "start", CLIBinary: gw, CLIArgs: []string{"start"}, Description: "Start gateway sidecar", Category: "daemon"},
		{TUIName: "stop", CLIBinary: gw, CLIArgs: []string{"stop"}, Description: "Stop gateway sidecar", Category: "daemon"},
		{TUIName: "restart", CLIBinary: gw, CLIArgs: []string{"restart"}, Description: "Restart gateway sidecar", Category: "daemon"},
		{TUIName: "gateway status", CLIBinary: gw, CLIArgs: []string{"status"}, Description: "Show gateway health", Category: "daemon"},
		{TUIName: "watchdog start", CLIBinary: gw, CLIArgs: []string{"watchdog", "start"}, Description: "Start health watchdog", Category: "daemon"},
		{TUIName: "watchdog stop", CLIBinary: gw, CLIArgs: []string{"watchdog", "stop"}, Description: "Stop health watchdog", Category: "daemon"},
		{TUIName: "watchdog status", CLIBinary: gw, CLIArgs: []string{"watchdog", "status"}, Description: "Show watchdog status", Category: "daemon"},

		// Sandbox
		{TUIName: "sandbox init", CLIBinary: dc, CLIArgs: []string{"sandbox", "init"}, Description: "Initialize sandbox environment", Category: "sandbox"},
		{TUIName: "sandbox setup", CLIBinary: dc, CLIArgs: []string{"sandbox", "setup"}, Description: "Configure sandbox networking", Category: "sandbox"},
		{TUIName: "sandbox start", CLIBinary: gw, CLIArgs: []string{"sandbox", "start"}, Description: "Start sandbox services", Category: "sandbox"},
		{TUIName: "sandbox stop", CLIBinary: gw, CLIArgs: []string{"sandbox", "stop"}, Description: "Stop sandbox services", Category: "sandbox"},
		{TUIName: "sandbox restart", CLIBinary: gw, CLIArgs: []string{"sandbox", "restart"}, Description: "Restart sandbox services", Category: "sandbox"},
		{TUIName: "sandbox status", CLIBinary: gw, CLIArgs: []string{"sandbox", "status"}, Description: "Show sandbox status", Category: "sandbox"},
		{TUIName: "sandbox exec", CLIBinary: gw, CLIArgs: []string{"sandbox", "exec"}, Description: "Run command in sandbox", Category: "sandbox", NeedsArg: true, ArgHint: "<command>"},
		{TUIName: "sandbox shell", CLIBinary: gw, CLIArgs: []string{"sandbox", "shell"}, Description: "Open sandbox shell", Category: "sandbox"},
		{TUIName: "sandbox policy diff", CLIBinary: gw, CLIArgs: []string{"sandbox", "policy", "diff"}, Description: "Compare policy vs endpoints", Category: "sandbox"},

		// Other
		{TUIName: "upgrade", CLIBinary: dc, CLIArgs: []string{"upgrade", "--yes"}, Description: "Upgrade DefenseClaw", Category: "other"},

		// Aliases (noun-first forms)
		{TUIName: "skill list", CLIBinary: dc, CLIArgs: []string{"skill", "list"}, Description: "List skills with scan status", Category: "info"},
		{TUIName: "skill scan", CLIBinary: dc, CLIArgs: []string{"skill", "scan"}, Description: "Scan a skill", Category: "scan", NeedsArg: true, ArgHint: "<skill-name>"},
		{TUIName: "skill info", CLIBinary: dc, CLIArgs: []string{"skill", "info"}, Description: "Show skill details", Category: "info", NeedsArg: true, ArgHint: "<skill-name>"},
		{TUIName: "mcp list", CLIBinary: dc, CLIArgs: []string{"mcp", "list"}, Description: "List MCP servers with status", Category: "info"},
		{TUIName: "mcp scan", CLIBinary: dc, CLIArgs: []string{"mcp", "scan"}, Description: "Scan an MCP server", Category: "scan", NeedsArg: true, ArgHint: "<url>"},
		{TUIName: "plugin list", CLIBinary: dc, CLIArgs: []string{"plugin", "list"}, Description: "List installed plugins", Category: "info"},
		{TUIName: "plugin scan", CLIBinary: dc, CLIArgs: []string{"plugin", "scan"}, Description: "Scan a plugin", Category: "scan", NeedsArg: true, ArgHint: "<plugin-name>"},
		{TUIName: "plugin info", CLIBinary: dc, CLIArgs: []string{"plugin", "info"}, Description: "Show plugin details", Category: "info", NeedsArg: true, ArgHint: "<plugin-name>"},
		{TUIName: "tool list", CLIBinary: dc, CLIArgs: []string{"tool", "list"}, Description: "List tool rules", Category: "info"},
		{TUIName: "skills", CLIBinary: dc, CLIArgs: []string{"skill", "list"}, Description: "List skills", Category: "info"},
		{TUIName: "mcps", CLIBinary: dc, CLIArgs: []string{"mcp", "list"}, Description: "List MCP servers", Category: "info"},
		{TUIName: "plugins", CLIBinary: dc, CLIArgs: []string{"plugin", "list"}, Description: "List plugins", Category: "info"},
		{TUIName: "tools", CLIBinary: dc, CLIArgs: []string{"tool", "list"}, Description: "List tools", Category: "info"},
		{TUIName: "alerts", CLIBinary: dc, CLIArgs: []string{"alerts", "list"}, Description: "List alerts", Category: "info"},
		{TUIName: "help", CLIBinary: dc, CLIArgs: []string{"--help"}, Description: "Show CLI help", Category: "info"},
	}
}

// MatchCommand finds the best matching CmdEntry for a user input string.
// Returns the entry and any extra arguments (e.g., the target name).
func MatchCommand(input string, registry []CmdEntry) (*CmdEntry, string) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, ""
	}

	var bestMatch *CmdEntry
	var bestLen int
	var extra string

	for i := range registry {
		entry := &registry[i]
		if strings.HasPrefix(input, entry.TUIName) {
			nameLen := len(entry.TUIName)
			if nameLen > bestLen {
				bestLen = nameLen
				bestMatch = entry
				remainder := strings.TrimSpace(input[nameLen:])
				extra = remainder
			}
		}
	}

	return bestMatch, extra
}
