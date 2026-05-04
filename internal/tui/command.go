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
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"

	tea "charm.land/bubbletea/v2"
	"github.com/creack/pty"
)

// resolveDefenseclawBin returns a best-effort absolute path to the
// `defenseclaw` CLI binary, with defensive fallbacks. TUI subprocess
// calls used to hardcode the literal "defenseclaw" string and relied
// on $PATH resolution, which quietly misbehaves when the TUI is
// launched from (a) a systemd unit with an empty PATH, (b) a shell
// with a stale PATH after an in-place install, or (c) a user with
// two `defenseclaw` binaries on PATH (e.g. `pipx` vs system package).
//
// Resolution order:
//  1. `os.Executable()` basename match — if the TUI was itself
//     launched as `defenseclaw tui`, reuse the exact same binary
//     so sibling commands match the running version.
//  2. sibling binary next to `os.Executable()` — supports installs
//     that symlink `defenseclaw-gateway` and `defenseclaw` into the
//     same directory.
//  3. `exec.LookPath("defenseclaw")` — classic PATH lookup.
//  4. literal "defenseclaw" string — last-resort fallback so tests
//     and minimal environments keep working; os/exec will surface
//     the same error the TUI used to.
//
// Callers get an absolute path when one is available so `exec.Command`
// never walks PATH again at spawn time. Always returns a non-empty
// string; errors are intentionally swallowed because all three
// fallbacks are advisory, not authoritative.
func resolveDefenseclawBin() string {
	return resolveSiblingBin("defenseclaw")
}

// resolveRegistryBinary maps a registry-stored logical binary name
// ("defenseclaw" or "defenseclaw-gateway") to an actual absolute path
// using the same sibling/PATH resolution as resolveDefenseclawBin.
// Anything else is returned verbatim — that keeps future extensions
// (e.g. a third `defenseclaw-xyz` helper) from silently breaking just
// because the resolver doesn't know about them yet.
func resolveRegistryBinary(binary string) string {
	switch binary {
	case "defenseclaw":
		return resolveDefenseclawBin()
	case "defenseclaw-gateway":
		return resolveDefenseclawGatewayBin()
	default:
		return binary
	}
}

// resolveDefenseclawGatewayBin resolves the `defenseclaw-gateway` binary
// using the same heuristics as resolveDefenseclawBin. The registry uses
// both binaries, so gateway commands (policy evaluate, policy reload,
// scan code, …) benefit from the same hardening against empty/stale
// PATH environments.
func resolveDefenseclawGatewayBin() string {
	return resolveSiblingBin("defenseclaw-gateway")
}

// resolveSiblingBin implements the shared lookup logic documented on
// resolveDefenseclawBin. The same resolution order applies regardless
// of which DefenseClaw binary we're targeting:
//  1. os.Executable basename match (process is already this binary).
//  2. sibling in os.Executable dir.
//  3. exec.LookPath.
//  4. literal name (fall through to os/exec's NotFound error).
func resolveSiblingBin(name string) string {
	self, err := os.Executable()
	if err == nil {
		// Clean up /proc/self/exe-style symlink chains so sibling
		// resolution lines up with what the user sees on disk.
		if resolved, rerr := filepath.EvalSymlinks(self); rerr == nil {
			self = resolved
		}

		// 1. Same binary — re-launching ourselves.
		if filepath.Base(self) == name {
			return self
		}

		// 2. Sibling binary in the same directory. This is how
		//    the Makefile's `cli-install` lays things out
		//    (defenseclaw and defenseclaw-gateway next to each
		//    other).
		sibling := filepath.Join(filepath.Dir(self), name)
		if info, statErr := os.Stat(sibling); statErr == nil {
			mode := info.Mode()
			if !mode.IsDir() && mode&0o111 != 0 {
				return sibling
			}
		}
	}

	// 3. Classic PATH lookup. Common case on developer machines
	//    where the binary lives in a venv's /bin directory.
	if p, lerr := exec.LookPath(name); lerr == nil {
		return p
	}

	// 4. Fallback. os/exec will produce the same "<name>: not
	//    found" error the pre-refactor code did, so behaviour is
	//    a strict superset of the old path.
	return name
}

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

func buildCLIArgs(entry *CmdEntry, extra string) ([]string, error) {
	if entry == nil {
		return nil, fmt.Errorf("missing command entry")
	}

	args := make([]string, len(entry.CLIArgs))
	copy(args, entry.CLIArgs)

	if strings.TrimSpace(extra) == "" {
		return args, nil
	}

	tailArgs, err := splitCommandTail(extra)
	if err != nil {
		return nil, err
	}
	return append(args, tailArgs...), nil
}

func splitCommandTail(tail string) ([]string, error) {
	var (
		args       []string
		current    strings.Builder
		inSingle   bool
		inDouble   bool
		escaping   bool
		argStarted bool
	)

	flush := func() {
		if !argStarted {
			return
		}
		args = append(args, current.String())
		current.Reset()
		argStarted = false
	}

	for _, r := range tail {
		switch {
		case escaping:
			current.WriteRune(r)
			escaping = false
			argStarted = true
		case r == '\\' && !inSingle:
			escaping = true
			argStarted = true
		case inSingle:
			if r == '\'' {
				inSingle = false
				argStarted = true
			} else {
				current.WriteRune(r)
				argStarted = true
			}
		case inDouble:
			if r == '"' {
				inDouble = false
				argStarted = true
			} else {
				current.WriteRune(r)
				argStarted = true
			}
		case r == '\'':
			inSingle = true
			argStarted = true
		case r == '"':
			inDouble = true
			argStarted = true
		case unicode.IsSpace(r):
			flush()
		default:
			current.WriteRune(r)
			argStarted = true
		}
	}

	if escaping {
		return nil, fmt.Errorf("command ends with an unfinished escape")
	}
	if inSingle || inDouble {
		return nil, fmt.Errorf("command has an unterminated quote")
	}

	flush()
	return args, nil
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
		cmd := exec.Command(resolveRegistryBinary(binary), args...)
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
	if err := scanner.Err(); err != nil && program != nil {
		program.Send(CommandOutputMsg{Line: fmt.Sprintf("[read error: %v]", err), Timestamp: time.Now()})
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
		cmd := exec.Command(resolveRegistryBinary(binary), args...)
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
		{TUIName: "init first-run", CLIBinary: dc, CLIArgs: []string{"init", "--non-interactive", "--yes", "--verify"}, Description: "Run guided first-run backend with defaults", Category: "setup"},
		{TUIName: "quickstart", CLIBinary: dc, CLIArgs: []string{"quickstart", "--non-interactive", "--yes"}, Description: "Compatibility first-run wrapper", Category: "setup"},
		{TUIName: "setup llm", CLIBinary: dc, CLIArgs: []string{"setup", "llm"}, Description: "Configure the unified LLM interactively", Category: "setup"},
		{TUIName: "setup llm show", CLIBinary: dc, CLIArgs: []string{"setup", "llm", "--show"}, Description: "Show unified LLM settings", Category: "setup"},
		{TUIName: "setup migrate-llm", CLIBinary: dc, CLIArgs: []string{"setup", "migrate-llm"}, Description: "Migrate legacy LLM config into unified llm: block", Category: "setup"},
		{TUIName: "setup skill-scanner", CLIBinary: dc, CLIArgs: []string{"setup", "skill-scanner"}, Description: "Configure skill scanner (interactive)", Category: "setup"},
		{TUIName: "setup mcp-scanner", CLIBinary: dc, CLIArgs: []string{"setup", "mcp-scanner"}, Description: "Configure MCP scanner (interactive)", Category: "setup"},
		{TUIName: "setup codex", CLIBinary: dc, CLIArgs: []string{"setup", "codex", "--yes"}, Description: "Configure Codex observability hooks", Category: "setup"},
		{TUIName: "setup claude-code", CLIBinary: dc, CLIArgs: []string{"setup", "claude-code", "--yes"}, Description: "Configure Claude Code observability hooks", Category: "setup"},
		{TUIName: "setup mode", CLIBinary: dc, CLIArgs: []string{"setup", "mode"}, Description: "Switch active connector", Category: "setup", NeedsArg: true, ArgHint: "<openclaw|codex|claudecode|zeptoclaw|hermes|cursor|windsurf|geminicli|copilot>"},
		{TUIName: "setup rotate-token", CLIBinary: dc, CLIArgs: []string{"setup", "rotate-token", "--yes"}, Description: "Rotate the gateway token", Category: "setup"},
		{TUIName: "setup gateway", CLIBinary: dc, CLIArgs: []string{"setup", "gateway"}, Description: "Configure gateway connection (interactive)", Category: "setup"},
		{TUIName: "setup guardrail", CLIBinary: dc, CLIArgs: []string{"setup", "guardrail"}, Description: "Configure LLM guardrail", Category: "setup"},
		{TUIName: "setup redaction", CLIBinary: dc, CLIArgs: []string{"setup", "redaction"}, Description: "Show/toggle redaction state", Category: "setup", NeedsArg: true, ArgHint: "<status|on|off> [--yes]"},
		{TUIName: "setup splunk", CLIBinary: dc, CLIArgs: []string{"setup", "splunk"}, Description: "Configure Splunk / O11y", Category: "setup"},
		{TUIName: "setup local-observability up", CLIBinary: dc, CLIArgs: []string{"setup", "local-observability", "up"}, Description: "Start local Prom/Loki/Tempo/Grafana stack", Category: "setup"},
		{TUIName: "setup local-observability down", CLIBinary: dc, CLIArgs: []string{"setup", "local-observability", "down"}, Description: "Stop local observability stack", Category: "setup"},
		{TUIName: "setup local-observability reset", CLIBinary: dc, CLIArgs: []string{"setup", "local-observability", "reset", "--yes"}, Description: "Stop local observability and wipe stored event volumes", Category: "setup"},
		{TUIName: "setup local-observability status", CLIBinary: dc, CLIArgs: []string{"setup", "local-observability", "status"}, Description: "Show local observability stack status", Category: "setup"},
		{TUIName: "setup local-observability url", CLIBinary: dc, CLIArgs: []string{"setup", "local-observability", "url"}, Description: "Show local observability URLs", Category: "setup"},
		{TUIName: "setup local-observability logs", CLIBinary: dc, CLIArgs: []string{"setup", "local-observability", "logs"}, Description: "Tail local observability logs", Category: "setup"},
		{TUIName: "setup observability add", CLIBinary: dc, CLIArgs: []string{"setup", "observability", "add"}, Description: "Add an observability/audit destination preset", Category: "setup", NeedsArg: true, ArgHint: "<preset> [flags]"},
		{TUIName: "setup observability list", CLIBinary: dc, CLIArgs: []string{"setup", "observability", "list"}, Description: "List configured observability destinations", Category: "setup"},
		{TUIName: "setup observability enable", CLIBinary: dc, CLIArgs: []string{"setup", "observability", "enable"}, Description: "Enable an observability destination", Category: "setup", NeedsArg: true, ArgHint: "<name>"},
		{TUIName: "setup observability disable", CLIBinary: dc, CLIArgs: []string{"setup", "observability", "disable"}, Description: "Disable an observability destination", Category: "setup", NeedsArg: true, ArgHint: "<name>"},
		{TUIName: "setup observability remove", CLIBinary: dc, CLIArgs: []string{"setup", "observability", "remove", "--yes"}, Description: "Remove an observability destination", Category: "setup", NeedsArg: true, ArgHint: "<name>"},
		{TUIName: "setup observability test", CLIBinary: dc, CLIArgs: []string{"setup", "observability", "test"}, Description: "Probe an observability destination", Category: "setup", NeedsArg: true, ArgHint: "<name>"},
		{TUIName: "setup observability migrate-splunk", CLIBinary: dc, CLIArgs: []string{"setup", "observability", "migrate-splunk", "--apply"}, Description: "Migrate legacy splunk: block into audit_sinks[]", Category: "setup"},
		{TUIName: "setup webhook add", CLIBinary: dc, CLIArgs: []string{"setup", "webhook", "add"}, Description: "Add a notifier webhook", Category: "setup", NeedsArg: true, ArgHint: "<name> --type <slack|teams|pagerduty|generic>"},
		{TUIName: "setup webhook list", CLIBinary: dc, CLIArgs: []string{"setup", "webhook", "list"}, Description: "List notifier webhooks", Category: "setup"},
		{TUIName: "setup webhook show", CLIBinary: dc, CLIArgs: []string{"setup", "webhook", "show"}, Description: "Show a notifier webhook", Category: "setup", NeedsArg: true, ArgHint: "<name>"},
		{TUIName: "setup webhook enable", CLIBinary: dc, CLIArgs: []string{"setup", "webhook", "enable"}, Description: "Enable a notifier webhook", Category: "setup", NeedsArg: true, ArgHint: "<name>"},
		{TUIName: "setup webhook disable", CLIBinary: dc, CLIArgs: []string{"setup", "webhook", "disable"}, Description: "Disable a notifier webhook", Category: "setup", NeedsArg: true, ArgHint: "<name>"},
		{TUIName: "setup webhook remove", CLIBinary: dc, CLIArgs: []string{"setup", "webhook", "remove", "--yes"}, Description: "Remove a notifier webhook", Category: "setup", NeedsArg: true, ArgHint: "<name>"},
		{TUIName: "setup webhook test", CLIBinary: dc, CLIArgs: []string{"setup", "webhook", "test"}, Description: "Send/probe a notifier webhook", Category: "setup", NeedsArg: true, ArgHint: "<name>"},
		{TUIName: "setup provider add", CLIBinary: dc, CLIArgs: []string{"setup", "provider", "add"}, Description: "Add a custom LLM provider to the overlay", Category: "setup"},
		{TUIName: "setup provider remove", CLIBinary: dc, CLIArgs: []string{"setup", "provider", "remove"}, Description: "Remove a custom LLM provider from the overlay", Category: "setup"},
		{TUIName: "setup provider list", CLIBinary: dc, CLIArgs: []string{"setup", "provider", "list"}, Description: "List overlay provider entries", Category: "setup"},
		{TUIName: "setup provider show", CLIBinary: dc, CLIArgs: []string{"setup", "provider", "show"}, Description: "Show merged provider registry", Category: "setup"},

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
		{TUIName: "set mcp", CLIBinary: dc, CLIArgs: []string{"mcp", "set"}, Description: "Scan + set MCP server in the active connector's config", Category: "enforce", NeedsArg: true, ArgHint: "<url>"},
		{TUIName: "unset mcp", CLIBinary: dc, CLIArgs: []string{"mcp", "unset"}, Description: "Unset MCP server from the active connector's config", Category: "enforce", NeedsArg: true, ArgHint: "<url>"},

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
		{TUIName: "doctor run", CLIBinary: dc, CLIArgs: []string{"doctor"}, Description: "Run health checks", Category: "info"},
		{TUIName: "doctor --fix", CLIBinary: dc, CLIArgs: []string{"doctor", "--fix", "--yes"}, Description: "Auto-repair safe health issues", Category: "info"},
		{TUIName: "config validate", CLIBinary: dc, CLIArgs: []string{"config", "validate"}, Description: "Validate config.yaml", Category: "info"},
		{TUIName: "config show", CLIBinary: dc, CLIArgs: []string{"config", "show"}, Description: "Show resolved config with secrets masked", Category: "info"},
		{TUIName: "config path", CLIBinary: dc, CLIArgs: []string{"config", "path"}, Description: "Show DefenseClaw filesystem paths", Category: "info"},
		{TUIName: "keys list", CLIBinary: dc, CLIArgs: []string{"keys", "list"}, Description: "List configured and missing credentials", Category: "info"},
		{TUIName: "keys check", CLIBinary: dc, CLIArgs: []string{"keys", "check"}, Description: "Fail if required credentials are missing", Category: "info"},
		{TUIName: "keys set", CLIBinary: dc, CLIArgs: []string{"keys", "set"}, Description: "Persist a credential to the DefenseClaw .env", Category: "setup", NeedsArg: true, ArgHint: "<ENV_NAME> --value <secret>"},
		{TUIName: "keys fill-missing", CLIBinary: dc, CLIArgs: []string{"keys", "fill-missing"}, Description: "Prompt for missing required credentials", Category: "setup"},
		{TUIName: "settings save", CLIBinary: dc, CLIArgs: []string{"settings", "save"}, Description: "Persist current settings/config", Category: "setup"},
		{TUIName: "guardrail status", CLIBinary: dc, CLIArgs: []string{"guardrail", "status"}, Description: "Show guardrail status", Category: "info"},
		{TUIName: "guardrail enable", CLIBinary: dc, CLIArgs: []string{"guardrail", "enable", "--yes"}, Description: "Enable guardrail", Category: "setup"},
		{TUIName: "guardrail disable", CLIBinary: dc, CLIArgs: []string{"guardrail", "disable", "--yes"}, Description: "Disable guardrail", Category: "setup"},
		{TUIName: "version", CLIBinary: dc, CLIArgs: []string{"version"}, Description: "Show DefenseClaw version information", Category: "info"},

		// Daemon
		{TUIName: "start", CLIBinary: gw, CLIArgs: []string{"start"}, Description: "Start gateway sidecar", Category: "daemon"},
		{TUIName: "stop", CLIBinary: gw, CLIArgs: []string{"stop"}, Description: "Stop gateway sidecar", Category: "daemon"},
		{TUIName: "restart", CLIBinary: gw, CLIArgs: []string{"restart"}, Description: "Restart gateway sidecar", Category: "daemon"},
		{TUIName: "gateway status", CLIBinary: gw, CLIArgs: []string{"status"}, Description: "Show gateway health", Category: "daemon"},
		{TUIName: "watchdog start", CLIBinary: gw, CLIArgs: []string{"watchdog", "start"}, Description: "Start health watchdog", Category: "daemon"},
		{TUIName: "watchdog stop", CLIBinary: gw, CLIArgs: []string{"watchdog", "stop"}, Description: "Stop health watchdog", Category: "daemon"},
		{TUIName: "watchdog status", CLIBinary: gw, CLIArgs: []string{"watchdog", "status"}, Description: "Show watchdog status", Category: "daemon"},
		{TUIName: "connector verify", CLIBinary: gw, CLIArgs: []string{"connector", "verify"}, Description: "Verify connector config is clean/current", Category: "daemon"},
		{TUIName: "connector teardown", CLIBinary: gw, CLIArgs: []string{"connector", "teardown"}, Description: "Remove active connector config patches", Category: "daemon"},
		{TUIName: "connector list-backups", CLIBinary: gw, CLIArgs: []string{"connector", "list-backups"}, Description: "List connector backup files", Category: "daemon"},
		{TUIName: "gateway audit export", CLIBinary: gw, CLIArgs: []string{"audit", "export"}, Description: "Export gateway audit log", Category: "info"},
		{TUIName: "gateway provenance show", CLIBinary: gw, CLIArgs: []string{"provenance", "show"}, Description: "Show gateway binary/config provenance", Category: "info"},

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
		{TUIName: "uninstall dry-run", CLIBinary: dc, CLIArgs: []string{"uninstall", "--dry-run"}, Description: "Preview uninstall changes without modifying the system", Category: "other"},
		{TUIName: "uninstall --yes", CLIBinary: dc, CLIArgs: []string{"uninstall", "--yes"}, Description: "Uninstall DefenseClaw after showing the plan", Category: "other"},
		{TUIName: "uninstall --all --yes", CLIBinary: dc, CLIArgs: []string{"uninstall", "--all", "--yes"}, Description: "Uninstall DefenseClaw and wipe local data", Category: "other"},
		{TUIName: "reset --yes", CLIBinary: dc, CLIArgs: []string{"reset", "--yes"}, Description: "Wipe DefenseClaw local data and keep binaries", Category: "other"},

		// Aliases (noun-first forms)
		{TUIName: "setup", CLIBinary: dc, CLIArgs: []string{"setup"}, Description: "Show setup command help", Category: "setup"},
		{TUIName: "setup local-observability", CLIBinary: dc, CLIArgs: []string{"setup", "local-observability"}, Description: "Show local observability commands", Category: "setup"},
		{TUIName: "setup observability", CLIBinary: dc, CLIArgs: []string{"setup", "observability"}, Description: "Show observability sink commands", Category: "setup"},
		{TUIName: "setup provider", CLIBinary: dc, CLIArgs: []string{"setup", "provider"}, Description: "Show provider registry commands", Category: "setup"},
		{TUIName: "setup webhook", CLIBinary: dc, CLIArgs: []string{"setup", "webhook"}, Description: "Show webhook commands", Category: "setup"},
		{TUIName: "skill", CLIBinary: dc, CLIArgs: []string{"skill"}, Description: "Show skill commands", Category: "info"},
		{TUIName: "skill list", CLIBinary: dc, CLIArgs: []string{"skill", "list"}, Description: "List skills with scan status", Category: "info"},
		{TUIName: "skill search", CLIBinary: dc, CLIArgs: []string{"skill", "search"}, Description: "Search available skills", Category: "info", NeedsArg: true, ArgHint: "<query>"},
		{TUIName: "skill scan", CLIBinary: dc, CLIArgs: []string{"skill", "scan"}, Description: "Scan a skill", Category: "scan", NeedsArg: true, ArgHint: "<skill-name>"},
		{TUIName: "skill info", CLIBinary: dc, CLIArgs: []string{"skill", "info"}, Description: "Show skill details", Category: "info", NeedsArg: true, ArgHint: "<skill-name>"},
		{TUIName: "skill allow", CLIBinary: dc, CLIArgs: []string{"skill", "allow"}, Description: "Allow-list a skill", Category: "enforce", NeedsArg: true, ArgHint: "<skill-name>"},
		{TUIName: "skill block", CLIBinary: dc, CLIArgs: []string{"skill", "block"}, Description: "Block a skill", Category: "enforce", NeedsArg: true, ArgHint: "<skill-name>"},
		{TUIName: "skill disable", CLIBinary: dc, CLIArgs: []string{"skill", "disable"}, Description: "Disable a skill at runtime", Category: "enforce", NeedsArg: true, ArgHint: "<skill-name>"},
		{TUIName: "skill enable", CLIBinary: dc, CLIArgs: []string{"skill", "enable"}, Description: "Enable a skill at runtime", Category: "enforce", NeedsArg: true, ArgHint: "<skill-name>"},
		{TUIName: "skill install", CLIBinary: dc, CLIArgs: []string{"skill", "install"}, Description: "Install a skill from ClawHub", Category: "install", NeedsArg: true, ArgHint: "<skill-name>"},
		{TUIName: "skill quarantine", CLIBinary: dc, CLIArgs: []string{"skill", "quarantine"}, Description: "Quarantine a skill", Category: "enforce", NeedsArg: true, ArgHint: "<skill-name>"},
		{TUIName: "skill restore", CLIBinary: dc, CLIArgs: []string{"skill", "restore"}, Description: "Restore a quarantined skill", Category: "enforce", NeedsArg: true, ArgHint: "<skill-name>"},
		{TUIName: "skill unblock", CLIBinary: dc, CLIArgs: []string{"skill", "unblock"}, Description: "Unblock a skill", Category: "enforce", NeedsArg: true, ArgHint: "<skill-name>"},
		{TUIName: "mcp", CLIBinary: dc, CLIArgs: []string{"mcp"}, Description: "Show MCP commands", Category: "info"},
		{TUIName: "mcp list", CLIBinary: dc, CLIArgs: []string{"mcp", "list"}, Description: "List MCP servers with status", Category: "info"},
		{TUIName: "mcp scan", CLIBinary: dc, CLIArgs: []string{"mcp", "scan"}, Description: "Scan an MCP server", Category: "scan", NeedsArg: true, ArgHint: "<url>"},
		{TUIName: "mcp allow", CLIBinary: dc, CLIArgs: []string{"mcp", "allow"}, Description: "Allow-list an MCP server", Category: "enforce", NeedsArg: true, ArgHint: "<url>"},
		{TUIName: "mcp block", CLIBinary: dc, CLIArgs: []string{"mcp", "block"}, Description: "Block an MCP server", Category: "enforce", NeedsArg: true, ArgHint: "<url>"},
		{TUIName: "mcp set", CLIBinary: dc, CLIArgs: []string{"mcp", "set"}, Description: "Scan + set MCP server in the active connector's config", Category: "enforce", NeedsArg: true, ArgHint: "<name> [--url <url>]"},
		{TUIName: "mcp unblock", CLIBinary: dc, CLIArgs: []string{"mcp", "unblock"}, Description: "Unblock an MCP server", Category: "enforce", NeedsArg: true, ArgHint: "<url>"},
		{TUIName: "mcp unset", CLIBinary: dc, CLIArgs: []string{"mcp", "unset"}, Description: "Unset MCP server from the active connector's config", Category: "enforce", NeedsArg: true, ArgHint: "<name-or-url>"},
		{TUIName: "plugin", CLIBinary: dc, CLIArgs: []string{"plugin"}, Description: "Show plugin commands", Category: "info"},
		{TUIName: "plugin list", CLIBinary: dc, CLIArgs: []string{"plugin", "list"}, Description: "List installed plugins", Category: "info"},
		{TUIName: "plugin scan", CLIBinary: dc, CLIArgs: []string{"plugin", "scan"}, Description: "Scan a plugin", Category: "scan", NeedsArg: true, ArgHint: "<plugin-name>"},
		{TUIName: "plugin info", CLIBinary: dc, CLIArgs: []string{"plugin", "info"}, Description: "Show plugin details", Category: "info", NeedsArg: true, ArgHint: "<plugin-name>"},
		{TUIName: "plugin allow", CLIBinary: dc, CLIArgs: []string{"plugin", "allow"}, Description: "Allow-list a plugin", Category: "enforce", NeedsArg: true, ArgHint: "<plugin-name>"},
		{TUIName: "plugin block", CLIBinary: dc, CLIArgs: []string{"plugin", "block"}, Description: "Block a plugin", Category: "enforce", NeedsArg: true, ArgHint: "<plugin-name>"},
		{TUIName: "plugin disable", CLIBinary: dc, CLIArgs: []string{"plugin", "disable"}, Description: "Disable a plugin at runtime", Category: "enforce", NeedsArg: true, ArgHint: "<plugin-name>"},
		{TUIName: "plugin enable", CLIBinary: dc, CLIArgs: []string{"plugin", "enable"}, Description: "Enable a plugin at runtime", Category: "enforce", NeedsArg: true, ArgHint: "<plugin-name>"},
		{TUIName: "plugin install", CLIBinary: dc, CLIArgs: []string{"plugin", "install"}, Description: "Install a plugin", Category: "install", NeedsArg: true, ArgHint: "<plugin-name>"},
		{TUIName: "plugin quarantine", CLIBinary: dc, CLIArgs: []string{"plugin", "quarantine"}, Description: "Quarantine a plugin", Category: "enforce", NeedsArg: true, ArgHint: "<plugin-name>"},
		{TUIName: "plugin remove", CLIBinary: dc, CLIArgs: []string{"plugin", "remove"}, Description: "Remove a plugin", Category: "enforce", NeedsArg: true, ArgHint: "<plugin-name>"},
		{TUIName: "plugin restore", CLIBinary: dc, CLIArgs: []string{"plugin", "restore"}, Description: "Restore a quarantined plugin", Category: "enforce", NeedsArg: true, ArgHint: "<plugin-name>"},
		{TUIName: "tool", CLIBinary: dc, CLIArgs: []string{"tool"}, Description: "Show tool commands", Category: "info"},
		{TUIName: "tool list", CLIBinary: dc, CLIArgs: []string{"tool", "list"}, Description: "List tool rules", Category: "info"},
		{TUIName: "tool allow", CLIBinary: dc, CLIArgs: []string{"tool", "allow"}, Description: "Allow-list a tool", Category: "enforce", NeedsArg: true, ArgHint: "<tool-name>"},
		{TUIName: "tool block", CLIBinary: dc, CLIArgs: []string{"tool", "block"}, Description: "Block a tool", Category: "enforce", NeedsArg: true, ArgHint: "<tool-name>"},
		{TUIName: "tool unblock", CLIBinary: dc, CLIArgs: []string{"tool", "unblock"}, Description: "Unblock a tool", Category: "enforce", NeedsArg: true, ArgHint: "<tool-name>"},
		{TUIName: "policy", CLIBinary: dc, CLIArgs: []string{"policy"}, Description: "Show policy commands", Category: "policy"},
		{TUIName: "policy edit", CLIBinary: dc, CLIArgs: []string{"policy", "edit"}, Description: "Show policy edit commands", Category: "policy"},
		{TUIName: "keys", CLIBinary: dc, CLIArgs: []string{"keys"}, Description: "Show credential commands", Category: "info"},
		{TUIName: "config", CLIBinary: dc, CLIArgs: []string{"config"}, Description: "Show config commands", Category: "info"},
		{TUIName: "guardrail", CLIBinary: dc, CLIArgs: []string{"guardrail"}, Description: "Show guardrail commands", Category: "info"},
		{TUIName: "settings", CLIBinary: dc, CLIArgs: []string{"settings"}, Description: "Show settings commands", Category: "setup"},
		{TUIName: "audit", CLIBinary: dc, CLIArgs: []string{"audit"}, Description: "Show audit commands", Category: "info"},
		{TUIName: "codeguard", CLIBinary: dc, CLIArgs: []string{"codeguard"}, Description: "Show CodeGuard commands", Category: "install"},
		{TUIName: "codeguard install-skill", CLIBinary: dc, CLIArgs: []string{"codeguard", "install-skill"}, Description: "Install CodeGuard skill", Category: "install"},
		{TUIName: "aibom", CLIBinary: dc, CLIArgs: []string{"aibom"}, Description: "Show AIBOM commands", Category: "scan"},
		{TUIName: "sandbox", CLIBinary: dc, CLIArgs: []string{"sandbox"}, Description: "Show sandbox commands", Category: "sandbox"},
		{TUIName: "reset", CLIBinary: dc, CLIArgs: []string{"reset"}, Description: "Run interactive local data reset", Category: "other"},
		{TUIName: "uninstall", CLIBinary: dc, CLIArgs: []string{"uninstall"}, Description: "Run interactive uninstall flow", Category: "other"},
		{TUIName: "skills", CLIBinary: dc, CLIArgs: []string{"skill", "list"}, Description: "List skills", Category: "info"},
		{TUIName: "mcps", CLIBinary: dc, CLIArgs: []string{"mcp", "list"}, Description: "List MCP servers", Category: "info"},
		{TUIName: "plugins", CLIBinary: dc, CLIArgs: []string{"plugin", "list"}, Description: "List plugins", Category: "info"},
		{TUIName: "tools", CLIBinary: dc, CLIArgs: []string{"tool", "list"}, Description: "List tools", Category: "info"},
		{TUIName: "alerts", CLIBinary: dc, CLIArgs: []string{"alerts", "--no-tui"}, Description: "List alerts", Category: "info"},
		{TUIName: "alerts acknowledge", CLIBinary: dc, CLIArgs: []string{"alerts", "acknowledge"}, Description: "Acknowledge alerts by severity", Category: "enforce", NeedsArg: true, ArgHint: "--severity HIGH"},
		{TUIName: "alerts dismiss", CLIBinary: dc, CLIArgs: []string{"alerts", "dismiss"}, Description: "Dismiss alerts by severity", Category: "enforce", NeedsArg: true, ArgHint: "--severity HIGH"},
		{TUIName: "audit log-activity", CLIBinary: dc, CLIArgs: []string{"audit", "log-activity"}, Description: "Log operator activity (payload via --payload-file)", Category: "other", NeedsArg: true, ArgHint: "--payload-file <path>"},
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
