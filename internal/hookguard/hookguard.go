// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package hookguard supplies the small per-user Windows Claude Code and
// Cowork launcher guards. It starts the installed hook directly and gives an
// event-specific answer when the launcher is unavailable or exits with a
// Windows exception status. Its direct form keeps ordinary child exits; the
// wrapped form shifts nonblocking exits so cmd.exe can distinguish a child
// result from a guard start failure. The guard uses only the standard library
// and, on Windows, owner and DACL checks from golang.org/x/sys/windows.
package hookguard

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Subcommand is the first argument of the guard argv.
const Subcommand = "launcher-guard"

// WrappedSubcommand marks a guard answer that a cmd.exe registration decodes.
// A child exit other than 0 or 2 is shifted out of the Win32 start-error range.
const WrappedSubcommand = "launcher-guard-wrapped"

const WrappedExitBase = 65536

// NeutralEvent reports a lifecycle event whose block would prolong a session
// or cannot stop a call. Keep this list equal to hookexec's Claude Code set.
func NeutralEvent(event string) bool {
	switch event {
	case "Stop", "SubagentStop", "TeammateIdle", "StopFailure", "SessionEnd":
		return true
	}
	return false
}

// NonBlockingExitMessage is shown when no launcher answer is available for
// a neutral event.
const NonBlockingExitMessage = "DefenseClaw could not check this Claude Code lifecycle event; run the DefenseClaw installer again to repair its hook launcher."

// MissingMessage is the sentence the guard prints when it blocks because
// nothing is at the launcher path. It is also the cmd.exe guard's sentence
// (one argument per word), which teardown recognizes: keep it unchanged.
const MissingMessage = "DefenseClaw blocked this: its Claude Code hook launcher is missing. " +
	"Run the DefenseClaw installer again to repair it."

// CannotStartMessage is the sentence the guard prints when it blocks because
// the launcher is there but Windows cannot start it: a damaged or partly
// written file, a folder, a file it may not run (cowork-1-0-8 GAP-0086).
const CannotStartMessage = "DefenseClaw blocked this: its Claude Code hook launcher cannot start. " +
	"Run the DefenseClaw installer again to repair it."

const hookBinaryName = "defenseclaw-hook.exe"

// Guardable reports whether cmd.exe reads path literally inside double
// quotes: it must not contain a quote, a variable sign or a line break.
func Guardable(path string) bool {
	return strings.TrimSpace(path) == path && path != "" &&
		!strings.ContainsAny(path, "\"%!\r\n")
}

// IsWindowsAbsolutePath reports a drive-absolute (C:\x, C:/x) or UNC path.
func IsWindowsAbsolutePath(path string) bool {
	if len(path) >= 3 && path[1] == ':' && (path[2] == '\\' || path[2] == '/') &&
		((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) {
		return true
	}
	normalized := strings.ReplaceAll(path, `/`, `\`)
	return strings.HasPrefix(normalized, `\\`) && len(strings.TrimPrefix(normalized, `\\`)) > 0
}

// AbsoluteHookExecutable reports an absolute path whose file name is
// defenseclaw-hook.exe.
func AbsoluteHookExecutable(path string) bool {
	if !IsWindowsAbsolutePath(path) && !filepath.IsAbs(path) {
		return false
	}
	return strings.EqualFold(path[strings.LastIndexAny(path, `\/`)+1:], hookBinaryName)
}

// Argv returns the launcher and hook argv the guard runs for args, its
// arguments after the program name. Only an absolute defenseclaw-hook.exe
// launcher with the per-user Claude Code hook argv is accepted, so the guard
// starts nothing but DefenseClaw's launcher.
func Argv(args []string) (launcher string, hookArgs []string, ok bool) {
	launcher, hookArgs, _, _, ok = ParseInvocation(args)
	return launcher, hookArgs, ok
}

// ParseInvocation accepts the released guard argv and the event-bound form.
// The latter lets the guard answer stop and session-end failures without
// depending on the order or size of fields in the hook's stdin JSON.
func ParseInvocation(args []string) (launcher string, hookArgs []string, event string, wrapped bool, ok bool) {
	want := []string{"hook", "--connector", "claudecode"}
	if len(args) != 2+len(want) && len(args) != 4+len(want) {
		return "", nil, "", false, false
	}
	if args[0] != Subcommand && args[0] != WrappedSubcommand ||
		!Guardable(args[1]) || !AbsoluteHookExecutable(args[1]) {
		return "", nil, "", false, false
	}
	for i, arg := range want {
		if args[2+i] != arg {
			return "", nil, "", false, false
		}
	}
	if len(args) == 4+len(want) {
		if args[5] != "--event" || !validEventName(args[6]) {
			return "", nil, "", false, false
		}
		event = args[6]
	} else if args[0] == WrappedSubcommand {
		return "", nil, "", false, false
	} else {
		event = "PreToolUse" // the released direct guard form
	}
	return args[1], append([]string(nil), want...), event, args[0] == WrappedSubcommand, true
}

func validEventName(event string) bool {
	if len(event) == 0 || len(event) > 64 {
		return false
	}
	for _, ch := range event {
		if !('A' <= ch && ch <= 'Z' || 'a' <= ch && ch <= 'z' || '0' <= ch && ch <= '9') {
			return false
		}
	}
	return true
}

// Run runs launcher with hookArgs and passes its stdin, stdout, stderr and
// exit code through. When the launcher cannot run it returns 2, which Claude
// Code treats as a block, and prints MissingMessage when nothing is at the
// launcher path and CannotStartMessage otherwise.
func Run(launcher string, hookArgs []string, stdin io.Reader, stdout, stderr io.Writer) int {
	code, _ := run(launcher, hookArgs, "PreToolUse", stdin, stdout, stderr)
	return code
}

// RunEvent runs one registered event. Wrapped answers encode ordinary child
// error exits so cmd.exe can distinguish them from a guard start failure.
func RunEvent(launcher string, hookArgs []string, event string, wrapped bool, stdin io.Reader, stdout, stderr io.Writer) int {
	code, _ := run(launcher, hookArgs, event, stdin, stdout, stderr)
	if wrapped && code != 0 && code != 2 {
		if code < 0 || code >= WrappedExitBase {
			code = 1
		}
		return WrappedExitBase + code
	}
	return code
}

// ExceptionStatus identifies a child that started but ended with a Windows
// exception or loader status rather than an ordinary hook exit code.
func ExceptionStatus(code int) bool { return code < 0 || uint32(code) >= 0x80000000 }

// run is Run that also reports whether the launcher started.
func run(launcher string, hookArgs []string, event string, stdin io.Reader, stdout, stderr io.Writer) (int, bool) {
	command := exec.Command(launcher, hookArgs...)
	command.Stdin, command.Stdout, command.Stderr = stdin, stdout, stderr
	err := command.Run()
	if err == nil {
		return 0, true
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code := exitErr.ExitCode()
		if !ExceptionStatus(code) {
			if NeutralEvent(event) && code == 2 {
				fmt.Fprintln(stderr, NonBlockingExitMessage)
				return 1, true
			}
			return code, true
		}
	}
	if NeutralEvent(event) {
		fmt.Fprintln(stderr, NonBlockingExitMessage)
		return 1, false
	}
	if _, statErr := os.Lstat(launcher); errors.Is(statErr, fs.ErrNotExist) {
		fmt.Fprintln(stderr, MissingMessage)
	} else {
		fmt.Fprintln(stderr, CannotStartMessage)
	}
	return 2, false
}
