// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package hookguard is the per-user Windows Claude Code PreToolUse launcher
// guard: it runs DefenseClaw's hook launcher with the Claude Code hook argv
// and blocks when the launcher is missing or cannot start. Claude Code treats
// a failed start of a hook command as a non-blocking error, so a launcher
// that antivirus removed let tool calls run uninspected (GAP-1011). The
// package uses only the standard library: defenseclaw-hook-guard.exe, the
// one-line install's guard, is built from it alone and stays small, and the
// native hook and the gateway answer the same argv through it.
package hookguard

import (
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
)

// Subcommand is the first argument of the guard argv.
const Subcommand = "launcher-guard"

// MissingMessage is the one sentence the guard prints when it blocks.
const MissingMessage = "DefenseClaw blocked this: its Claude Code hook launcher is missing. " +
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
	want := []string{"hook", "--connector", "claudecode"}
	if len(args) != 2+len(want) || args[0] != Subcommand ||
		!Guardable(args[1]) || !AbsoluteHookExecutable(args[1]) {
		return "", nil, false
	}
	for i, arg := range want {
		if args[2+i] != arg {
			return "", nil, false
		}
	}
	return args[1], append([]string(nil), want...), true
}

// Run runs launcher with hookArgs and passes its stdin, stdout, stderr and
// exit code through. When the launcher is missing or cannot start it prints
// MissingMessage and returns 2, which Claude Code treats as a block.
func Run(launcher string, hookArgs []string, stdin io.Reader, stdout, stderr io.Writer) int {
	command := exec.Command(launcher, hookArgs...)
	command.Stdin, command.Stdout, command.Stderr = stdin, stdout, stderr
	err := command.Run()
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() >= 0 {
		return exitErr.ExitCode()
	}
	fmt.Fprintln(stderr, MissingMessage)
	return 2
}
