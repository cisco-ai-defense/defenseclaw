// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package hookguard supplies the per-user Windows Claude Code launcher guard
// and the Cowork account plugin guard. It runs DefenseClaw's hook launcher
// with the Claude Code hook argv and blocks when the launcher is missing or
// cannot start, with a sentence that says which. Claude Code treats
// a failed start of a hook command as a non-blocking error, so a launcher
// that antivirus removed let tool calls run uninspected (GAP-1011). The
// package uses only the standard library and, on Windows,
// golang.org/x/sys/windows to read an owner and a DACL: defenseclaw-hook-guard.exe, the
// one-line install's guard, is built from it alone and stays small, and the
// native hook and the gateway answer the same argv through it.
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
// exit code through. When the launcher cannot run it returns 2, which Claude
// Code treats as a block, and prints MissingMessage when nothing is at the
// launcher path and CannotStartMessage otherwise.
func Run(launcher string, hookArgs []string, stdin io.Reader, stdout, stderr io.Writer) int {
	code, _ := run(launcher, hookArgs, stdin, stdout, stderr)
	return code
}

// run is Run that also reports whether the launcher started.
func run(launcher string, hookArgs []string, stdin io.Reader, stdout, stderr io.Writer) (int, bool) {
	command := exec.Command(launcher, hookArgs...)
	command.Stdin, command.Stdout, command.Stderr = stdin, stdout, stderr
	err := command.Run()
	if err == nil {
		return 0, true
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() >= 0 {
		return exitErr.ExitCode(), true
	}
	if _, statErr := os.Lstat(launcher); errors.Is(statErr, fs.ErrNotExist) {
		fmt.Fprintln(stderr, MissingMessage)
	} else {
		fmt.Fprintln(stderr, CannotStartMessage)
	}
	return 2, false
}
