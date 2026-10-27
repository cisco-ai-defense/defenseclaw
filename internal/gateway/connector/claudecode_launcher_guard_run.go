// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// RunClaudeCodeLauncherGuard runs launcher with hookArgs and passes its stdin,
// stdout, stderr and exit code through, as the cmd.exe guard of the other
// Claude Code events does. When the launcher is missing or cannot start it
// prints the guard sentence and exits 2, which Claude Code treats as a block;
// a direct start of a missing launcher was a non-blocking error that let the
// tool call run unchecked.
func RunClaudeCodeLauncherGuard(launcher string, hookArgs []string, stdin io.Reader, stdout, stderr io.Writer) int {
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
	fmt.Fprintln(stderr, ClaudeCodeLauncherMissingMessage)
	return 2
}

// ClaudeCodeGatewayPreToolGuard answers a start of defenseclaw-gateway.exe as
// the one-line install's Windows Claude Code PreToolUse guard: the
// launcher-guard argv runs the launcher through RunClaudeCodeLauncherGuard,
// and on Windows a start without arguments and a Cursor event on stdin (Cursor
// runs an imported handler's command without its args, GAP-1011) gets no
// answer, exit 0. handled is false for every other start, which the gateway
// runs as before.
func ClaudeCodeGatewayPreToolGuard(goos string, args []string, stdin *os.File, stdout, stderr io.Writer) (code int, handled bool) {
	if launcher, hookArgs, ok := ClaudeCodeLauncherGuardArgv(args); ok {
		return RunClaudeCodeLauncherGuard(launcher, hookArgs, stdin, stdout, stderr), true
	}
	if goos == "windows" && len(args) == 0 && StdinIsPiped(stdin) && IsCursorHookEvent(stdin) {
		return 0, true
	}
	return 0, false
}

// StdinIsPiped reports a stdin that is a pipe or file, not a console.
func StdinIsPiped(stdin *os.File) bool {
	if stdin == nil {
		return false
	}
	info, err := stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice == 0
}

// IsCursorHookEvent reports whether r holds one JSON object with a top-level
// cursor_version string, the marker of every Cursor hook event (the same
// marker hookexec reads for an imported Claude Code call). The object is read
// as a stream, value by value, so a large tool input is not held whole.
func IsCursorHookEvent(r io.Reader) bool {
	decoder := json.NewDecoder(r)
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return false
	}
	found := false
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		if key, _ := token.(string); key == "cursor_version" {
			var value string
			if decoder.Decode(&value) != nil {
				return false
			}
			found = found || value != ""
			continue
		}
		if !skipJSONValue(decoder) {
			return false
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return false
	}
	return found
}

// skipJSONValue reads one JSON value token by token.
func skipJSONValue(decoder *json.Decoder) bool {
	depth := 0
	for {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		switch token {
		case json.Delim('{'), json.Delim('['):
			depth++
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
		if depth == 0 {
			return true
		}
	}
}
