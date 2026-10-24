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

// defenseclaw-hook is the native hook/notification entrypoint. On Windows,
// release builds link it with -H=windowsgui so graphical agent applications
// can invoke DefenseClaw synchronously without Windows allocating a transient
// console. On Linux and macOS it is the administrator-owned binary that
// standalone managed deployments register (hook --connector X
// --enterprise-managed): it runs as the agent's user, trusts only the
// root-owned runtime descriptor, and verifies the gateway's uid before
// sending a byte.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	// Its init raises a Windows hook process to above-normal priority
	// before the CLI packages initialize (GAP-0155).
	_ "github.com/defenseclaw/defenseclaw/cmd/defenseclaw-hook/internal/hookpriority"
	"github.com/defenseclaw/defenseclaw/internal/cli"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	// Identity inspection must not depend on mutable per-user hook state. Setup
	// invokes this exact mode before signing and after installation so archived
	// hook bytes are bound to the payload manifest's source commit.
	// A person checking the hook binary types --version (GAP-1415).
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		useParentConsoleForStdout()
		fmt.Printf("defenseclaw-hook version %s (commit=%s, built=%s)\n", version, commit, date)
		return
	}
	if isIdentityEntrypoint(os.Args[1:]) {
		useParentConsoleForStdout()
		if err := writeMachineIdentity(os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "defenseclaw-hook: write identity: %v\n", err)
			os.Exit(1)
		}
		return
	}
	// The stable Windows launcher survives uninstall because agent clients may
	// cache its absolute command for the lifetime of their process. Disabled,
	// publishing, missing, or unsafe installer state is an intentional no-op;
	// check it before parsing project-inherited environment or fail-mode flags.
	if cli.NativeHookRuntimeNoop() {
		os.Exit(0)
	}
	// Hermes v0.19 keeps registered callbacks in memory until its host is
	// restarted. A connector-scoped disabled tombstone lets an already-running
	// Hermes process safely call the exact cached native command after teardown
	// without disabling any other connector that shares this launcher.
	if cli.NativeConnectorHookNoop(os.Args[1:]) {
		os.Exit(0)
	}
	if !isHookEntrypoint(os.Args[1:]) {
		os.Exit(nonHookInvocationExit(os.Args[1:], os.Stdin, os.Stderr))
	}
	cli.SetVersion(version)
	cli.SetBuildInfo(commit, date)
	os.Exit(cli.Execute())
}

// nonHookInvocationExit answers a start without a hook subcommand. Cursor
// imports the hooks in ~/.claude/settings.json (its third-party hooks, on by
// default) and runs only each handler's command, without the handler's args.
// For a Windows exec-form Claude Code handler that is this launcher with no
// arguments and a Cursor event on stdin. Its exit 2 made Cursor block every
// tool call, also with no Cursor hooks set up (GAP-1011). That call is no
// Claude Code event, so it gets no answer (exit 0, no output); Cursor's own
// DefenseClaw hooks, when set up, decide its events. Any other start without
// a subcommand is still refused with exit 2.
func nonHookInvocationExit(args []string, stdin *os.File, stderr io.Writer) int {
	if len(args) == 0 && stdinIsPiped(stdin) && isCursorEvent(stdin) {
		return 0
	}
	fmt.Fprintln(stderr, "defenseclaw-hook: expected hook, hook-post or notify subcommand")
	return 2
}

// stdinIsPiped is false for a console or terminal, where a person who typed
// the command would otherwise wait on a read.
func stdinIsPiped(stdin *os.File) bool {
	if stdin == nil {
		return false
	}
	info, err := stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice == 0
}

// isCursorEvent reports whether r holds one JSON object with a top-level
// cursor_version string, the marker of every Cursor hook event (the same
// marker hookexec reads for an imported Claude Code call). The object is read
// as a stream, value by value, so a large tool input is not held whole.
func isCursorEvent(r io.Reader) bool {
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

func isHookEntrypoint(args []string) bool {
	return len(args) > 0 && (args[0] == "hook" || args[0] == "hook-post" || args[0] == "notify")
}

func isIdentityEntrypoint(args []string) bool {
	return len(args) == 1 && args[0] == "--version-json"
}

func writeMachineIdentity(w io.Writer) error {
	return json.NewEncoder(w).Encode(struct {
		SchemaVersion int    `json:"schema_version"`
		Name          string `json:"name"`
		Version       string `json:"version"`
		Commit        string `json:"commit"`
		Built         string `json:"built,omitempty"`
	}{
		SchemaVersion: 1,
		Name:          "defenseclaw-hook",
		Version:       version,
		Commit:        commit,
		Built:         date,
	})
}
