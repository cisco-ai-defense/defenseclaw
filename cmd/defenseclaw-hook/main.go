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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"

	// Its init raises a Windows hook process to above-normal priority
	// before the CLI packages initialize (GAP-0155).
	_ "github.com/defenseclaw/defenseclaw/cmd/internal/hookpriority"
	// Its init keeps the collector off until main starts (GAP-0050).
	"github.com/defenseclaw/defenseclaw/cmd/internal/initgc"
	"github.com/defenseclaw/defenseclaw/internal/cli"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/hookguard"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	initgc.Restore()
	// A panic anywhere in the hook path becomes the hook's failure decision
	// instead of a stack dump on the agent-visible stderr.
	defer cli.RecoverHookPanic()
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
	// An elevated hook (an elevated Claude Desktop runs Cowork's hooks)
	// creates hooks\.outage-warnings, its logs and markers as its user, so
	// the account without elevation can remove them (GAP-0063). Before the
	// launcher guard: the hook it starts inherits the owner.
	managed.UseCurrentUserAsWindowsDefaultOwner(os.Args[1:])
	// The per-user Windows Claude Code launcher guard. It runs before the
	// installer-state checks below: the launcher it starts applies them, and
	// a missing launcher must block whatever that state says.
	if launcher, hookArgs, event, wrapped, open, ok := hookguard.ParseInvocationMode(os.Args[1:]); ok {
		os.Exit(hookguard.RunEventMode(launcher, hookArgs, event, wrapped, open, os.Stdin, os.Stdout, os.Stderr))
	}
	if runtime.GOOS == "windows" {
		if dataDir, launcher, event, ok := hookguard.CoworkArgv(os.Args[1:]); ok {
			os.Exit(hookguard.RunCowork(dataDir, launcher, event, os.Stdin, os.Stdout, os.Stderr))
		}
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
		// Claude Code builds before exec-form args invoke the Unix managed
		// command without its configured arguments. Route their event through
		// the same managed hook command used by newer builds.
		if runtime.GOOS != "windows" && len(os.Args) == 1 && connector.StdinIsPiped(os.Stdin) {
			payload, err := io.ReadAll(io.LimitReader(os.Stdin, hookexec.DefaultMaxBody+1))
			if err == nil {
				if int64(len(payload)) > hookexec.DefaultMaxBody {
					// Cursor imports can carry larger tool inputs. Check the full
					// event as a stream without enlarging the managed hook body.
					if connector.IsCursorHookEvent(io.MultiReader(bytes.NewReader(payload), os.Stdin)) {
						os.Exit(0)
					}
				} else {
					switch classifyNoArgHook(payload) {
					case noArgCursor:
						os.Exit(0)
					case noArgClaude:
						if replay, replayErr := replayHookInput(payload); replayErr == nil {
							os.Stdin = replay
							os.Args = append(os.Args, "hook", "--connector", "claudecode", "--enterprise-managed")
						}
					}
				}
			}
			if !isHookEntrypoint(os.Args[1:]) {
				os.Exit(nonHookInvocationExit(os.Args[1:], nil, os.Stderr))
			}
		} else {
			os.Exit(nonHookInvocationExit(os.Args[1:], os.Stdin, os.Stderr))
		}
	}
	cli.SetVersion(version)
	cli.SetBuildInfo(commit, date)
	os.Exit(cli.Execute())
}

type noArgHookKind uint8

const (
	noArgOther noArgHookKind = iota
	noArgCursor
	noArgClaude
)

func classifyNoArgHook(payload []byte) noArgHookKind {
	if connector.IsCursorHookEvent(bytes.NewReader(payload)) {
		return noArgCursor
	}
	var event struct {
		Name          string          `json:"hook_event_name"`
		CursorVersion json.RawMessage `json:"cursor_version"`
	}
	if json.Unmarshal(payload, &event) != nil || len(event.CursorVersion) != 0 || event.Name == "" ||
		event.Name[0] < 'A' || event.Name[0] > 'Z' {
		return noArgOther
	}
	return noArgClaude
}

func replayHookInput(payload []byte) (*os.File, error) {
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	go func() {
		_, _ = writer.Write(payload)
		_ = writer.Close()
	}()
	return reader, nil
}

// nonHookInvocationExit answers a start without a hook subcommand. Cursor
// imports the hooks in ~/.claude/settings.json (its third-party hooks, on by
// default) and runs only each handler's command, without the handler's args.
// For a Windows Claude Code PreToolUse handler that is this binary (the
// guard, or the launcher of an exec-form handler) with no arguments and a
// Cursor event on stdin. Its exit 2 made Cursor block every
// tool call, also with no Cursor hooks set up (GAP-1011). That call is no
// Claude Code event, so it gets no answer (exit 0, no output); Cursor's own
// DefenseClaw hooks, when set up, decide its events. Any other start without
// a subcommand is refused with exit 2 unless it is a Unix Claude Code event,
// which main routes through the managed hook command before this function.
func nonHookInvocationExit(args []string, stdin *os.File, stderr io.Writer) int {
	if len(args) == 0 && connector.StdinIsPiped(stdin) && connector.IsCursorHookEvent(stdin) {
		return 0
	}
	fmt.Fprintln(stderr, "defenseclaw-hook: expected hook, hook-post or notify subcommand")
	return 2
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
