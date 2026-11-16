// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package hookpriority gives a Windows hook process the CPU it needs to
// answer a tool call within its answer budget. defenseclaw-hook and
// defenseclaw-gateway import it for its init, which runs before the heavy
// package initialization of the CLI: a hook call and a Claude Code launcher
// guard start run above normal priority. It does nothing on Linux and macOS, where an account cannot raise its
// own priority; there the lifecycle runs at nice 10 instead.
package hookpriority

// LauncherGuardSubcommand is connector.ClaudeCodeLauncherGuardSubcommand,
// spelled out because this package initializes before the CLI packages and
// must not import them.
const LauncherGuardSubcommand = "launcher-guard"
