// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// RecoverHookPanic is deferred by the hook entrypoints (defenseclaw-hook's
// main and the hook subcommand). It turns a panic into the hook's failure
// decision (hookexec.HookPanicExit) instead of Go's stack dump on stderr,
// which an agent would show the user as the block message.
func RecoverHookPanic() {
	if recovered := recover(); recovered != nil {
		os.Exit(hookPanicExit(os.Args[1:], recovered))
	}
}

// hookPanicExit reads the connector, event and managed flag straight from
// args: a panic may come before Cobra parsed them. A Codex notification is
// best-effort and exits 0 silently.
func hookPanicExit(args []string, recovered any) int {
	if len(args) > 0 && args[0] == "notify" {
		return 0
	}
	return hookexec.HookPanicExit(hookexec.Options{
		Connector:         strings.ToLower(strings.TrimSpace(hookPanicFlagValue(args, "--connector"))),
		Event:             hookPanicFlagValue(args, "--event"),
		ManagedEnterprise: hookPanicManagedFlag(args),
	}, recovered)
}

func hookPanicFlagValue(args []string, flag string) string {
	value := ""
	for index := 0; index < len(args); index++ {
		switch arg := args[index]; {
		case arg == flag && index+1 < len(args):
			index++
			value = args[index]
		case strings.HasPrefix(arg, flag+"="):
			value = strings.TrimPrefix(arg, flag+"=")
		}
	}
	return value
}

func hookPanicManagedFlag(args []string) bool {
	for _, arg := range args {
		if arg == "--enterprise-managed" || arg == "--enterprise-managed=true" {
			return true
		}
	}
	return false
}
