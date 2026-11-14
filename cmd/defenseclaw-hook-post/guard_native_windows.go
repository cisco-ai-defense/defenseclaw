// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"fmt"
	"io"
)

// runNativeUserHook: Windows registers its own native hook
// (claudeCodeWindowsHookInvocation), never this Unix guard pair, and has no
// defenseclaw-hook-user; such a command line could not start, as before.
func runNativeUserHook(_, _, _ string, _ io.Reader, _, errOutput io.Writer) int {
	fmt.Fprintln(errOutput, "DefenseClaw hook could not start")
	return 2
}

func stopNativeHookLooks() {}

// registeredNativeArgs: no native hook on Windows; its guard cannot start.
func registeredNativeArgs(args []string) (home, addr string, ok bool) {
	if len(args) < 5 {
		return "", "", false
	}
	return args[4], "", true
}
