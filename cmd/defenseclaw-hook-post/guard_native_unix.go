// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"io"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/hookuser"
)

// guardStartedAt is when the call started: this process's start, as for
// defenseclaw-hook-user; a test replaces it.
var guardStartedAt = hookexec.ProcessStartTime

// runNativeUserHook is the native Claude Code hook of a checked guard
// command line. native is the defenseclaw-hook-user beside this executable:
// the path hook-user itself resolves for the account's trusted gateway.
func runNativeUserHook(self, home, addr string, input io.Reader, output, errOutput io.Writer) int {
	native := filepath.Join(filepath.Dir(self), "defenseclaw-hook-user")
	return hookuser.Run(native, home, addr, input, output, errOutput, guardStartedAt())
}

func stopNativeHookLooks() { hookuser.StopOutageLooks() }

// registeredNativeArgs checks the native hook's part of a guard command line
// as defenseclaw-hook-user does (a loopback --api-addr, a clean home).
func registeredNativeArgs(args []string) (home, addr string, ok bool) {
	return hookuser.RegisteredArgs(args)
}
