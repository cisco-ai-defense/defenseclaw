// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import "time"

// Windows hooks cold-start the gateway natively under the hook runtime's own
// lock (hook_gateway_recovery_windows.go), so the shell hook path is unused.
const hookColdStartSupported = false

func acquireGatewayStartLock(string, time.Duration) (func(), error) { return func() {}, nil }

func liftHookResourceLimits() {}
