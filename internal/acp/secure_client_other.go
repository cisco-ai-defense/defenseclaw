//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"os"
	"runtime"
)

// secureClientHost reports a Secure Client DefenseClaw install, the same
// check the gateway CLI makes; Secure Client exists on macOS only. A seam
// for tests.
var secureClientHost = func() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	_, err := os.Stat("/opt/cisco/secureclient/defenseclaw")
	return err == nil
}
