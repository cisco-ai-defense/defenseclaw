// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import "github.com/defenseclaw/defenseclaw/internal/managed"

// runtimeRoot is <ProgramData>\Cisco\DefenseClaw-ScannerRuntime, which only
// LocalSystem and Administrators can write: the lifecycle unpacks the runtime
// there ("prepare"), and the gateway service runs it read-only.
func runtimeRoot() (string, error) {
	return managed.StandaloneWindowsScannerRuntimeDir()
}
