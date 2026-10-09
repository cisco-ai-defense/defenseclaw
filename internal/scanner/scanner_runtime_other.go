// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package scanner

// resolveScannerRuntime keeps binary: the embedded scanner runtime ships
// only in the standalone Windows enterprise payload.
func resolveScannerRuntime(binary string, _ ...string) string {
	return binary
}

// scannerRuntimeProblem is nil: no other OS has a managed scanner runtime.
var scannerRuntimeProblem = func() error { return nil }

// managedScannerRuntimeHost is false: no other OS has a managed scanner
// runtime. Tests replace it.
var managedScannerRuntimeHost = func() bool { return false }
