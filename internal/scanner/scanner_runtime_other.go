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
