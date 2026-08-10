// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"errors"
	"runtime"
)

// requireSupportedPlatform gates the binary to Windows. On ARM64 hosts the
// amd64 build runs under x64 emulation and reports GOARCH=amd64, so a strict
// amd64 check here would still let ARM64 through — which matches the AVC
// contract. When a native ARM64 build lands later this file swaps to a build
// tag rather than a runtime branch.
func requireSupportedPlatform() error {
	if runtime.GOOS != "windows" {
		return errors.New("defenseclaw-mgr is only supported on Windows")
	}
	return nil
}
