// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import "errors"

// requireSupportedPlatform refuses to run on non-Windows hosts. The build
// still succeeds off-Windows so `go vet ./...` and cross-compile checks work
// in CI.
func requireSupportedPlatform() error {
	return errors.New("defenseclaw-mgr is only supported on Windows")
}
