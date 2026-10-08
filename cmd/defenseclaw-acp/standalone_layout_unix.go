//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"runtime"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

var managedACPStandaloneLayout = func() (managed.StandaloneLayout, error) {
	return managed.StandaloneLayoutFor(runtime.GOOS)
}
