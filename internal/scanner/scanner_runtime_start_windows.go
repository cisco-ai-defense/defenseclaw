// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package scanner

import (
	"os"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

var scannerRuntimeStartCheck = runtimeStartCheck{
	standalone: standaloneScannerRuntime,
	root:       func() (string, error) { return scannerRuntimeRoot() },
	lstat:      os.Lstat,
	trustTree:  managed.ValidateTrustedRuntimeCodeTree,
}
