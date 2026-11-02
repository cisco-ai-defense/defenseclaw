//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import "os"

func ownedLockPermCheck(path string, _ *os.File, info os.FileInfo) error {
	return otlpValidatePerm(path, info)
}
