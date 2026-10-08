// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import "github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"

// The package tests run on hosts where users may have agents open; no test
// reads the real process table into a result.
func init() {
	windowsEnterpriseProcessSnapshot = func() ([]procprobe.Process, int, error) { return nil, 0, nil }
}
