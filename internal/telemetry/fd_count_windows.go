// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package telemetry

func countOpenFDs() int64 {
	return -1
}
