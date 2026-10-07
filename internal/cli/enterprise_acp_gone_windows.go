//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import "errors"

// enterpriseACPHomeForUID: --uid applies only on Linux and macOS.
var enterpriseACPHomeForUID = func(int) (string, bool, error) {
	return "", false, errors.New("--uid applies only on Linux and macOS")
}
