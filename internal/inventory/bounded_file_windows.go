// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package inventory

import "os"

func openReadOnlyNonblocking(path string) (*boundedReadFile, error) {
	return os.Open(path)
}
