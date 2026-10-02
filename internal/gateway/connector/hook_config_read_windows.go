// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import "os"

func openHookConfigForRead(path string) (*os.File, error) {
	return os.Open(path)
}
