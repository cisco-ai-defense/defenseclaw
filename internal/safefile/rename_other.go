// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package safefile

import "os"

func replaceFile(source, destination string) error {
	return os.Rename(source, destination)
}
