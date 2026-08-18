// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import "os"

func launcherWorkingDirectories(_ string) (logical, process string, err error) {
	cwd, err := os.Getwd()
	return cwd, cwd, err
}
