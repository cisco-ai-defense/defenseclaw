// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin

package daemon

import "fmt"

func darwinProcessStartIdentity(pid int) (string, error) {
	return "", fmt.Errorf("daemon: Darwin process identity unavailable for pid %d", pid)
}

func darwinLegacyProcessStartIdentity(pid int) (string, error) {
	return "", fmt.Errorf("daemon: Darwin legacy process identity unavailable for pid %d", pid)
}

func processExecutableDarwin(pid int) (string, error) {
	return "", fmt.Errorf("daemon: Darwin executable identity unavailable for pid %d", pid)
}
