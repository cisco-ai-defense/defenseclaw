//go:build !windows && !darwin && !linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package policy

func installedPythonInterpreter() (string, error) {
	return "python3", nil
}
