// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import "errors"

func runInteractiveWizard(_ options, _, _ string) (int, error) {
	return 1, errors.New("interactive setup wizard is Windows-only")
}
