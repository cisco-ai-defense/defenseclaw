// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import "errors"

func probeSetupLaunchContext() (setupLaunchFacts, error) {
	return setupLaunchFacts{}, errors.New("Windows-only operation")
}

func showSetupLaunchContextFailure(_ error, _ bool) {}
