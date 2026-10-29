// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"context"
	"errors"
	"io"
	"time"
)

func loadTrustedEnterprisePayload() (enterprisePayload, error) {
	return loadEmbeddedEnterprisePayload()
}

func executeEnterpriseSetup(
	_ context.Context,
	_ enterpriseSetupOptions,
	_, _ io.Writer,
) (int, error) {
	return 0, errors.New("DefenseClaw enterprise Setup is supported only on native Windows x64")
}

func enterpriseSetupProcessStarted() time.Time {
	return enterpriseSetupInitTime
}

func runStandaloneSetupRecoveryWatchdog(string, io.Writer, io.Writer) int {
	return 1
}
