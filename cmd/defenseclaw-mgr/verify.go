// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import "errors"

// runVerify is the post-install self-test — Authenticode policy on every PE
// under bin/, layout under %ProgramFiles%\..., ACLs under %ProgramData%\...,
// and service registration. Mirrors the `/verify` action on
// DefenseClawSetup-x64.exe (cmd/defenseclaw-setup/main.go).
func runVerify(_ []string) (int, error) {
	return exitRetryable, errors.New("verify not yet implemented — port from cmd/defenseclaw-setup verifySetupExecutablePolicyAt")
}
