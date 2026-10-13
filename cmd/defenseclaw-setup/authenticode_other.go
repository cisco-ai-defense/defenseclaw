// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import "errors"

func verifyEmbeddedAuthenticodeTrust(_ string) error {
	return errors.New("WinVerifyTrust is available only on Windows")
}
