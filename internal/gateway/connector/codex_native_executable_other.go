// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin

package connector

func validateCodexNativeExecutablePlatform(string) error {
	return nil
}
