//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import "fmt"

var enterpriseHookSIDProfilePath = func(string) (string, error) {
	return "", fmt.Errorf("SID-only targets are supported only on native Windows")
}

func enterpriseHooksNativePlatformPreflight() error { return nil }
