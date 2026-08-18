//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestEnterpriseHooksNativeMutationPreflightRequiresLocalSystem(t *testing.T) {
	previousGOOS := enterpriseHooksRuntimeGOOS
	enterpriseHooksRuntimeGOOS = func() string { return "windows" }
	t.Cleanup(func() { enterpriseHooksRuntimeGOOS = previousGOOS })

	user, tokenErr := windows.GetCurrentProcessToken().GetTokenUser()
	isSystem := tokenErr == nil && user != nil && user.User.Sid != nil &&
		user.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
	err := enterpriseHooksNativeMutationIdentityPreflight()
	if isSystem {
		if err != nil {
			t.Fatalf("LocalSystem mutation preflight = %v", err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), "LocalSystem guardian") {
		t.Fatalf("non-LocalSystem mutation preflight = %v", err)
	}
}
