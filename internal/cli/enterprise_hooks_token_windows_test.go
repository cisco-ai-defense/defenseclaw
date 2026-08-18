//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestAlignEnterpriseWindowsTokenOwnerRejectsReparseChainBeforeACLWrites(t *testing.T) {
	originalCheck := enterpriseWindowsReparseChainCheck
	originalWriter := enterpriseWindowsProtectionWriter
	t.Cleanup(func() {
		enterpriseWindowsReparseChainCheck = originalCheck
		enterpriseWindowsProtectionWriter = originalWriter
	})

	enterpriseWindowsReparseChainCheck = func(string) error {
		return errors.New("reparse point in path")
	}
	writes := 0
	enterpriseWindowsProtectionWriter = func(string, *windows.SID, bool) error {
		writes++
		return nil
	}

	err := alignEnterpriseWindowsTokenOwner(`C:\managed`, `C:\managed\hooks\.hook-claudecode.token`, "hook token")
	if err == nil || !strings.Contains(err.Error(), "reparse point") {
		t.Fatalf("alignEnterpriseWindowsTokenOwner error = %v, want reparse refusal", err)
	}
	if writes != 0 {
		t.Fatalf("ACL writes = %d, want zero before reparse-chain rejection", writes)
	}
}
