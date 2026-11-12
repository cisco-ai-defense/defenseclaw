// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"strings"
	"testing"
)

// cowork-1-0-8 GAP-0095 round 2: the retry hints of the Windows-only lifecycle
// ask for "the same command" on the standalone profile and keep "run Setup
// again" for Secure Client.
func TestWindowsEnterpriseRetryHintsOfTheLifecycleNameNoSetupOnStandalone(t *testing.T) {
	t.Cleanup(func() { windowsEnterpriseRunStandalone.Store(false) })
	blocked := func() string {
		return newWindowsEnterpriseStagingBlockedPrereq("Windows enterprise installer staging", []string{`C:\ProgramData`}, errors.New("access denied")).Error()
	}
	windowsEnterpriseRunStandalone.Store(true)
	if got := blocked(); !strings.HasSuffix(strings.TrimSuffix(got, `"`), "then run the same command again") || strings.Contains(got, "Setup") {
		t.Errorf("standalone staging block = %q", got)
	}
	windowsEnterpriseRunStandalone.Store(false)
	if got := blocked(); !strings.HasSuffix(strings.TrimSuffix(got, `"`), "then run Setup again") {
		t.Errorf("Secure Client staging block = %q", got)
	}

	if strings.Contains(windowsScannerPrepareRetryNotice, "Setup") {
		t.Errorf("scanner prepare retry notice names Setup: %q", windowsScannerPrepareRetryNotice)
	}
}
