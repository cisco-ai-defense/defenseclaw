// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"path/filepath"
	"testing"
)

func TestSecureClientDoesNotPreSkipMacOSPrivacyFolder(t *testing.T) {
	oldOS, oldFDA := discoveryGOOS, macOSFullDiskAccess
	t.Cleanup(func() { discoveryGOOS, macOSFullDiskAccess = oldOS, oldFDA })
	discoveryGOOS = "darwin"
	macOSFullDiskAccess = func() bool { return false }
	home := t.TempDir()
	svc := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{HomeDir: home, SecureClient: true}}
	if svc.macOSTCCSkipped(filepath.Join(home, "Documents")) {
		t.Fatal("Secure Client pre-skipped a readable folder")
	}
}
