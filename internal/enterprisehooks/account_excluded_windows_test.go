// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"path/filepath"
	"testing"
)

// The Windows bindings publish through the hook closure writer and read through
// the trusted policy reader; an untrusted directory is never "excluded".
func TestWindowsAccountExcludedMarkerBindings(t *testing.T) {
	stubOffRosterSeams(t)
	dir := filepath.Join(t.TempDir(), "hookruntime")
	files := windowsAccountExcludedMarkerIO()
	if err := publishAccountExcludedMarkers(dir, []string{excludedSIDOne}, files); err != nil {
		t.Fatal(err)
	}
	if got, err := accountExcludedMarkerPresent(dir, excludedSIDOne, files); err != nil || !got {
		t.Fatalf("published account: excluded=%t err=%v", got, err)
	}
	if got, err := accountExcludedMarkerPresent(dir, enrolledSIDOther, files); err != nil || got {
		t.Fatalf("account with no marker: excluded=%t err=%v", got, err)
	}
	windowsManagedPolicyDirTrustCheck = func(string) error { return errors.New("untrusted directory") }
	if got, err := accountExcludedMarkerPresent(dir, excludedSIDOne, files); err == nil || got {
		t.Fatalf("untrusted directory: excluded=%t err=%v", got, err)
	}
}
