//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0652 E4 and g582 review 6 S1: on standalone the hook guardian manifest
// folder repair asks the read-only refusal first, then stamps through
// managed.StampStandaloneTrustedObject, which judges the folder again on the
// handle it writes. A refused folder is not stamped at all. Secure Client
// keeps the base stamp.
func TestWindowsTargetsManifestParentStandaloneStampsThroughTheSameHandleRepair(t *testing.T) {
	for _, tc := range []struct {
		name       string
		standalone bool
		refusal    error
		wantSame   int
		wantBase   int
		wantErr    string
	}{
		{name: "standalone, trusted-only drift", standalone: true, wantSame: 1},
		{name: "standalone, refused before any stamp", standalone: true, refusal: errors.New("an untrusted principal can write or owns it"), wantErr: "was not repaired"},
		{name: "Secure Client keeps the base stamp", wantBase: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := validateWindowsTargetsManifestObject(dir, true); err == nil {
				t.Skip("temp directory already satisfies the AdminDirectory contract")
			}
			previousDrift, previousRefusal := windowsTargetsManifestRefusesContentDrift, windowsTargetsManifestParentRefusal
			previousBase, previousSame := windowsTargetsManifestProtect, windowsTargetsManifestStandaloneProtect
			t.Cleanup(func() {
				windowsTargetsManifestRefusesContentDrift, windowsTargetsManifestParentRefusal = previousDrift, previousRefusal
				windowsTargetsManifestProtect, windowsTargetsManifestStandaloneProtect = previousBase, previousSame
			})
			windowsTargetsManifestRefusesContentDrift = func() bool { return tc.standalone }
			windowsTargetsManifestParentRefusal = func(string, managed.ObjectKind) error { return tc.refusal }
			base, same := 0, 0
			windowsTargetsManifestProtect = func(string, bool) error { base++; return errors.New("stamped") }
			windowsTargetsManifestStandaloneProtect = func(string, bool) error { same++; return errors.New("stamped") }

			err := ensureWindowsTargetsManifestParentProtected(dir)

			if base != tc.wantBase || same != tc.wantSame {
				t.Fatalf("base stamps %d, same-handle stamps %d; want %d, %d", base, same, tc.wantBase, tc.wantSame)
			}
			if err == nil || (tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}
