// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"fmt"
	"testing"

	"golang.org/x/sys/windows"
)

// GAP-0217: a session nobody is signed in to is not the target's session;
// other token query errors still fail the lookup.
func TestWindowsSessionHasNoUserOnlyForNoToken(t *testing.T) {
	if !windowsSessionHasNoUser(fmt.Errorf("query: %w", windows.ERROR_NO_TOKEN)) {
		t.Fatal("ERROR_NO_TOKEN was not read as a session without a user")
	}
	for _, err := range []error{windows.ERROR_ACCESS_DENIED, windows.ERROR_PRIVILEGE_NOT_HELD, fmt.Errorf("other")} {
		if windowsSessionHasNoUser(err) {
			t.Fatalf("%v was read as a session without a user", err)
		}
	}
}
