// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"fmt"
	"testing"
)

func TestIsWindowsTargetSessionUnavailableRequiresTypedCause(t *testing.T) {
	typed := &WindowsTargetSessionUnavailableError{
		SID: "S-1-5-21-1-2-3-1001",
	}
	if !IsWindowsTargetSessionUnavailable(fmt.Errorf("wrapped: %w", typed)) {
		t.Fatal("wrapped typed target-session absence was not recognized")
	}
	lookalike := fmt.Errorf("enterprise hooks: no active interactive session token matches explicit target SID S-1-5-21-1-2-3-1001; guardian will retry")
	if IsWindowsTargetSessionUnavailable(lookalike) {
		t.Fatal("message lookalike was downgraded to deferred session absence")
	}
}
