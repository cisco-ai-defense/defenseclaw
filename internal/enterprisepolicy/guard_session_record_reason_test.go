// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// The hook retries the gateway's record-store denial by its exact words
// (GAP-1711), so the two must not drift apart.
func TestSessionRecordDenialIsTheReasonTheHookRetries(t *testing.T) {
	if got := sessionUnavailableDecision(GuardDecision{}).Reason; got != hookexec.ForeignHookSessionRecordUnavailableReason {
		t.Fatalf("session store denial %q is not the hook's retried reason %q", got, hookexec.ForeignHookSessionRecordUnavailableReason)
	}
}
