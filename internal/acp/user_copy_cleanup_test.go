// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"fmt"
	"testing"
)

func TestEnterpriseUserCopyCleanupOverflowPreservesPendingEntries(t *testing.T) {
	dataDir := t.TempDir()
	next := make([]EnterpriseUserCopyCleanup, maxEnterpriseUserCopyCleanups+1)
	for i := range next {
		next[i] = EnterpriseUserCopyCleanup{SID: fmt.Sprintf("S-1-5-21-%d", i), ClientID: "zed", AgentID: "kiro"}
	}
	err := UpdateEnterpriseUserCopyCleanups(dataDir, func([]EnterpriseUserCopyCleanup) []EnterpriseUserCopyCleanup { return next })
	if err == nil {
		t.Fatal("overflow silently discarded an older cleanup obligation")
	}
	pending, err := EnterpriseUserCopyCleanups(dataDir)
	if err != nil || len(pending) != 0 {
		t.Fatalf("overflow changed the pending list: entries=%d err=%v", len(pending), err)
	}
}
