// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package useridentity

import (
	"testing"
	"time"
)

// A managed OpenCode call runs the session check and then the gateway hook
// inside a 3.5 s native answer budget. A slow ccache on the first call after
// idle may consume its own facts deadline at both stages (GAP-0744).
func TestSessionFactsDeadlineLeavesTheManagedHookAnswerBudget(t *testing.T) {
	if 2*sessionFactsDeadline >= 2*time.Second {
		t.Fatalf("two session-facts reads can take %s before gateway work; want under 2s", 2*sessionFactsDeadline)
	}
}
