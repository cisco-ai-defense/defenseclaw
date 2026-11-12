// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"strings"
	"testing"
)

// nativeWriteBlockedOverBound is nativeWriteBlocked for a call that may carry
// more operands than the call-wide bound (GAP-0943). Past the bound an
// ordinary call, whose names the full judgment finds to be no protected
// file, is allowed with the bound alert and no other finding in the default
// tier (the ruled tier outcome); that is no block. A block is read as before,
// and any other finding next to the bound alert is still a failure.
func nativeWriteBlockedOverBound(t *testing.T, got string, overBound bool) bool {
	t.Helper()
	var resp struct {
		Action   string   `json:"action"`
		Findings []string `json:"findings"`
	}
	if err := json.Unmarshal([]byte(got), &resp); err != nil {
		t.Fatalf("verdict %q: %v", got, err)
	}
	if overBound && resp.Action == "alert" && len(resp.Findings) > 0 {
		onlyBound := true
		for _, finding := range resp.Findings {
			onlyBound = onlyBound && strings.HasPrefix(finding, operandBoundRuleID+":")
		}
		if onlyBound {
			return false
		}
	}
	return nativeWriteBlocked(t, got)
}
