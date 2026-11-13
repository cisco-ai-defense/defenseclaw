// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv/hlinkmatrix"
)

// GAP-0293 regression corpus through the per-user reading: every row the
// matrix generates is held to its effect. A row that reaches the protected
// inode blocks (the identity check runs on every candidate of the word); a
// row on an ordinary name, a replaced name or a symlink entry allows.
func TestHLinkMatrixPerUserDecision(t *testing.T) {
	f := newShellWordFixture(t)
	var missed, falseBlock []string
	for _, row := range hlinkmatrix.Rows(f.names) {
		got := ActionCommandDecision(row.Command, f.project, f.home) != ""
		switch {
		case row.Protected() && !got:
			missed = append(missed, row.ID)
		case !row.Protected() && got:
			falseBlock = append(falseBlock, row.ID)
		}
	}
	sort.Strings(missed)
	sort.Strings(falseBlock)
	if len(missed) > 0 {
		t.Errorf("%d protected rows allowed: %s", len(missed), strings.Join(missed, ", "))
	}
	if len(falseBlock) > 0 {
		t.Errorf("%d benign rows blocked: %s", len(falseBlock), strings.Join(falseBlock, ", "))
	}
	t.Logf("rows=%d", len(hlinkmatrix.Rows(f.names)))
}
