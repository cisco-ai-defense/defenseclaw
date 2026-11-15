// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"strings"
	"testing"
)

// TestBoundRuleSedBackupDepthCap: a shell or eval body the reader does not
// enter because of the depth cap sets unresolved, so the call is at least
// the unknown tier of the pack, and whatever the reader proved before the
// cap still blocks (rel-1-0-10:GAP-0738).
func TestBoundRuleSedBackupDepthCap(t *testing.T) {
	env, keys := sedBackupBoundEnv(t)
	const unresolved, block, allow = "unresolved", "block", "allow"
	var cases []struct{ id, command, want string }
	add := func(id, command, want string) {
		cases = append(cases, struct{ id, command, want string }{id, command, want})
	}
	edit := `sed -i{keys}/* s/x/y/ authorized_keys`
	for n := 1; n <= 12; n++ {
		want := block
		if n > 8 {
			want = unresolved
		}
		add(fmt.Sprintf("BND-eval-%02d", n), strings.Repeat("eval ", n)+edit, want)
		add(fmt.Sprintf("BND-eval-dyn-%02d", n), strings.Repeat("eval ", n)+`sed -i{keys}/* s/x/y/ "$X"`, unresolved)
	}
	// A call whose proven write comes before the capped part stays a block.
	add("BND-eval-seen-before", edit+"; "+strings.Repeat("eval ", 10)+"true", block)
	// Benign twins: shallow evals and plain calls are not changed.
	add("BND-benign-eval-3", strings.Repeat("eval ", 3)+"echo hi", allow)
	add("BND-benign-sed-bak", "sed -i.bak s/x/y/ f", allow)
	runSedBackupTierRows(t, env, keys, cases)
}
