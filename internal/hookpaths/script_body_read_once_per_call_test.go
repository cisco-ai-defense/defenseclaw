// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A hook call whose command sources a script behind as many folder links as
// the system opens in one name reads the body once and walks the links of the
// name once. Every later rule and reading of the call that asks again (the
// write operands, the command decision and the state scan here, each with an
// evaluation memo of its own as the gateway makes them) takes the body the
// call read and the paths the call resolved. On Windows each ask walked the
// whole chain again, share check included: 26 reads of the body, a walk of
// the chain for each evaluation memo and 77 more for the state entry check,
// and a Codex call answered in 1.8 to 2.4 s of its 2.5 s window, in 8.7 s
// with one unreadable statement before it (rel-1-0-10:GAP-0447). The bar is a
// count of the share walk's component reads, so it holds whatever the load of
// the host: the first evaluation reads at least one component per link, and
// each evaluation after it fewer components than the chain has links. The
// answers are the same in every evaluation: the writer's protected target is
// found each time.
func TestScriptBodyBehindTheLinkBoundIsReadOncePerHookCall(t *testing.T) {
	// The call's memory of the file system is on by default only on Windows
	// (memoReads); the count is the one of a Windows call on every host.
	previous := memoReads
	memoReads = true
	t.Cleanup(func() { memoReads = previous })
	resetPlainFolders(t)
	restore := OverrideNetworkSharesForTest(func(string) string { return "" }, func(string) {})
	defer restore()
	limit := SystemLinkLimit()
	home := linkFreeTempDir(t)
	cwd, live := filepath.Join(home, "proj"), filepath.Join(home, "live")
	for _, dir := range []string{cwd, live, filepath.Join(home, ".ssh")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(live, "wk.sh"), []byte("echo marker >> ~/.ssh/authorized_keys\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := limit; i >= 1; i-- {
		to := live
		if i < limit {
			to = fmt.Sprintf("hop%03d", i+1)
		}
		if err := os.Symlink(to, filepath.Join(cwd, fmt.Sprintf("hop%03d", i))); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
	}
	reads := countWalkReads(t)
	const command = ". ./hop001/wk.sh"
	defer HookCall()()
	var perEvaluation []int
	firstDecision := ""
	for i := range 8 {
		before := *reads
		operands := LiteralWriteOperands(command, cwd, home)
		decision := ActionCommandDecision(command, cwd, home)
		state := NewTargetMemo().ActionStateTargetMention(command, cwd, home)
		perEvaluation = append(perEvaluation, *reads-before)
		if state {
			t.Fatalf("evaluation %d: the state scan names a DefenseClaw state file", i+1)
		}
		if !slices.ContainsFunc(operands, func(operand string) bool { return strings.HasSuffix(filepath.ToSlash(operand), ".ssh/authorized_keys") }) {
			t.Fatalf("evaluation %d: the write operands %q miss the sourced writer's target", i+1, operands)
		}
		if i == 0 {
			firstDecision = decision
		} else if decision != firstDecision {
			t.Fatalf("evaluation %d: decision %q, the first was %q", i+1, decision, firstDecision)
		}
	}
	t.Logf("component reads per evaluation behind %d links: %v (decision %q)", limit, perEvaluation, firstDecision)
	if perEvaluation[0] < limit {
		t.Fatalf("the first evaluation read %d components, want at least one per link (%d): the chain was not walked", perEvaluation[0], limit)
	}
	for i, n := range perEvaluation[1:] {
		if n >= limit {
			t.Errorf("evaluation %d read %d components, want fewer than the %d links: the body was read again", i+2, n, limit)
		}
	}
}
