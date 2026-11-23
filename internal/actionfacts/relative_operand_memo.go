// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "sync"

// RelativeOperandMemo keeps the simpleRelativePathOperand answers of the
// readings of one hook. A sandbox call the whole-call analysis does not read
// in full is split once per reading (the placed children and the hook-config
// guard, GAP-0923), and each split asks for every segment of the call whether
// it names a relative path operand, a fresh parse and Analyze per ask. The
// answer depends only on the segment text: it reads the Paths of an Analyze
// of that text alone, with no working directory and no home, and Analyze
// reads files only into the private credential-path record, never into
// Paths. So one answer per text is exact for the hook. A memo is made per
// hook, never shared across hooks, so a package setting a test changes
// between hooks is read afresh. The zero value is ready; nil keeps nothing.
type RelativeOperandMemo struct {
	mu      sync.Mutex
	answers map[string]bool
}

// relativeOperandMemoEntries bounds one hook's memo; past it an ask is
// answered without being kept.
const relativeOperandMemoEntries = 4096

func (memo *RelativeOperandMemo) of(source string) bool {
	if memo == nil {
		return simpleRelativePathOperand(source)
	}
	memo.mu.Lock()
	answer, found := memo.answers[source]
	memo.mu.Unlock()
	if found {
		return answer
	}
	answer = simpleRelativePathOperand(source)
	memo.mu.Lock()
	if memo.answers == nil {
		memo.answers = make(map[string]bool)
	}
	if len(memo.answers) < relativeOperandMemoEntries {
		memo.answers[source] = answer
	}
	memo.mu.Unlock()
	return answer
}
