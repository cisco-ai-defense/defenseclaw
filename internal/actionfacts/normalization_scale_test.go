// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"fmt"
	"testing"
	"time"
)

// A command of many operands has a path fact for each; normalizing them took
// a scan of the whole argument list per fact (GAP-0483). The cost must grow
// with the operand count, not with its square.
func TestNormalizePathFactsGrowsLinearlyWithOperands(t *testing.T) {
	cost := func(operands int) time.Duration {
		command := CommandFact{ID: 1, Dialect: DialectPOSIX}
		paths := make([]PathFact, operands)
		for i := range paths {
			value := fmt.Sprintf("lo%d.txt", i)
			command.Arguments = append(command.Arguments, ArgumentFact{Value: value})
			paths[i] = PathFact{CommandID: 1, Value: value}
		}
		best := time.Duration(1 << 62)
		for range 5 {
			facts := append([]PathFact(nil), paths...)
			start := time.Now()
			normalizePathFactsForCommandsInShell(facts, "/work", "/home/u", []CommandFact{command}, false)
			if elapsed := time.Since(start); elapsed < best {
				best = elapsed
			}
		}
		return best
	}
	small, large := cost(2000), cost(8000)
	t.Logf("2000 operands: %v, 8000 operands: %v", small, large)
	if small < time.Millisecond {
		small = time.Millisecond
	}
	if large > 8*small {
		t.Fatalf("8000 operands cost %v against %v for 2000: more than 8x for 4x the operands", large, small)
	}
}
