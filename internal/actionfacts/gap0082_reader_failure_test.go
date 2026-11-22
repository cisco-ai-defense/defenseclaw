// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// gas-ux-r2:GAP-0082: 1.0.7 and 1.0.8 panicked in simpleRelativePathOperand
// on this benign probe chain, and the hook refused it with no rule id. The
// chain reads as three commands.
func TestGAP0082CommandVChainReads(t *testing.T) {
	input := Input{Tool: "shell", Command: "command -v unzip && command -v uncompress && command -v tar", CWD: "/home/u/work"}
	simples := SimpleCommands(input, Analyze(input))
	for _, simple := range simples {
		if simple.EvaluationFailure != "" {
			t.Fatalf("SimpleCommands = %+v, want the commands read", simples)
		}
	}
}

// A reader that fails internally answers EvaluationFailureInternal, never a
// panic and never an empty (ordinary) reading.
func TestGAP0082ReaderFailureIsInternalEvaluationFailure(t *testing.T) {
	simpleCommandsFault = func() { panic("injected reader fault") }
	t.Cleanup(func() { simpleCommandsFault = nil })
	input := Input{Tool: "shell", Command: "echo hi", CWD: "/home/u/work"}
	simples := SimpleCommands(input, Analyze(input))
	if len(simples) != 1 || simples[0].EvaluationFailure != EvaluationFailureInternal {
		t.Fatalf("SimpleCommands = %+v, want one %q failure", simples, EvaluationFailureInternal)
	}
}
