// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// ShellInputPastByteBound reports a shell call whose analysis stops at a byte
// bound, not at a count: the arguments past maxArgsJSONBytes, the command
// text past maxCommandBytes, or one literal word past maxScalarBytes. Such an
// analysis (limit_exceeded, input_limit) ends with the commands behind the
// bound unread. A count bound (a statement of more argv words than the
// analysis keeps, fact_limit) is not this: the operand bound judges it
// (rel-1-0-10:GAP-0382).
func ShellInputPastByteBound(command string, argsLen int) bool {
	if argsLen > maxArgsJSONBytes || len(command) > maxCommandBytes {
		return true
	}
	if len(command) <= maxScalarBytes {
		return false
	}
	file, ok := shellparse.Parse(command)
	if !ok {
		return false
	}
	past := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if past {
			return false
		}
		word, isWord := node.(*syntax.Word)
		if !isWord {
			return true
		}
		if value := projectPOSIXWord(word); !value.Expands && len(value.Value) > maxScalarBytes {
			past = true
		}
		return false
	})
	return past
}
