// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// BudgetStateReading is the client's reduced reading of a call past the
// reading budget of shellparse (nesting, bytes, tokens, chain operators,
// tree nodes or depth): no reader parses such a call, so a gateway behind
// ProtectHome would read an empty map as "the call touches no state". The
// map of such a call lists the DefenseClaw state it may write, and says it is
// incomplete (TruncatedKey), so no reader takes "no state listed" for "no
// state touched" (the bound rule: a cut is visible).
//
// The reading needs no parse of the whole call: the call is cut at the
// bytes a shell command ends at (; | & and line ends, and the brackets that
// open or close a group), and the segments that may name the state
// (MayNameState: quotes, escapes, case and patterns do not hide it) are kept,
// in order, as one command. A cut inside a quoted string only leaves a
// segment that does not parse: the reading then gives up (ok false) and the
// map says only that it is incomplete. ok is also false when nothing may
// name the state, or when more than StateNamingStatementsMax segments do.
func BudgetStateReading(command string) (reduced string, ok bool) {
	if !MayNameState(command) {
		return "", false
	}
	var kept []string
	segment := func(from, to int) bool {
		text := strings.Trim(strings.TrimSpace(command[from:to]), "(){}")
		text = strings.TrimSpace(text)
		if text == "" || !MayNameState(text) {
			return true
		}
		if kept = append(kept, text); len(kept) > StateNamingStatementsMax {
			return false
		}
		return true
	}
	start := 0
	for i := 0; i < len(command); i++ {
		switch command[i] {
		case ';', '\n', '|':
		case '&':
			// 2>&1, >&2, &> and &>> are part of a redirect, not a cut.
			if i > 0 && (command[i-1] == '>' || command[i-1] == '<') || i+1 < len(command) && command[i+1] == '>' {
				continue
			}
		default:
			continue
		}
		if !segment(start, i) {
			return "", false
		}
		start = i + 1
	}
	if !segment(start, len(command)) || len(kept) == 0 {
		return "", false
	}
	reduced = strings.Join(kept, "; ")
	if len(reduced) > 64<<10 || shellparse.BudgetExceeded(reduced) != "" {
		return "", false
	}
	if _, parsed := shellparse.Parse(reduced); !parsed {
		return "", false
	}
	return reduced, true
}
