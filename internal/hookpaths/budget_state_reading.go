// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// stateNamingSegments cuts command at the bytes a shell command ends at (;
// | & and line ends, and the brackets that open or close a group) and
// returns the segments that may name the DefenseClaw state
// (MayNameState), in order. within is false when more than
// StateNamingStatementsMax segments do.
func stateNamingSegments(command string) (kept []string, within bool) {
	if !MayNameState(command) {
		return nil, true
	}
	segment := func(from, to int) bool {
		text := strings.TrimSpace(strings.Trim(strings.TrimSpace(command[from:to]), "(){}"))
		if text == "" || !MayNameState(text) {
			return true
		}
		kept = append(kept, text)
		return len(kept) <= StateNamingStatementsMax
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
			return kept, false
		}
		start = i + 1
	}
	return kept, segment(start, len(command))
}

// BudgetMayWriteState reports that a call the readers did not read may write
// the DefenseClaw state: a segment of it (as BudgetStateReading cuts it)
// names the state and is not proven to change no file, or more than
// StateNamingStatementsMax segments name it. A call that only reads or prints
// what names the state (a grep, a cat, an echo) is not one; neither is a call
// that does not name it. A segment that does not parse may write.
func BudgetMayWriteState(command, home string) bool {
	// A call the budget refused for what it holds (nested bodies, brace
	// expansion) still parses: its statements are read as the reduced
	// reading of an over-budget call reads them, which keeps a compound
	// statement whole (an if or a loop is one statement, not three
	// fragments).
	if _, _, parsed := actionfacts.ShellStatementTextsWithOffsets(command); parsed {
		reduced, overflow, _ := StateNamingStatements(command, home)
		return overflow || reduced != ""
	}
	kept, within := stateNamingSegments(command)
	if !within {
		return true
	}
	for _, text := range kept {
		if !stateStatementReadOnly(text, home) {
			return true
		}
	}
	return false
}

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
	kept, within := stateNamingSegments(command)
	if !within || len(kept) == 0 {
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
