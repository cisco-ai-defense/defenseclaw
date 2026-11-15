// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// The PowerShell cap pieces: a PowerShell call past a reading cap keeps the
// blocks proven on the statements the cap did not take (rel-1-0-10:GAP-0693,
// the PowerShell twin of the POSIX cap floor).
//
// A call past a nesting, word, statement or command cap is judged at the
// unknown tier of its pack (the evaluation-limit finding: an alert in the
// default, permissive and managed default packs, a block in strict). That is
// a floor, not the verdict: a statement of the call that writes a protected
// file is still a command the shell runs. A PowerShell write of the Windows
// keys file next to 513 nested parentheses, 131073 words or 2100 statements
// was an alert in four of the five tiers, though the same call without the
// padding blocks everywhere. The statements at the start and at the end of the
// call, where a command sits beside the padding, are judged as calls of their
// own, and a block they prove counts for the call, with its rule id
// (withTwinProvenBlocks), whatever the cap did to the rest of it. A call that
// holds no such statement is as before: the floor alone.
const (
	// psCapPiecesPerEnd bounds the statements judged from each end of a call.
	psCapPiecesPerEnd = 8
	// psCapPieceBytes bounds one statement judged on its own: padding is a
	// statement of many bytes.
	psCapPieceBytes = 4 << 10
	// psCapHeadScan and psCapTailScan bound the bytes cut into statements:
	// the start and the end of a call of hundreds of KiB.
	psCapHeadScan = 64 << 10
	psCapTailScan = 32 << 10
)

// powerShellCapPieceTwins returns the twins that judge the first and the last
// statements of a PowerShell call alone. Nothing for a twin, a call that is
// not PowerShell, or one the text of which is not a command string.
func powerShellCapPieceTwins(request trustedActionRequest) []trustedActionRequest {
	if request.readingTwin || request.simpleCommandPass {
		return nil
	}
	if request.Input.DialectHint != actionfacts.DialectPowerShell && !trustedPowerShellExecutionTool(request.Input.Tool) &&
		!request.windowsDialectReadings {
		return nil
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known {
		return nil
	}
	pieces := powerShellCapPieces(command)
	twins := make([]trustedActionRequest, 0, len(pieces))
	for _, piece := range pieces {
		twin := windowsReadingTwin(request)
		twin.Input.Args, twin.Input.Argv = nil, nil
		twin.Input.Command = piece
		// The piece is placed as a Windows hook places the same call without
		// its padding (overLimitTwinDialect), never as a POSIX word list; a
		// piece that is not PowerShell is not read.
		dialect := overLimitTwinDialect(request, twin.Input)
		if dialect != actionfacts.DialectPowerShell {
			if !trustedPowerShellExecutionTool(request.Input.Tool) {
				continue
			}
			dialect = actionfacts.DialectPowerShell
		}
		twin.Input.DialectHint = dialect
		twin.LegacyText = piece
		twins = append(twins, twin)
	}
	return twins
}

// withPowerShellCapPieces adds the blocks the first and the last statements of
// a capped PowerShell call prove.
func withPowerShellCapPieces(parent context.Context, request trustedActionRequest, findings []RuleFinding) []RuleFinding {
	for _, twin := range powerShellCapPieceTwins(request) {
		findings = withTwinProvenBlocks(findings, dispatchTrustedAction(parent, twin))
	}
	return findings
}

// powerShellCapPieces cuts the start and the end of command into statements:
// at a line end or a ; outside a string, a here-string, a comment and any
// bracket, so a pipeline stays one piece. The pieces are text, never parsed
// here: a piece cut wrongly proves nothing, and only a proven block counts.
// A statement over psCapPieceBytes is padding and is not judged alone.
func powerShellCapPieces(command string) []string {
	runes := []rune(command)
	var head, tail []string
	headEnd := min(len(runes), psCapHeadScan)
	head = powerShellStatements(runes[:headEnd], headEnd == len(runes))
	if len(runes) > psCapHeadScan {
		start := max(headEnd, len(runes)-psCapTailScan)
		// The tail starts at a line, not inside a statement.
		for start < len(runes) && runes[start-1] != '\n' {
			start++
		}
		if start < len(runes) {
			tail = powerShellStatements(runes[start:], true)
		}
	}
	if len(runes) <= psCapHeadScan {
		// The whole call was cut: its last statements are the tail.
		tail = head
	}
	if len(head) > psCapPiecesPerEnd {
		head = head[:psCapPiecesPerEnd]
	}
	if len(tail) > psCapPiecesPerEnd {
		tail = tail[len(tail)-psCapPiecesPerEnd:]
	}
	seen := map[string]bool{}
	var out []string
	for _, piece := range append(head, tail...) {
		if !seen[piece] {
			seen[piece] = true
			out = append(out, piece)
		}
	}
	return out
}

// powerShellStatements splits runes into statements (see powerShellCapPieces).
// A window cut inside a statement drops its last (complete is false) piece;
// every piece over psCapPieceBytes is dropped.
func powerShellStatements(runes []rune, complete bool) []string {
	scan := newPSScan(runes, nil)
	var pieces []string
	start, depth := 0, 0
	flush := func(end int) {
		piece := strings.TrimSpace(string(runes[start:end]))
		if piece != "" && len(piece) <= psCapPieceBytes {
			pieces = append(pieces, piece)
		}
		start = end
	}
	for i := 0; i < len(runes) && scan.budget.step(); i++ {
		r := runes[i]
		switch {
		case r == '`':
			i++
		case psSingleQuote(r):
			i = scan.singleQuoted(i) - 1
		case psDoubleQuote(r):
			i = scan.doubleQuoted(i) - 1
		case r == '@' && i+1 < len(runes) && (psSingleQuote(runes[i+1]) || psDoubleQuote(runes[i+1])) && scan.hereStringOpen(i+2):
			i = scan.hereString(i) - 1
		case r == '<' && i+1 < len(runes) && runes[i+1] == '#' && actionfacts.PowerShellCommentStarts(runes, i, false):
			end := i + 2
			for end+1 < len(runes) && (runes[end] != '#' || runes[end+1] != '>') {
				end++
			}
			if end+1 >= len(runes) {
				return pieces
			}
			i = end + 1
		case r == '#' && actionfacts.PowerShellCommentStarts(runes, i, false):
			for i+1 < len(runes) && runes[i+1] != '\n' && runes[i+1] != '\r' {
				i++
			}
		case r == '(' || r == '{' || r == '[':
			depth++
		case r == ')' || r == '}' || r == ']':
			depth = max(depth-1, 0)
		case (r == '\n' || r == ';') && depth == 0:
			flush(i)
			start = i + 1
		}
	}
	if complete {
		flush(len(runes))
	}
	return pieces
}
