// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// A call the readers did not read (past the reading budget, or past the
// nested-body bound) is judged at the unknown tier and by the check of its raw
// text for the state (withBudgetStateBlock). That leaves one thing of the bound
// rule: a finding proven before the cap still decides, and so does one after
// it (GAP-0435, GAP-0381). The statements of such a call that may name a
// protected target are small and read like any call: each is judged on its own
// as the call it is, and a block proven there counts.
const (
	// budgetSegmentMaxBytes bounds a statement judged on its own: the padding
	// that put the call past the budget is a statement of many bytes.
	budgetSegmentMaxBytes = 4096
	// budgetSegmentMax bounds the statements judged: sixteen of them at the
	// cost of a hook call each (about 10 ms) stay inside the hook window.
	budgetSegmentMax = 16
	// budgetSegmentScan bounds the bytes read from each end of a call: the
	// statements judged are those at its start and at its end, where a command
	// is written beside the padding that made the call past a bound. The
	// middle of a call of hundreds of KiB is padding the raw-text state check
	// has covered; reading it for protected names cost 150 bytes of memory for
	// each byte.
	budgetSegmentScan = 32 << 10
)

// budgetShellCommand is the shell command text of a call.
func budgetShellCommand(request trustedActionRequest) string {
	input := request.Input
	command := input.Command
	if command == "" && len(bytes.TrimSpace(input.Args)) > 0 {
		if field, present, valid := trustedTopLevelCommandField(input.Args); valid && present {
			command = field
		}
	}
	return command
}

// budgetSegments are the statements of command that may name a protected
// target or the DefenseClaw state, cut at ; and line ends and at && and ||
// (read from the text, never parsed: a quoted string, a comment and a here-document body are not cut, see
// shellparse.StatementSpans), each of at most
// budgetSegmentMaxBytes. The statements that name one are found by halving
// the call: a range that names none is dropped whole, so a call of thousands
// of statements costs a pass over the text for each level of the halving,
// not a check for each statement.
func budgetSegments(command, cwd, home string) []string {
	if len(command) > 2*budgetSegmentScan {
		head, tail := command[:budgetSegmentScan], command[len(command)-budgetSegmentScan:]
		if i := strings.LastIndexAny(head, ";\n"); i > 0 {
			head = head[:i]
		}
		if i := strings.IndexAny(tail, ";\n"); i >= 0 {
			tail = tail[i+1:]
		}
		command = head + "\n" + tail
	}
	spans := shellparse.StatementSpans(command)
	rangeText := func(lo, hi int) string { return command[spans[lo][0]:spans[hi-1][1]] }
	names := func(text string) bool {
		return hookpaths.BoundCallMayNameProtected(text, cwd, home) || hookpaths.MayNameState(text)
	}
	var segments []string
	var find func(lo, hi int)
	find = func(lo, hi int) {
		if lo >= hi || len(segments) >= budgetSegmentMax {
			return
		}
		text := rangeText(lo, hi)
		if !names(text) {
			return
		}
		if hi-lo == 1 {
			if text = strings.TrimSpace(text); len(text) <= budgetSegmentMaxBytes {
				segments = append(segments, text)
			}
			return
		}
		mid := (lo + hi) / 2
		find(lo, mid)
		find(mid, hi)
	}
	find(0, len(spans))
	return segments
}

// budgetSegmentTwins are the requests for the statements of a call the readers
// did not read (budgetSegments): the same call with one statement as its
// command.
func budgetSegmentTwins(request trustedActionRequest) []trustedActionRequest {
	if request.budgetSegment {
		return nil
	}
	if _, known := trustedBashCommandInput(request.Input); !known {
		return nil
	}
	var twins []trustedActionRequest
	for _, segment := range budgetSegments(budgetShellCommand(request), request.Input.CWD, request.Input.ActiveHome) {
		twin := request
		twin.budgetSegment = true
		twin.Input.Command = segment
		twin.LegacyText = segment
		if len(bytes.TrimSpace(request.Input.Args)) != 0 {
			args, err := json.Marshal(map[string]string{"command": segment})
			if err != nil {
				continue
			}
			twin.Input.Args = args
			twin.LegacyText = string(args)
		}
		twin.conflictSource = nil
		twin.record, twin.recordTelemetry = nil, nil
		twins = append(twins, twin)
	}
	return twins
}

// withBudgetSegmentBlocks adds the blocks proven on the statements of a call
// the readers did not read.
func withBudgetSegmentBlocks(parent context.Context, request trustedActionRequest, findings []RuleFinding) []RuleFinding {
	for _, twin := range budgetSegmentTwins(request) {
		findings = withTwinProvenBlocks(findings, dispatchTrustedAction(parent, twin))
	}
	return findings
}
