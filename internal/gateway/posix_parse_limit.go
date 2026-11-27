// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// A shell call whose POSIX analysis stopped at a byte bound (limit_exceeded,
// input_limit: a word past the string bound of 4 KiB, the command text past
// 64 KiB, the arguments past 256 KiB) has commands the analysis never read. It
// is truncated in the sense of the bound rule (internal/guardrail/bounded):
// judged at the unknown tier of the pack (an alert in the default and
// permissive packs, a managed install's included, a block in the strict
// pack), never below what the text read before the bound proves, which keeps
// deciding on its own. Before this, one word past the bound ended the
// analysis with no command and the readers had nothing to judge: the call was
// allowed with no finding in every pack (rel-1-0-10:GAP-0382).
//
// Not here: a count bound (a statement of more argv words than the analysis
// keeps) belongs to the operand bound (operandBoundDispatch); the node and
// depth bounds of the analysis lie inside the reading budget, whose own caps
// the property test of the bound rule pins (parse_budget_lanes_test.go); and
// a Windows host call (a PowerShell or cmd tool or dialect) keeps its own rule
// (rel-1-0-10:GAP-0345, GAP-0318: one long ordinary PowerShell statement is
// not limited).

// A word past the bound that the local shell only passes on is not truncated:
// a big quoted script handed to a program that runs it elsewhere (dcx, ssh,
// docker exec) is DATA to the local shell, whose hook never sees what runs
// there. The call is judged as its twin, the same call with each such word
// shortened (actionfacts.SplitOverLimitWords), so every other statement is
// read in full, and the word itself leaves a detection-only record
// (posixDataWordTwinRequest, withPosixDataWordRecord). A word the local shell
// runs as code (the command name, a shell or interpreter operand, a wrapper's
// command, a redirect target, a here-document) stays truncated; the grammar
// position decides, no program is named for being data (rel-1-0-10:GAP-0382,
// second round).

// posixInputLimitCommand is the command text of a POSIX shell call whose
// analysis stopped at an input bound (limit_exceeded, input_limit), "" for any
// other call: a byte bound of the text or of a word (posixByteBoundCommand),
// a count of words, or the bound of a reader inside the text, such as the
// 2 KiB bound of an inline perl or ruby program.
func posixInputLimitCommand(request trustedActionRequest, facts actionfacts.Facts) string {
	input := request.Input
	if facts.Parse.Status != actionfacts.StatusLimitExceeded ||
		!slices.Contains(facts.Parse.Issues, actionfacts.IssueInputLimit) ||
		!trustedBashExecutionTool(input.Tool) {
		return ""
	}
	switch facts.Parse.Dialect {
	case "", actionfacts.DialectNone, actionfacts.DialectPOSIX:
	default:
		return ""
	}
	if input.DialectHint != "" && input.DialectHint != actionfacts.DialectPOSIX {
		return ""
	}
	command, known := trustedBashCommandInput(input)
	if !known {
		// A call whose command is an argv array (the Codex shell tool, an
		// Input.Argv) is the shell text of its words: a word past the bound is
		// in code or data position by the same grammar as in a text call, so
		// the array form is never a clean allow where the text form is
		// truncated (rel-1-0-10:GAP-0689).
		command, known = trustedArgvCommandText(input)
	}
	if !known {
		return ""
	}
	return command
}

// posixByteBoundCommand is the command text of a POSIX shell call the
// analysis stopped reading at a byte bound, "" for any other call.
func posixByteBoundCommand(request trustedActionRequest, facts actionfacts.Facts) string {
	command := posixInputLimitCommand(request, facts)
	if command == "" || !actionfacts.ShellInputPastByteBound(command, len(request.Input.Args)) {
		return ""
	}
	return command
}

// trustedArgvCommandText is the shell text of a call whose command is an
// array of words: each word single-quoted, joined by blanks, so the words
// keep their positions in the grammar. false when the call carries no such
// array or a word is not a string.
func trustedArgvCommandText(input actionfacts.Input) (string, bool) {
	words := input.Argv
	if len(words) == 0 {
		var args struct {
			Command []any `json:"command"`
		}
		if len(input.Args) == 0 || json.Unmarshal(input.Args, &args) != nil || len(args.Command) == 0 {
			return "", false
		}
		for _, word := range args.Command {
			text, ok := word.(string)
			if !ok {
				return "", false
			}
			words = append(words, text)
		}
	}
	var text strings.Builder
	for i, word := range words {
		if strings.IndexByte(word, 0) >= 0 {
			return "", false
		}
		if i > 0 {
			text.WriteByte(' ')
		}
		text.WriteString("'" + strings.ReplaceAll(word, "'", `'\''`) + "'")
	}
	return text.String(), text.Len() > 0
}

// posixParseTruncation is the cap of the input bound the POSIX analysis of a
// shell call hit, empty when it read the call to the end, stopped at another
// bound, the call is not a POSIX shell call, a call over the text bound only
// by the white space or comments that pad it, whose bounded twin
// (overLimitCommandBoundedTwinRequest) is read in full and judged as the
// unpadded command (GAP-0934), or a call whose every over-limit word is DATA
// (posixDataWordTwinRequest).
//
// An inline perl or ruby program past the 2 KiB bound of its reader, in a
// word under the byte bound, is truncated too (actionfacts.InlineProgramPastBound):
// the program's commands were never read, and no twin reads it shorter. It
// used to end in a clean allow in every pack when nothing else was proven:
// under the ONE BOUND RULE it is the unknown tier (an alert in the default and
// permissive packs and the managed default, a block in strict and managed
// strict), and a finding proven elsewhere in the call keeps its own verdict
// (rel-1-0-10:GAP-0689, lead ruling 2026-11-15). Any other input bound under
// the byte bound keeps its own path: a count of words is the operand bound
// (operandBoundDispatch), and a data word inside a command substitution is
// read by the data-word ruling.
func posixParseTruncation(request trustedActionRequest, facts actionfacts.Facts) bounded.CapSet {
	command := posixInputLimitCommand(request, facts)
	if command == "" {
		return bounded.CapSet{}
	}
	if !actionfacts.ShellInputPastByteBound(command, len(request.Input.Args)) {
		if slices.ContainsFunc(facts.Commands, actionfacts.InlineProgramPastBound) {
			return bounded.Of(bounded.Bytes)
		}
		return bounded.CapSet{}
	}
	if posixArgvScriptReadAsText(request, facts) {
		return bounded.CapSet{}
	}
	if _, twinRead := overLimitCommandBoundedTwinRequest(request, facts); twinRead {
		return bounded.CapSet{}
	}
	if _, _, dataOnly := posixDataWordTwinRequest(request, facts); dataOnly {
		return bounded.CapSet{}
	}
	return bounded.Of(bounded.Bytes)
}

// posixDataWordTwinRequest is the request for the twin of a call whose every
// over-limit word is DATA or the inline query of a SQL client: the same call
// with each data word shortened and each query read to its statements within
// the bound (actionfacts.OverLimitWordSplit.Query), which the analysis reads
// to the end, and the split that made it. false when a word is in code
// position, the text cannot be read with certainty, or the twin is still
// past a bound.
func posixDataWordTwinRequest(request trustedActionRequest, facts actionfacts.Facts) (trustedActionRequest, actionfacts.OverLimitWordSplit, bool) {
	command := posixByteBoundCommand(request, facts)
	if command == "" || len(command) > actionfacts.MaxCommandTextBytes {
		return trustedActionRequest{}, actionfacts.OverLimitWordSplit{}, false
	}
	split, ok := actionfacts.SplitOverLimitWords(command)
	if _, text := trustedBashCommandInput(request.Input); !text {
		split, ok = actionfacts.SplitOverLimitWordsOfArgv(command)
	}
	if !ok || split.Code > 0 || split.Data+split.Query == 0 ||
		actionfacts.ShellInputPastByteBound(split.Twin, len(request.Input.Args)) {
		return trustedActionRequest{}, actionfacts.OverLimitWordSplit{}, false
	}
	twin := bashReadingRequest(request, command, split.Twin)
	if !actionfacts.OverLimitTwinWithinBounds(twin.Input, split.Twin) {
		return trustedActionRequest{}, actionfacts.OverLimitWordSplit{}, false
	}
	return twin, split, true
}

// sqlQueryChunkRequests are the readings of the statements of an over-limit
// inline query past its first chunk (actionfacts.OverLimitWordSplit
// .QueryChunks): the call with the query replaced by each further chunk of
// whole statements, judged as the twin is and joined raise-only (DET111
// ruling B on GAP-1926). A chunk whose reading is past a bound is not read;
// its statements stay under the truncation record, which raises nothing.
func sqlQueryChunkRequests(request trustedActionRequest, facts actionfacts.Facts, split actionfacts.OverLimitWordSplit) []trustedActionRequest {
	if len(split.QueryChunks) == 0 {
		return nil
	}
	command := posixByteBoundCommand(request, facts)
	requests := make([]trustedActionRequest, 0, len(split.QueryChunks))
	for _, text := range split.QueryChunks {
		if actionfacts.ShellInputPastByteBound(text, len(request.Input.Args)) {
			continue
		}
		chunk := bashReadingRequest(request, command, text)
		if !actionfacts.OverLimitTwinWithinBounds(chunk.Input, text) {
			continue
		}
		requests = append(requests, chunk)
	}
	return requests
}

// posixDataWordTitle is the reason of the record a data word leaves.
const posixDataWordTitle = "Shell word past the analysis bound is data to the local shell, not read (bounded_truncated cap=bytes, operand)"

// withPosixDataWordRecord adds to the findings of a call a detection-only
// record of the word the analysis did not read: the call keeps the verdict of
// its twin, and the record is no action raise. A limit finding the call
// already carries, or a record a twin left, is kept as it is. The record is
// marked (boundRecord) so no cap logic reads it as a cap the call hit
// (rel-1-0-10:GAP-0760).
func withPosixDataWordRecord(findings []RuleFinding) []RuleFinding {
	return withBoundRecord(findings, posixDataWordTitle, bounded.Of(bounded.Bytes).Reason()+"; operand")
}

// sqlQueryCutTitle is the reason of the record the inline query of a SQL
// client past the shell word bound leaves.
const sqlQueryCutTitle = "SQL client inline query past the shell word bound, judged on its statements within the bound (bounded_truncated cap=bytes, query)"

// withSQLQueryCutRecord adds the detection-only record of the inline query
// of a SQL client (psql -c, mysql -e, sqlcmd -Q, snowsql -q) past the shell
// word bound: the query is code to the server and the call is recorded
// truncated, but the cut by itself raises nothing, as a SQL facts cap hit
// does (DET111 ruling on FIX-T20B: a long benign query must not start
// alerting). The call is judged as its twin, which keeps the statements
// within the bound with their long literals shortened, so a rule that
// matches there still fires.
func withSQLQueryCutRecord(findings []RuleFinding) []RuleFinding {
	return withBoundRecord(findings, sqlQueryCutTitle, bounded.Of(bounded.Bytes).Reason()+"; query")
}

// withSQLASTCapRecord adds the detection-only record of the SQL facts
// reader's cap hits in set: the SQL past the bound gets no SQL fact and the
// legacy SQL readers judge it as at 1.0.10, so the hit is recorded in the
// decision and raises nothing by itself (DET111 ruling on T20 review P3-1:
// a large benign SQL text must not start alerting).
func withSQLASTCapRecord(findings []RuleFinding, set bounded.CapSet) []RuleFinding {
	return withBoundRecord(findings, sqlASTCapRecordTitle+" ("+set.Reason()+")", set.Reason())
}

// sqlASTCapRecordTitle is the reason of the record a SQL facts cap leaves.
const sqlASTCapRecordTitle = "SQL text past the SQL facts bound, judged by the SQL rules only"

// withBoundRecord adds a detection-only record with title (one per title) to
// the findings of a call: INFO, recorded only (no action raise) and marked
// boundRecord, so no cap logic reads it as a cap the call hit. A limit
// finding the call already carries says more and is kept alone.
func withBoundRecord(findings []RuleFinding, title, evidence string) []RuleFinding {
	if boundedLimitIndex(findings) >= 0 || slices.ContainsFunc(findings, func(f RuleFinding) bool {
		return f.boundRecord && f.Title == title
	}) {
		return findings
	}
	record := trustedActionLimitFindings(false)[0]
	record.Title = title
	record.Evidence = evidence
	record.Severity = "INFO" // a record is no CRITICAL on an allowed call
	record.Proof = record.Proof.Record()
	record.boundRecord = true
	return append(slices.Clip(findings), record)
}

// posixArgvScriptReadAsText reports an argv shell launcher (["bash", "-lc",
// SCRIPT], the Codex shell tool) whose script the launcher body reading
// judges as the string command it is, with nothing else the call runs
// (launcherBodyTwinRequest, read and fully, rel-1-0-10:GAP-0803): the script
// word past 4 KiB is then no cut of the call, and the reading of the script
// decides with its own floor, a code word past the bound inside the script
// truncated as in the text form. Truncating the argv form for the length of
// the script alone made every ordinary Codex script over 4 KiB (a
// here-document file write, a long for list) an alert, and a block in
// strict, where the same script as text is allowed (rel-1-0-10:GAP-0853).
func posixArgvScriptReadAsText(request trustedActionRequest, facts actionfacts.Facts) bool {
	if _, text := trustedBashCommandInput(request.Input); text {
		return false
	}
	launcher := launcherBodyTwinRequest(request, facts)
	// fully already holds every launcher reading of the call to the command
	// bound (launcherCallTwin, rel-1-0-10:GAP-0857).
	return launcher.read && launcher.fully
}
