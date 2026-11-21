// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// windowsListPrefixMaxReadings bounds the list-prefix readings of one call:
// a list whose prefixes fall in more key runs than this is read at the ends
// of its longest runs and judged truncated (the unknown tier of the pack),
// never a clean allow.
const windowsListPrefixMaxReadings = 8

// windowsListPrefixMaxKeys bounds the prefix keys one call computes to find
// its key runs (windowsListPrefixRunEnds): past it the runs not yet found are
// unread and the call is judged truncated, as past
// windowsListPrefixMaxReadings.
const windowsListPrefixMaxKeys = 48

// windowsListPrefixKey is how the Windows hook reads one list prefix: the
// dialect the route places it in (the hook's selection when it made one,
// none otherwise) and the dialect and status of its analysis. Prefixes with
// one key are read the same way, statement by statement, so the longest
// prefix of a run of them holds every statement the shorter ones hold, read
// the same way, and the run that ends at the call as written is read by the
// call itself. An invalid reading reads no statement (a fork bomb is proven
// only where it ends the text, endsWithForkBomb), so it proves nothing about
// a shorter or longer prefix: each invalid prefix, and an invalid call, is a
// run of its own (alone, its index plus one; rel-1-0-10:GAP-1569).
type windowsListPrefixKey struct {
	hint, dialect actionfacts.Dialect
	status        actionfacts.ParseStatus
	alone         int
}

// windowsListPrefixKeyOf is the key of a reading at index of the run search.
func windowsListPrefixKeyOf(hint actionfacts.Dialect, parse actionfacts.ParseResult, index int) windowsListPrefixKey {
	key := windowsListPrefixKey{hint: hint, dialect: parse.Dialect, status: parse.Status}
	if parse.Status == actionfacts.StatusInvalid {
		key.alone = index + 1
	}
	return key
}

// windowsListPrefixTwinRequests are the extra readings of a Windows hook's
// shell call that the hook placed in no dialect and whose text is a POSIX
// list of two or more statements (; newline && ||) the shell grammar reads
// whole: the list cut before a later statement, each prefix judged as the
// hook judges that call (rel-1-0-10:GAP-0348). The hook's selection places
// `git show --output=.git/config HEAD ; echo done` in no dialect; its POSIX
// reading places no .git/config under a Windows folder and its PowerShell
// reading is partial with no readable-statements reading, so a trailing
// benign statement hid what the git read alone proves. One trailer or a run
// of them hides it the same way (rel-1-0-10:GAP-1569). A call placed in no
// dialect may run in any shell, so the dialect its own reading infers from
// the text (POSIX, or CMD for a Windows path under a tool label that names no
// shell) does not decide whether its prefixes are read, and that reading may
// be complete, invalid (a fork bomb: the list grammar still reads it whole),
// partial or ambiguous (a native Windows program with a Windows path operand,
// which the POSIX model cannot place): such a reading proves nothing about a
// prefix, so it is no reason to skip one (rel-1-0-10:GAP-0348 round 2). A
// list the selection reads as PowerShell is read a statement at a time
// already (actionfacts.HostScriptReadings).
//
// A trailer hides a statement by changing how the call is read, so the
// prefixes are grouped by how the hook reads them (windowsListPrefixKey) and
// the longest prefix of each run of one key is read, except the run that ends
// at the call as written, which the call itself reads: a benign list of 10 or
// 127 statements is read once more at its first statement, not 9 or 126
// times, each costing about 2 ms per statement (rel-1-0-10:GAP-1587). The
// runs are found from the keys of the prefixes of 1, 2, 4, 8 ... statements
// and the list without its last statement, bisected where two of them
// differ (windowsListPrefixRunEnds).
//
// A prefix runs exactly as written whatever follows it, folder moves included,
// so it cannot invent a folder or a write the call does not make, and a fork
// bomb keeps the definition and the call it needs. Each prefix gets the
// dialect the route gives a call: the hook's selection again when it made one
// (windowsPowerShellReading; Codex and the agent hooks), the call's own
// inference otherwise (Claude Code's Bash tool is Git Bash and is never read
// as PowerShell). The readings are additive (withHostTwinFindings): proven
// findings keep their verdict and nothing the call as written raised is
// removed or weakened. Bound: at most windowsListPrefixMaxReadings readings
// and windowsListPrefixMaxKeys keys per call, the cap set returned past
// either (ONE BOUND RULE); a reading twin makes none; none for one
// statement, text the POSIX list grammar does not read whole, a capped or
// unsupported reading (judged by its own bound), a call over the statement
// budget (dispatch refuses it whole before the twins,
// trustedCallOverStatementBudget), a call placed in a dialect, or a call
// outside the Windows hooks (Linux and macOS hooks keep their reading
// unchanged).
func windowsListPrefixTwinRequests(request trustedActionRequest, facts actionfacts.Facts) ([]trustedActionRequest, bounded.CapSet) {
	if !request.windowsDialectReadings || request.readingTwin || request.simpleCommandPass ||
		request.Input.DialectHint != "" || len(request.Input.Argv) != 0 {
		return nil, bounded.CapSet{}
	}
	switch facts.Parse.Status {
	case actionfacts.StatusComplete, actionfacts.StatusInvalid, actionfacts.StatusPartial, actionfacts.StatusAmbiguous:
	default:
		return nil, bounded.CapSet{}
	}
	command, ok := trustedBashCommandInput(request.Input)
	if !ok || !strings.ContainsAny(command, ";\n&|") {
		return nil, bounded.CapSet{}
	}
	// Longest first; index i of the run search is the prefix of i+1 cuts.
	prefixes := posixListPrefixes(command)
	if len(prefixes) == 0 {
		return nil, bounded.CapSet{}
	}
	count := len(prefixes)
	twins := make(map[int]trustedActionRequest)
	key := func(index int) windowsListPrefixKey {
		prefix := prefixes[count-1-index]
		twin := windowsReadingTwin(request)
		twin.windowsPowerShellReading = nil
		twin.Input.Args, twin.Input.Argv = nil, nil
		twin.Input.Command, twin.LegacyText = prefix, prefix
		if request.windowsPowerShellReading != nil {
			twin.Input.DialectHint, _ = selectWindowsShellDialectReading(twin.Input.Tool, prefix, twin.Input)
		}
		twins[index] = twin
		return windowsListPrefixKeyOf(twin.Input.DialectHint, actionfacts.Analyze(twin.Input).Parse, index)
	}
	whole := windowsListPrefixKeyOf("", facts.Parse, count)
	ends, capped := windowsListPrefixRunEnds(count, whole, key, windowsListPrefixMaxKeys)
	if len(ends) > windowsListPrefixMaxReadings {
		ends, capped = ends[:windowsListPrefixMaxReadings], true
	}
	readings := make([]trustedActionRequest, 0, len(ends))
	for _, end := range ends {
		readings = append(readings, twins[end])
	}
	if capped {
		return readings, bounded.Of(bounded.Items)
	}
	return readings, bounded.CapSet{}
}

// windowsListPrefixRunEnds finds the runs of equal keys among count prefixes
// of a call, index 0 the shortest and count the call as written (key whole),
// and returns the last index of each run that does not end at the call,
// longest first. Keys are computed (at most maxKeys times) at 0, 1, 3, 7 ...
// (1, 2, 4, 8 ... cuts) and count-1, and between two known indices with
// different keys at the middle until the change falls between adjacent
// indices. capped reports that maxKeys stopped the search before every
// change between known indices was placed.
func windowsListPrefixRunEnds(count int, whole windowsListPrefixKey, key func(int) windowsListPrefixKey, maxKeys int) (ends []int, capped bool) {
	keys := map[int]windowsListPrefixKey{count: whole}
	computed := 0
	known := func(index int) bool {
		if _, ok := keys[index]; ok {
			return true
		}
		if computed == maxKeys {
			return false
		}
		computed++
		keys[index] = key(index)
		return true
	}
	samples := []int{}
	for index := 0; index < count-1; index = 2*index + 1 {
		samples = append(samples, index)
	}
	samples = append(samples, count-1, count)
	type span struct{ from, to int }
	var open []span
	for i, index := range samples {
		if !known(index) {
			return nil, true
		}
		if i > 0 {
			open = append(open, span{samples[i-1], index})
		}
	}
	for len(open) != 0 {
		next := open[len(open)-1]
		open = open[:len(open)-1]
		if next.to-next.from < 2 || keys[next.from] == keys[next.to] {
			continue
		}
		middle := next.from + (next.to-next.from)/2
		if !known(middle) {
			capped = true
			break
		}
		open = append(open, span{next.from, middle}, span{middle, next.to})
	}
	indices := make([]int, 0, len(keys))
	for index := range keys {
		indices = append(indices, index)
	}
	slices.Sort(indices)
	for i := len(indices) - 2; i >= 0; i-- {
		if keys[indices[i]] != keys[indices[i+1]] {
			ends = append(ends, indices[i])
		}
	}
	return ends, capped
}

// posixListPrefixes are the prefixes of command cut before each later
// statement of its top-level list, longest first: before each statement of a
// ; or newline list and before the right side of each && or || on the left
// spine of a statement, with the separator dropped. A command of one
// statement, or one the shell grammar does not read whole, has none. A cut
// inside a here-document (after its operator, before the end of its body) is
// no prefix: the text before it does not hold the body the command reads.
func posixListPrefixes(command string) (prefixes []string) {
	file, ok := shellparse.Parse(command)
	if !ok || len(file.Stmts) == 0 {
		return nil
	}
	var cuts []int
	for index, stmt := range file.Stmts {
		if index > 0 {
			cuts = append(cuts, int(stmt.Pos().Offset()))
		}
		for current := stmt; !current.Negated && !current.Background && !current.Coprocess && len(current.Redirs) == 0; {
			list, isList := current.Cmd.(*syntax.BinaryCmd)
			if !isList || list.Op != syntax.AndStmt && list.Op != syntax.OrStmt {
				break
			}
			cuts = append(cuts, int(list.Y.Pos().Offset()))
			current = list.X
		}
	}
	if len(cuts) == 0 {
		return nil
	}
	type span struct{ from, to int }
	var heredocs []span
	syntax.Walk(file, func(node syntax.Node) bool {
		if redirect, ok := node.(*syntax.Redirect); ok && redirect.Hdoc != nil {
			to := len(command)
			if redirect.Hdoc.End().IsValid() && len(redirect.Hdoc.Parts) != 0 {
				to = int(redirect.Hdoc.End().Offset())
			}
			heredocs = append(heredocs, span{int(redirect.OpPos.Offset()), to})
		}
		return true
	})
	slices.Sort(cuts)
	cuts = slices.Compact(cuts)
	for index := len(cuts) - 1; index >= 0; index-- {
		cut := cuts[index]
		if cut <= 0 || cut > len(command) || slices.ContainsFunc(heredocs, func(h span) bool { return h.from < cut && cut <= h.to }) {
			continue
		}
		prefix := strings.TrimRight(command[:cut], " \t\r\n")
		switch {
		case strings.HasSuffix(prefix, "&&"), strings.HasSuffix(prefix, "||"):
			prefix = prefix[:len(prefix)-2]
		case strings.HasSuffix(prefix, ";") && !strings.HasSuffix(prefix, ";;"):
			prefix = prefix[:len(prefix)-1]
		}
		prefix = strings.TrimRight(prefix, " \t\r\n")
		if strings.TrimSpace(prefix) == "" || slices.Contains(prefixes, prefix) {
			continue
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}
