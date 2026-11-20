// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// windowsListPrefixTwinRequest is the one extra reading of a Windows hook's
// shell call that the hook placed in no dialect and whose own reading is a
// POSIX list of two or more statements (; newline && ||) the shell grammar
// reads whole: the list without its last statement, judged as the hook judges
// that call (rel-1-0-10:GAP-0348). The hook's selection places
// `git show --output=.git/config HEAD ; echo done` in no dialect; its POSIX
// reading places no .git/config under a Windows folder and its PowerShell
// reading is partial with no readable-statements reading, so a trailing
// benign statement hid what the git read alone proves. A list the selection
// reads as PowerShell is read a statement at a time already
// (actionfacts.HostScriptReadings).
//
// A prefix runs exactly as written whatever follows it, folder moves included,
// so it cannot invent a folder or a write the call does not make, and a fork
// bomb keeps the definition and the call it needs. The prefix gets the dialect
// the route gives a call: the hook's selection again when it made one
// (windowsPowerShellReading; Codex and the agent hooks), the call's own
// inference otherwise (Claude Code's Bash tool is Git Bash and is never read
// as PowerShell). The reading is additive (withHostTwinFindings): proven
// findings keep their verdict and nothing the call as written raised is
// removed or weakened. Bound: one reading per call, a reading twin makes none;
// none for one statement, a partial or capped reading, a call placed in a
// dialect, or a call outside the Windows hooks (Linux and macOS hooks keep
// their reading unchanged).
func windowsListPrefixTwinRequest(request trustedActionRequest, facts actionfacts.Facts) (trustedActionRequest, bool) {
	if !request.windowsDialectReadings || request.readingTwin || request.simpleCommandPass ||
		request.Input.DialectHint != "" || len(request.Input.Argv) != 0 || facts.Parse.Dialect != actionfacts.DialectPOSIX ||
		facts.Parse.Status != actionfacts.StatusComplete && facts.Parse.Status != actionfacts.StatusInvalid {
		return trustedActionRequest{}, false
	}
	command, ok := trustedBashCommandInput(request.Input)
	if !ok || !strings.ContainsAny(command, ";\n&|") {
		return trustedActionRequest{}, false
	}
	prefix, ok := posixListPrefix(command)
	if !ok {
		return trustedActionRequest{}, false
	}
	twin := windowsReadingTwin(request)
	twin.windowsPowerShellReading = nil
	twin.Input.Args, twin.Input.Argv = nil, nil
	twin.Input.Command, twin.LegacyText = prefix, prefix
	if request.windowsPowerShellReading != nil {
		twin.Input.DialectHint, _ = selectWindowsShellDialectReading(twin.Input.Tool, prefix, twin.Input)
	}
	return twin, true
}

// posixListPrefix is command without the last statement of its top-level list:
// the text before the last statement of a ; or newline list, or before the
// right side of a last && or || list, with the separator dropped. A command of
// one statement, or one the shell grammar does not read whole, has none.
func posixListPrefix(command string) (string, bool) {
	file, ok := shellparse.Parse(command)
	if !ok || len(file.Stmts) == 0 {
		return "", false
	}
	last := file.Stmts[len(file.Stmts)-1]
	cut := -1
	if len(file.Stmts) >= 2 {
		cut = int(last.Pos().Offset())
	}
	if list, isList := last.Cmd.(*syntax.BinaryCmd); isList && (list.Op == syntax.AndStmt || list.Op == syntax.OrStmt) &&
		!last.Negated && !last.Background && !last.Coprocess && len(last.Redirs) == 0 {
		cut = int(list.Y.Pos().Offset())
	}
	if cut <= 0 || cut > len(command) {
		return "", false
	}
	prefix := strings.TrimRight(command[:cut], " \t\r\n")
	switch {
	case strings.HasSuffix(prefix, "&&"), strings.HasSuffix(prefix, "||"):
		prefix = prefix[:len(prefix)-2]
	case strings.HasSuffix(prefix, ";") && !strings.HasSuffix(prefix, ";;"):
		prefix = prefix[:len(prefix)-1]
	}
	prefix = strings.TrimRight(prefix, " \t\r\n")
	return prefix, strings.TrimSpace(prefix) != ""
}
