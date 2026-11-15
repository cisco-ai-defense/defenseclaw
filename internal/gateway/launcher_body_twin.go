// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// maxArgvDecodeBytes is the largest tool-argument object whose command array
// the gateway reads for a launcher body (actionfacts reads 256 KiB of JSON).
const maxArgvDecodeBytes = 256 << 10

// maxLauncherBodyDepth bounds the launchers read through one another
// (cmd /c powershell -Command ...): each level is one more analysis.
const maxLauncherBodyDepth = 2

// trustedArgvCommandInput returns the argv array a shell execution tool call
// sends as its command (the Codex shell tool: ["powershell.exe", "-Command",
// "<script>"]), and whether the call has one.
func trustedArgvCommandInput(input actionfacts.Input) ([]string, bool) {
	if !trustedShellCommandTool(input.Tool) {
		return nil, false
	}
	if len(input.Argv) > 0 {
		return input.Argv, true
	}
	if len(bytes.TrimSpace(input.Args)) == 0 || len(input.Args) > maxArgvDecodeBytes {
		return nil, false
	}
	var object struct {
		Command []json.RawMessage `json:"command"`
	}
	if json.Unmarshal(input.Args, &object) != nil || len(object.Command) == 0 {
		return nil, false
	}
	argv := make([]string, 0, len(object.Command))
	for _, raw := range object.Command {
		var word string
		if json.Unmarshal(raw, &word) != nil {
			return nil, false
		}
		argv = append(argv, word)
	}
	return argv, true
}

// launcherBodyTwinRequest is the second reading of a shell launcher call, so
// that a launcher gets the same verdict as an argv command and as one command
// string (rel-1-0-10:GAP-0711, GAP-0712, GAP-0735). The Codex Windows shell
// tool sends powershell.exe -Command, pwsh -c or cmd /c as an argv array or as
// one string. The argv analysis stopped at the launcher unless the startup
// scripts were switched off (-NoProfile, /d) and read no word past 4 KiB, so a
// protected write in the script went unread in every pack, and a script past
// the reading bounds had no limit finding at all.
//
//   - CMD launcher (argv or string): the script is judged as the CMD command
//     it is, whatever AutoRun does before it.
//   - PowerShell launcher whose script is past a reading bound (its own
//     analysis is limit_exceeded): the script is judged as a PowerShell
//     command, with its own statement budget, PowerShellCappedRuns and the
//     TRUNCATED floor of trustedReadingCut: a proven finding in the read
//     part keeps its verdict, the rest is at least the unknown tier.
//   - PowerShell launcher in an argv array, script within the bounds: the
//     same call as one command string (powerShellLineOfArgv), so the
//     existing readings of a string launcher (the profile wrapper reduction,
//     which counts only a match a profile or an outer redirect cannot undo)
//     decide, and the two forms agree.
//   - POSIX launcher (bash -c): the script only when the call's own analysis
//     is limit_exceeded.
//
// A PowerShell launcher string within the bounds keeps the readings it had.
func launcherBodyTwinRequest(request trustedActionRequest, facts actionfacts.Facts) (trustedActionRequest, bool) {
	if request.simpleCommandPass || request.readingTwin || request.launcherDepth >= maxLauncherBodyDepth {
		return trustedActionRequest{}, false
	}
	var (
		body    string
		dialect actionfacts.Dialect
		argv    []string
	)
	argv, isArgv := trustedArgvCommandInput(request.Input)
	if isArgv {
		var ok bool
		if body, dialect, ok = actionfacts.ShellLauncherBody(argv); !ok {
			return trustedActionRequest{}, false
		}
	} else {
		text, known := trustedBashCommandInput(request.Input)
		if !known {
			return trustedActionRequest{}, false
		}
		var ok bool
		if body, dialect, ok = actionfacts.ShellLauncherBodyOfText(text); !ok {
			return trustedActionRequest{}, false
		}
	}
	twin := request
	twin.launcherDepth++
	twin.record, twin.recordTelemetry = nil, nil
	twin.conflictSource = nil
	switch dialect {
	case actionfacts.DialectPOSIX:
		if facts.Parse.Status != actionfacts.StatusLimitExceeded {
			return trustedActionRequest{}, false
		}
	case actionfacts.DialectPowerShell:
		bodyFacts := actionfacts.Analyze(actionfacts.Input{
			Tool: request.Input.Tool, Command: body, DialectHint: dialect, CWD: request.Input.CWD,
			ActiveHome: request.Input.ActiveHome,
		})
		if bodyFacts.Parse.Status != actionfacts.StatusLimitExceeded {
			if !isArgv {
				return trustedActionRequest{}, false
			}
			line := powerShellLineOfArgv(argv)
			twin.Input.Command, twin.Input.Args, twin.Input.Argv = line, nil, nil
			twin.Input.DialectHint = actionfacts.DialectPowerShell
			twin.LegacyText = line
			return twin, true
		}
	}
	twin.Input.Command, twin.Input.Args, twin.Input.Argv = body, nil, nil
	twin.Input.DialectHint = dialect
	twin.LegacyText = body
	return twin, true
}

// powerShellLineOfArgv is argv as one PowerShell command line: each word that
// is not plain is single-quoted, so PowerShell reads back the same words.
func powerShellLineOfArgv(argv []string) string {
	words := make([]string, len(argv))
	for i, word := range argv {
		words[i] = powerShellWord(word)
	}
	return strings.Join(words, " ")
}

func powerShellWord(word string) string {
	plain := word != ""
	for _, r := range word {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.', r == '/', r == ':', r == '\\', r == '=', r == '+', r == ',', r == '@':
		default:
			plain = false
		}
	}
	if plain {
		return word
	}
	return "'" + strings.ReplaceAll(word, "'", "''") + "'"
}

// trustedArgvReadingCut is the cap at which the reading of an argv command
// stopped, for a shell execution tool whose command is an array and whose
// analysis is limit_exceeded (a word over 4 KiB, over 64 KiB in all, or more
// than 256 words) when no launcher body reading covers it
// (launcherBodyTwinRequest): such a call has no dialect, so no other floor
// applies to it (the one bound rule, rel-1-0-10:GAP-0712).
func trustedArgvReadingCut(input actionfacts.Input, facts actionfacts.Facts) bounded.CapSet {
	if facts.Parse.Status != actionfacts.StatusLimitExceeded {
		return bounded.CapSet{}
	}
	argv, ok := trustedArgvCommandInput(input)
	if !ok {
		if len(input.Args) > maxArgvDecodeBytes && trustedShellCommandTool(input.Tool) {
			return bounded.Of(bounded.Bytes)
		}
		return bounded.CapSet{}
	}
	if len(argv) > actionfacts.MaxArgvItems {
		return bounded.Of(bounded.Items)
	}
	return bounded.Of(bounded.Bytes)
}
