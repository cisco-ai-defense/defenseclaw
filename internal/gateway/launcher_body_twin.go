// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"path"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// maxArgvDecodeBytes is the largest tool-argument object whose command array
// the gateway reads for a launcher body (actionfacts reads 256 KiB of JSON).
const maxArgvDecodeBytes = 256 << 10

// maxLauncherBodyDepth bounds the launchers read through one another
// (cmd /c powershell -Command ...): each level is one more analysis. It is the
// depth the over-limit launcher screen reads (actionfacts
// maxLauncherScriptDepth); a launcher nested deeper is TRUNCATED at the depth
// cap, never a silent allow (rel-1-0-10:GAP-0806).
const maxLauncherBodyDepth = 4

// maxLauncherPrefixBytes is the most a wrapper's words before the launcher
// (sudo -u x, env NAME=value, timeout 5) may hold for the launcher script to
// count as the whole call: longer wrapper words are not read either.
const maxLauncherPrefixBytes = 4 << 10

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

// launcherBodyReading is the second reading of a shell launcher call
// (launcherBodyTwinRequest): the requests that read it, one per launcher the
// call may run (actionfacts.ShellLauncherCalls: a word read both as a wrapper
// operand and as the launcher gives two, rel-1-0-10:GAP-0857), whether the
// launcher's script is all the call runs in every one of them (fully: no
// unread wrapper words, no words after a POSIX -c script that it may run, a
// script within the command bound), and whether a launcher was found past
// maxLauncherBodyDepth (depthCut).
type launcherBodyReading struct {
	twins    []trustedActionRequest
	read     bool
	fully    bool
	depthCut bool
}

// launcherBodyTwinRequest is the second reading of a shell launcher call, so
// that a launcher gets the same verdict as an argv command and as one command
// string, however it is spelled (rel-1-0-10:GAP-0711, GAP-0712, GAP-0735,
// GAP-0804, GAP-0805). The Codex Windows shell tool sends powershell.exe
// -Command, pwsh -c or cmd /c as an argv array or as one string, at any
// install path, behind a wrapper (start "", wsl -e, sudo, env, nohup,
// timeout, xargs) or in a later statement. actionfacts.ShellLauncherCalls
// names the launchers with the over-limit screen's wrapper reading, so the
// screen and this reading agree on which launcher a call runs; each one is
// judged and the caller keeps the strongest proven verdict.
//
//   - CMD launcher (argv or string): the script is judged as the CMD command
//     it is, whatever AutoRun does before it.
//   - PowerShell launcher whose script is past a reading bound (its own
//     analysis is limit_exceeded): the script is judged as a PowerShell
//     command, with its own statement budget, PowerShellCappedRuns and the
//     TRUNCATED floor of trustedReadingCut: a proven finding in the read
//     part keeps its verdict, the rest is at least the unknown tier.
//   - PowerShell launcher within the bounds in an argv array, behind a
//     wrapper, at a path or in a later statement: the launcher alone, as the
//     one command line `<pwsh|powershell>[.exe] <words>` the bare launcher
//     is (powerShellLineOfArgv), so the readings of a bare launcher string
//     (psparse's script reading, the profile wrapper reduction, which counts
//     only a match a profile or an outer redirect cannot undo) decide, and
//     every spelling agrees with the bare one.
//   - POSIX launcher (bash -c): the script only when the call's own analysis
//     is limit_exceeded.
//
// A bare PowerShell launcher string within the bounds keeps the readings it
// has.
func launcherBodyTwinRequest(request trustedActionRequest, facts actionfacts.Facts) launcherBodyReading {
	if request.simpleCommandPass || request.readingTwin || request.hostScriptTwinOff {
		// hostScriptTwinOff turns both launcher script readings off: this one
		// and psparse's (hostScriptTwinRequests).
		return launcherBodyReading{}
	}
	var (
		calls     []actionfacts.LauncherCall
		words     []string
		statement int
	)
	argv, isArgv := trustedArgvCommandInput(request.Input)
	if isArgv {
		words = argv
		calls = actionfacts.ShellLauncherCalls(argv)
	} else {
		text, known := trustedBashCommandInput(request.Input)
		if !known {
			return launcherBodyReading{}
		}
		calls, words, statement, _ = actionfacts.ShellLauncherCallsOfText(text)
	}
	if len(calls) == 0 {
		return launcherBodyReading{}
	}
	if request.launcherDepth >= maxLauncherBodyDepth {
		return launcherBodyReading{depthCut: true}
	}
	reading := launcherBodyReading{fully: true}
	for _, call := range calls {
		twin, read, fully := launcherCallTwin(request, facts, call, words, statement, isArgv)
		if !read {
			continue
		}
		reading.read = true
		reading.fully = reading.fully && fully
		reading.twins = append(reading.twins, twin)
	}
	if !reading.read {
		return launcherBodyReading{}
	}
	return reading
}

// launcherCallTwin is the request that reads one launcher call of
// launcherBodyTwinRequest, and whether its script is all the call runs.
func launcherCallTwin(
	request trustedActionRequest, facts actionfacts.Facts, call actionfacts.LauncherCall,
	words []string, statement int, isArgv bool,
) (twin trustedActionRequest, read, fully bool) {
	prefix := 0
	for _, word := range words[:call.Start] {
		prefix += len(word)
	}
	fully = !call.Trailing && prefix <= maxLauncherPrefixBytes
	twin = request
	twin.launcherDepth++
	twin.record, twin.recordTelemetry = nil, nil
	twin.conflictSource = nil
	switch call.Dialect {
	case actionfacts.DialectPOSIX:
		// A POSIX launcher string keeps the readings it has (its script is
		// read inside the call); only an argv array, whose words the analysis
		// bounds one by one, needs the script read on its own.
		if !isArgv || facts.Parse.Status != actionfacts.StatusLimitExceeded {
			return trustedActionRequest{}, false, false
		}
	case actionfacts.DialectPowerShell:
		bodyFacts := actionfacts.Analyze(actionfacts.Input{
			Tool: request.Input.Tool, Command: call.Body, DialectHint: call.Dialect, CWD: request.Input.CWD,
			ActiveHome: request.Input.ActiveHome,
		})
		if bodyFacts.Parse.Status != actionfacts.StatusLimitExceeded {
			launcher := words[call.Start:]
			bare := launcherProgramName(launcher[0])
			if !isArgv && statement == 0 && call.Start == 0 && bare == launcher[0] {
				return trustedActionRequest{}, false, false
			}
			line := powerShellLineOfArgv(append([]string{bare}, launcher[1:]...))
			twin.Input.Command, twin.Input.Args, twin.Input.Argv = line, nil, nil
			// The dialect the Windows hook gives the same text as a string.
			twin.Input.DialectHint = actionfacts.DialectPowerShell
			if request.windowsDialectReadings {
				twin.Input.DialectHint = ""
				twin.Input.DialectHint, _ = selectWindowsShellDialectReading(request.Input.Tool, line, twin.Input)
			}
			twin.LegacyText = line
			return twin, true, fully && len(line) <= actionfacts.MaxCommandBytes
		}
	}
	twin.Input.Command, twin.Input.Args, twin.Input.Argv = call.Body, nil, nil
	twin.Input.DialectHint = call.Dialect
	twin.LegacyText = call.Body
	return twin, true, fully && len(call.Body) <= actionfacts.MaxCommandBytes
}

// launcherProgramName is the launcher program word as the bare launcher is
// written: the lower-case file name of the program at any path (a quoted
// install path such as C:\Program Files\PowerShell\7\pwsh.exe is pwsh.exe,
// rel-1-0-10:GAP-0804).
func launcherProgramName(word string) string {
	return strings.ToLower(path.Base(strings.ReplaceAll(word, `\`, "/")))
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
	return managed.PowerShellLiteral(word)
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
		return bounded.CapSet{}
	}
	if len(argv) > actionfacts.MaxArgvItems {
		return bounded.Of(bounded.Items)
	}
	return bounded.Of(bounded.Bytes)
}
