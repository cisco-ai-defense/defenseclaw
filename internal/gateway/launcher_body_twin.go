// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"

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

// launcherBodyTwinRequest is the request for the script a shell launcher in
// an argv command runs (powershell.exe -Command, pwsh -c, cmd /c, bash -c),
// judged as the string command the same script is when a hook sends it
// whole: in the launcher's own dialect, with its own statement budget and
// its own TRUNCATED floor (trustedReadingCut). The Codex Windows shell tool
// sends its command as such an array, whose analysis stops at the launcher
// unless the startup scripts are switched off (-NoProfile, /d) and reads no
// word past 4 KiB, so a protected write in the body went unread in every
// pack (rel-1-0-10:GAP-0711) and a body past the reading bounds had no
// limit finding at all (rel-1-0-10:GAP-0712).
//
// The body runs as written whatever a profile or AutoRun entry does before
// it, so every finding of its reading counts. A POSIX launcher is read only
// when its own analysis hit a bound; a PowerShell or CMD launcher always, as an
// authoritative -NoProfile reading still missed what the string form of the
// same script finds (the atomic parity fixture, alert as a string).
func launcherBodyTwinRequest(request trustedActionRequest, facts actionfacts.Facts) (trustedActionRequest, bool) {
	if request.simpleCommandPass || request.readingTwin || request.launcherDepth >= maxLauncherBodyDepth {
		return trustedActionRequest{}, false
	}
	var (
		body    string
		dialect actionfacts.Dialect
	)
	if argv, isArgv := trustedArgvCommandInput(request.Input); isArgv {
		var ok bool
		if body, dialect, ok = actionfacts.ShellLauncherBody(argv); !ok {
			return trustedActionRequest{}, false
		}
	} else {
		// A launcher in a command string, as the Codex Windows hook sends
		// the same call (rel-1-0-10:GAP-0735): read the same way.
		text, known := trustedBashCommandInput(request.Input)
		if !known {
			return trustedActionRequest{}, false
		}
		var ok bool
		if body, dialect, ok = actionfacts.ShellLauncherBodyOfText(text); !ok {
			return trustedActionRequest{}, false
		}
	}
	if dialect == actionfacts.DialectPOSIX && facts.Parse.Status != actionfacts.StatusLimitExceeded {
		return trustedActionRequest{}, false
	}
	twin := request
	twin.launcherDepth++
	twin.record, twin.recordTelemetry = nil, nil
	twin.conflictSource = nil
	twin.Input.Command, twin.Input.Args, twin.Input.Argv = body, nil, nil
	twin.Input.DialectHint = dialect
	twin.LegacyText = body
	return twin, true
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
