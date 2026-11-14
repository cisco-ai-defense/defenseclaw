// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/awkprog"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// awkCommandTwinRequest returns the request for actionfacts.AwkCommandTwin of
// a POSIX Bash call: the reading in which each command an awk program starts
// is the group that runs it, judged as the hook running it directly. Behind
// ProtectHome (managed hook peer) the hook client map lists the targets of the
// same reading (hookpaths). Only a block of that reading counts; the
// findings of the call as written stand. caps is what the reading could not
// read (an awk program in shell STRINGs nested past the bound).
func awkCommandTwinRequest(request trustedActionRequest) (twin trustedActionRequest, reading actionfacts.AwkTwin, ok bool) {
	if request.Input.DialectHint != actionfacts.DialectPOSIX && request.Input.DialectHint != "" {
		return trustedActionRequest{}, actionfacts.AwkTwin{}, false
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known {
		return trustedActionRequest{}, actionfacts.AwkTwin{}, false
	}
	reading = actionfacts.AwkCommandTwinFiles(command, awkProgramFileReader(request))
	if reading.Text == "" || reading.Text == command {
		return trustedActionRequest{}, reading, false
	}
	return bashReadingRequest(request, command, reading.Text), reading, true
}

// awkProgramFileReader reads the program files of an awk call for the reach
// this gateway has: a per-user gateway runs as the user and opens them as the
// hook client does; a managed gateway behind ProtectHome cannot, and the hook
// client's answer (hookpaths.AwkFilesKey) stands for it.
func awkProgramFileReader(request trustedActionRequest) awkprog.FileReader {
	if request.ProtectedHomeHook {
		return func(string) (string, bool) { return "", false }
	}
	cwd := request.Input.CWD
	return func(name string) (string, bool) { return hookpaths.ReadProgramFile(name, cwd) }
}

// awkProgramFilesUnknown reports an awk call whose program file this gateway
// could not read or whose commands are computed, and that the hook client did
// not vouch for: the call is unknown, never an allow.
func awkProgramFilesUnknown(request trustedActionRequest, reading actionfacts.AwkTwin) bool {
	if !reading.ProgramFiles || !reading.FilesUnknown {
		return false
	}
	return !(request.ProtectedHomeHook && request.ResolvedWriteTargets[hookpaths.AwkFilesKey] == "1")
}

// awkDynamicTitle is the ship-authored title of the finding; the reason
// awkprog.DynamicReason follows it, and no program text is in either.
const awkDynamicTitle = "Awk program runs a command it cannot read, judged as unknown"

// awkCommandDynamic reports an awk call of facts (a nested shell's included)
// that runs a command not fully known.
func awkCommandDynamic(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if actionfacts.IsAwkCall(command) && actionfacts.AwkCall(command).Read().Dynamic {
			return true
		}
	}
	return false
}

// withAwkDynamicCommand adds the unknown-tier finding of an awk command the
// readers cannot read to the findings of what they did read, which keep
// deciding on their own.
func withAwkDynamicCommand(findings []RuleFinding, enforcementCapable bool) []RuleFinding {
	return withUnknownFinding(findings, unknownReasonFinding(awkDynamicTitle, awkprog.DynamicReason, enforcementCapable))
}
