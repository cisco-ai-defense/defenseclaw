// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/awkprog"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// awkCommandTwinRequest returns the request for actionfacts.AwkCommandTwin of
// a POSIX Bash call: the reading in which each command an awk program starts
// is the group that runs it, judged as the hook running it directly. Behind
// ProtectHome (managed hook peer) the hook client map lists the targets of the
// same reading (hookpaths). Only a block of that reading counts; the
// findings of the call as written stand. caps is what the reading could not
// read (an awk program in shell STRINGs nested past the bound).
func awkCommandTwinRequest(request trustedActionRequest) (twin trustedActionRequest, caps bounded.CapSet, ok bool) {
	if request.Input.DialectHint != actionfacts.DialectPOSIX && request.Input.DialectHint != "" {
		return trustedActionRequest{}, bounded.CapSet{}, false
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known {
		return trustedActionRequest{}, bounded.CapSet{}, false
	}
	reading := actionfacts.AwkCommandTwin(command)
	if reading.Text == "" || reading.Text == command {
		return trustedActionRequest{}, reading.Truncated, false
	}
	return bashReadingRequest(request, command, reading.Text), reading.Truncated, true
}

// awkDynamicTitle is the ship-authored title of the finding; the reason
// awkprog.DynamicReason follows it, and no program text is in either.
const awkDynamicTitle = "Awk program runs a command it cannot read, judged as unknown"

// awkCommandDynamic reports an awk call of facts (a nested shell's included)
// that runs a command not fully known.
func awkCommandDynamic(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if !command.ArgvComplete || len(command.Argv) < 2 {
			continue
		}
		switch command.Program {
		case "awk", "gawk", "mawk", "nawk":
			if _, dynamic := awkprog.ArgvShell(command.Argv); dynamic {
				return true
			}
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
