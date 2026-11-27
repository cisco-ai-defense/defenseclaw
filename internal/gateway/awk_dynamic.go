// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/awkprog"
	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
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
	return !request.ProtectedHomeHook || request.ResolvedWriteTargets[hookpaths.AwkFilesKey] != "1"
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
		// The same awk call behind a wrapper (env, sudo, timeout, chroot,
		// xargs ...) is as dynamic as the bare call (rel-1-0-10:GAP-0859).
		if inner, ok := actionfacts.AwkCallBehindWrappers(command); ok && actionfacts.AwkCall(inner).Read().Dynamic {
			return true
		}
	}
	return false
}

// awkDynamicBoundBySimpleCommands reports a call whose awk words are built
// only from variables the call assigns as literals before it (out=report.txt;
// awk "BEGIN {print 1 >> \"$out\"}"): the simple-command pass binds them and
// judges each awk call on its bound text, so the call as written is not an
// awk program built at run time. A call with a simple command the pass cannot
// read, with an awk call still built at run time after the binding, or with a
// bound program that starts a command, keeps the unknown tier
// (rel-1-0-10:GAP-0729).
func awkDynamicBoundBySimpleCommands(request trustedActionRequest, facts actionfacts.Facts) bool {
	simples := request.simpleMemo.commands(request.Input, facts)
	if len(simples) == 0 {
		return false
	}
	for _, simple := range simples {
		if simple.EvaluationFailure != "" || simple.Text == "" {
			return false
		}
		input := request.Input
		input.Command, input.Args, input.Argv = simple.Text, nil, nil
		if simple.CWD != "" {
			input.CWD = simple.CWD
		}
		facts := actionfacts.Analyze(input)
		if awkCommandDynamic(facts) || awkStartsCommands(facts) {
			return false
		}
	}
	return true
}

// awkStartsCommands reports an awk call of facts whose program starts a
// command (system(), print |, | getline). Bound or not, such a call keeps the
// unknown tier when the call as written built its program at run time: the
// hook client resolved no targets for the commands of the bound reading
// (TestAwkSpellingRowsReachTheRule A20, A21: P='BEGIN{system(...)}'; awk "$P").
// A print redirect into a literal file starts no command: the bound reading
// judges its write and the hook client lists its target (GAP-2197), so it
// keeps no unknown tier (rel-1-0-10:GAP-1566).
func awkStartsCommands(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if actionfacts.IsAwkCall(command) && actionfacts.AwkCall(command).Read().Starts {
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

// withAwkInetRecordEffects carries a proven gawk record-to-network flow into
// the effect reading. awkprog proves the sole unguarded record action and a
// bounded list of static input files; the ordinary shell extractor then
// resolves those files and links each read to the send exactly as it does for
// the equivalent plain redirect. A sink without that proof adds no effects.
func withAwkInetRecordEffects(request trustedActionRequest, base effects.Result, opts effects.Options) effects.Result {
	if opts.Flavor != effects.FlavorPOSIX || len(base.Unknowns) != 0 ||
		request.Input.DialectHint != "" && request.Input.DialectHint != actionfacts.DialectPOSIX {
		return base
	}
	command, ok := trustedBashCommandInput(request.Input)
	if !ok || !strings.Contains(command, "awk") {
		return base
	}
	facts := actionfacts.Analyze(request.Input)
	if facts.Parse.Status == actionfacts.StatusLimitExceeded {
		return base
	}
	var body string
	for _, command := range facts.Commands {
		if !actionfacts.IsAwkCall(command) || command.ParentCommandID != 0 ||
			command.ControlFlowUncertain {
			continue
		}
		reading := actionfacts.AwkCall(command).Read()
		if !reading.NetworkSink || !reading.NetworkRecordFlow || reading.Body == "" {
			continue
		}
		if body != "" {
			return base // several proven flows need their own ordering proof
		}
		body = reading.Body
	}
	if body == "" {
		return base
	}
	projected := effects.Extract(effects.Call{Surface: effects.SurfaceShell,
		Tool: request.Input.Tool, Command: body}, opts)
	if len(projected.Unknowns) != 0 {
		return base
	}
	sentRead := false
	for i, effect := range projected.Effects {
		if effect.Kind == effects.KindRead {
			if flow, _ := effectReadFlowTo(projected, i); flow == decide.FlowSent {
				sentRead = true
				break
			}
		}
	}
	if !sentRead {
		return base
	}
	offset := len(base.Effects)
	extra := make([]effects.Effect, 0, len(projected.Effects))
	for _, effect := range projected.Effects {
		if effect.Data != nil {
			data := *effect.Data
			data.Sources = append([]effects.Source(nil), data.Sources...)
			for i := range data.Sources {
				if data.Sources[i].Kind == effects.SourceEffect {
					if data.Sources[i].Effect <= 0 || data.Sources[i].Effect > len(projected.Effects) {
						return base
					}
					data.Sources[i].Effect += offset
				}
			}
			effect.Data = &data
		}
		extra = append(extra, effect)
	}
	base.Effects = append(base.Effects, extra...)
	return base
}
