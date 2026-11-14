// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// inlineStateReading is what a shell call hands to inline-code interpreter
// children, read against the active DefenseClaw state
// (rel-1-0-10:GAP-0365, GAP-0657, GAP-0663).
type inlineStateReading struct {
	// hands is set when a handed word reaches the state (a fixed path in it,
	// or a word only a runner knows in a command that names the state).
	hands bool
	// access is the strongest access of the code that is handed such a word:
	// InlineWrites (the code names a write call) or InlineUnknown (it is not
	// proven read-only and names none). Code proven read-only is no hand-off.
	access actionfacts.InlineAccess
	// caps is what the hand-off reader left unread: a wrapper or runner
	// chain past actionfacts.InlineChainRounds, shell bodies nested past
	// hookpaths.InlineMaxShellDepth.
	caps bounded.CapSet
}

func readInlineState(facts actionfacts.Facts, request trustedActionRequest) inlineStateReading {
	command, known := trustedBashCommandInput(request.Input)
	if !known {
		return inlineStateReading{}
	}
	home := strings.TrimRight(facts.ActiveHome, "/")
	paths, caps := hookpaths.InlineHandedPaths(command, facts.CWD, home)
	reading := inlineStateReading{caps: caps}
	reaches, ok := stateReachFunc(facts, request)
	if !ok {
		return reading
	}
	mentioned, asked := false, false
	for _, handed := range paths {
		if handed.Dynamic {
			if !asked {
				asked = true
				mentioned = request.targetMemo.ActionStateTargetMention(command, request.Input.CWD, request.Input.ActiveHome) ||
					hookpaths.CommandMentionsPath(command, home, home+"/.defenseclaw")
			}
			if !mentioned {
				continue
			}
		} else if !reaches(handed.Path) {
			continue
		}
		reading.hands = true
		reading.access = max(reading.access, handed.Access)
	}
	return reading
}

// inlineHandoffStateWrite reports an inline-code interpreter child (python -c
// CODE ARG...) handed a path in the active state by code that names a write
// call: the path is a proven write of it, in every pack. Code that is not
// proven read-only and names no write gets the unknown tier instead
// (withInlineHandoffTier), and code proven read-only is no hand-off. Every
// runner is read (direct argv, sudo, env, sh -c, su -c, a variable, find
// -exec), and so is a word only a runner knows ("$f" of a while read loop) in
// a command that names the state at all. The runners that rewrite their call
// first (xargs fed by echo or printf, a for loop) reach this as the plain
// call.
func inlineHandoffStateWrite(facts actionfacts.Facts, request trustedActionRequest) bool {
	reading := readInlineState(facts, request)
	return reading.hands && reading.access == actionfacts.InlineWrites
}

// inlineUnknownStateTitle is the title of the unknown-tier finding.
const inlineUnknownStateTitle = "Inline code that may write DefenseClaw security state"

// withInlineHandoffTier is the verdict of the hand-off reading of one whole
// call, applied once by the outermost dispatch:
//   - a chain the reader left unread is TRUNCATED: the evaluation-limit
//     finding with the bound reason (at least the unknown tier of the pack,
//     the findings of what was read before it kept);
//   - inline code that is not proven read-only, handed a path in the active
//     state and naming no write call, is a possible write: an alert in the
//     default and permissive packs (a managed install's included) and a block
//     in strict, unless the call already carries an enforcing state finding.
//
// The finding is alert-only outside strict, so the self-protection floor of
// profileClassFloor (which blocks an enforcing tamper.detector_state_write in
// every profile) does not apply to a possible write.
func withInlineHandoffTier(request trustedActionRequest, findings []RuleFinding) []RuleFinding {
	if !trustedShellCommandInput(request.Input) {
		return findings
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known || !containsInlineInterpreterName(command) && !mentionsArchiveExtractor(command) {
		return findings
	}
	facts := actionfacts.Analyze(request.Input)
	reading := readInlineState(facts, request)
	if mentionsArchiveExtractor(command) {
		_, caps := hookpaths.ArchiveExtractionReading(command, facts.CWD, strings.TrimRight(facts.ActiveHome, "/"))
		reading.caps = reading.caps.Union(caps)
	}
	if reading.caps.Any() {
		findings = withBoundedTruncation(findings, reading.caps, request)
	}
	if !reading.hands || reading.access != actionfacts.InlineUnknown {
		return findings
	}
	const ruleID = "tamper.detector_state_write"
	if slices.ContainsFunc(findings, func(f RuleFinding) bool { return f.RuleID == ruleID && f.contributesToEnforcement() }) {
		return findings
	}
	finding := RuleFinding{
		RuleID: ruleID, Title: inlineUnknownStateTitle, Severity: "HIGH", Confidence: 0.80,
		Tags:     []string{"cognitive-tampering", "tampering", "security-state"},
		Evidence: trustedActionInputText(request.Input, ""), LineNumber: 1,
	}
	finding = adjustConfidence(request.Input.Tool, finding)
	switch {
	case !request.EnforcementCapable:
		finding.enforcement = findingEnforcementDetectionOnly
	case request.StrictPolicy:
		finding.enforcement = findingEnforcementAllowed
	default:
		finding.enforcement = findingEnforcementAlertOnly
	}
	return append(slices.Clip(findings), finding)
}

func containsInlineInterpreterName(command string) bool {
	for _, name := range []string{"python", "pypy", "node", "bun", "ruby", "php"} {
		if strings.Contains(command, name) {
			return true
		}
	}
	return false
}

// mentionsArchiveExtractor is the cheap gate of the archive reading.
func mentionsArchiveExtractor(command string) bool {
	for _, name := range []string{"tar", "unzip", "7z", "cpio", "ditto"} {
		if strings.Contains(command, name) {
			return true
		}
	}
	return false
}
