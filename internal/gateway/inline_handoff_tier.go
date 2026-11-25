// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/textlower"
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
	// A gateway behind ProtectHome receives no cwd of its own: the code is
	// placed where the hook client ran the call, so a file it opens by an
	// absolute name is read too (rel-1-0-10:GAP-1134).
	cwd := facts.CWD
	if client, placed := protectedHomeReportedDirectory(request); placed {
		cwd = client
	}
	paths, caps := hookpaths.InlineHandedPaths(command, cwd, home)
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
// The finding is alert-only outside strict: a possible write never blocks
// where a proven one alerts.
func withInlineHandoffTier(ctx context.Context, request trustedActionRequest, findings []RuleFinding) []RuleFinding {
	if !trustedShellCommandInput(request.Input) {
		return findings
	}
	findings = withFindChildTwins(ctx, request, findings)
	command, known := trustedBashCommandInput(request.Input)
	if !known || !containsInlineInterpreterName(command) && !mentionsArchiveExtractor(command) {
		return findings
	}
	facts := actionfacts.Analyze(request.Input)
	reading := readInlineState(facts, request)
	if mentionsArchiveExtractor(command) {
		archives := readArchiveState(facts, request)
		reading.caps = reading.caps.Union(archives.caps)
		// Members nothing tells (the words name none, the archive cannot be
		// listed) may be a file of the state below a folder that holds it:
		// the unknown tier (rel-1-0-10:GAP-0142, GAP-1173).
		if archives.possible && !archives.writes && !reading.hands {
			reading.hands, reading.access = true, actionfacts.InlineUnknown
		}
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
		finding.Proof = finding.Proof.Record()
	default:
		finding.Proof = request.tieredProof(finding.Proof, tierGateStrict)
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

// mentionsArchiveExtractor is the cheap gate of the unknown-tier archive
// reading: the shell extractors, the Python archive modules and the
// PowerShell extractions (rel-1-0-10:GAP-1173). It reads the text as the
// shell reads a program word, without quotes and backslashes and in any
// case, so 'un'zip, t\ar and TAR pass it (rel-1-0-10:GAP-1223).
func mentionsArchiveExtractor(command string) bool {
	text := textlower.Lower(archiveGateText.Replace(command))
	for _, name := range []string{"tar", "unzip", "7z", "cpio", "ditto", "zipfile", "unpack_archive", "expand-archive", "extracttodirectory"} {
		if strings.Contains(text, name) {
			return true
		}
	}
	return false
}

var archiveGateText = strings.NewReplacer(`'`, "", `"`, "", `\`, "", "`", "")

// withFindChildTwins judges each program a find runs (-exec, -execdir, -ok,
// -okdir) as a call of its own, with the handed entry put as a plain file of
// the working folder: what the child names itself (sort -o STATE, an install
// destination, a redirect in an sh -c body) is reached as it would be run
// directly. A proven state or hook config finding of the twin is added to the
// call's findings (rel-1-0-10:GAP-0501, GAP-0660).
func withFindChildTwins(ctx context.Context, request trustedActionRequest, findings []RuleFinding) []RuleFinding {
	command, known := trustedBashCommandInput(request.Input)
	if !known || !strings.Contains(command, "find") || !strings.Contains(command, "-exec") &&
		!strings.Contains(command, "-ok") {
		return findings
	}
	children := hookpaths.FindExecChildCommands(command, request.Input.CWD, strings.TrimRight(request.Input.ActiveHome, "/"))
	for _, child := range children[:min(len(children), 4)] {
		twin := operandBoundReading(request, child)
		twin.targetMemo, twin.simpleMemo = nil, nil
		// The twin is a reading of the call, not a call: the call records its
		// own facts for the tool-call chains. Recording the twin replaced
		// them, so a find -exec read of a credentials file started no
		// secret-read chain (substrate-1:GAP-0349 Q23).
		twin.record = nil
		got := dispatchTrustedAction(ctx, twin)
		got = agentHookConfigFindings(ctx, twin, got)
		for _, found := range got {
			if !found.contributesToEnforcement() ||
				found.RuleID != "tamper.detector_state_write" && found.RuleID != agentHookConfigWriteRuleID &&
					found.RuleID != agentHookConfigDisableRuleID {
				continue
			}
			if !slices.ContainsFunc(findings, func(f RuleFinding) bool {
				return f.RuleID == found.RuleID && f.contributesToEnforcement()
			}) {
				findings = append(slices.Clip(findings), found)
			}
		}
	}
	return findings
}
