// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// appendTrustedPrivateKeyReaderFinding carries a complete reader proof across
// a home-anchored shell expansion or an exact inline pathlib read. The normal
// partial parse is retained for all other policy checks.
func appendTrustedPrivateKeyReaderFinding(
	findings []RuleFinding,
	generation *compiledRulePackCategories,
	request trustedActionRequest,
	facts actionfacts.Facts,
) []RuleFinding {
	if trustedActionOwnSSHFolderCopy(request, request.Input) {
		// A copy of the user's own SSH folder content to a private place of the
		// same home: the key is read only to be copied there, which alerts and does
		// not block, however the path scan read the operands (a glob of the folder
		// included; rel-1-0-10:GAP-0018).
		for index := range findings {
			if findings[index].RuleID == "PATH-SSH-KEY" || findings[index].RuleID == "PATH-WIN-SSH-KEY" {
				findings[index].Proof = findings[index].Proof.Advise()
			}
		}
		return appendTrustedPrivateKeyHomeCopyAlert(findings, generation, request)
	}
	proved := facts.Authoritative() && facts.EnforcementEligible() &&
		trustedActionActiveSSHPrivateKeyContentRead(facts.EnforcementProjection())
	if !proved {
		if twin, ok := actionfacts.HomeResolvedTwin(request.Input); ok {
			projection := twin.EnforcementProjection()
			proved = projection.EnforcementEligible() &&
				trustedActionActiveSSHPrivateKeyContentRead(projection)
		}
	}
	if !proved {
		if path, ok := actionfacts.ExactPythonHomePathRead(facts); ok &&
			strings.HasPrefix(path, ".ssh/") && strings.Count(path, "/") == 1 &&
			matchesSSHPrivateKey(path) && request.Input.ActiveHome != "" {
			proved = true
		}
	}
	var keyGlobCut bounded.CapSet
	if !proved {
		command := request.Input.Command
		if command == "" {
			command, _ = trustedBashCommandInput(request.Input)
		}
		dialect := request.Input.DialectHint
		switch {
		case strings.EqualFold(request.Input.Tool, "Bash") && !strings.EqualFold(request.Connector, "codex"):
			dialect = actionfacts.DialectPOSIX
		case strings.EqualFold(request.Input.Tool, "PowerShell"):
			dialect = actionfacts.DialectPowerShell
		}
		proved, keyGlobCut = hookpaths.ActionPrivateKeyReadBoundedIn(request.hookCall, command, request.Input.CWD, request.Input.ActiveHome, dialect)
		proved = proved || hookpaths.ActionMakePrivateKeyRead(command, request.Input.CWD, request.Input.ActiveHome)
		if proved && (trustedActionPrivateKeyOnlyCopiedInHome(request.Input, facts) && !trustedActionCallOpensAccess(request) ||
			trustedActionOwnSSHFolderCopy(request, request.Input)) {
			// Every command copies inside the home and nothing in the call
			// opens access (rel-1-0-10:GAP-0854): the key is read only to be
			// copied there, which alerts and does not block.
			return appendTrustedPrivateKeyHomeCopyAlert(findings, generation, request)
		}
	}
	if !proved && request.tierEnforces(tierGateStrict) && request.EnforcementCapable &&
		facts.Authoritative() && facts.EnforcementEligible() &&
		trustedActionOtherHomeSSHPrivateKeyContentRead(facts.EnforcementProjection()) {
		// A proven content read of another account's key: the strict pack
		// blocks it as it blocks the active user's; the other packs keep the
		// alert of the path rule (rel-1-0-10:GAP-0810).
		proved = true
	}
	if !proved {
		// A pattern the reader expanded only up to its cap, with no key among
		// the matches read before it, is TRUNCATED: at least the unknown tier,
		// beside what was read (the one bound rule, rel-1-0-10:GAP-1066).
		return withBoundedTruncation(findings, keyGlobCut, request)
	}
	return withProvedPrivateKeyRead(findings, generation, request)
}

// withProvedPrivateKeyRead gives findings the PATH-SSH-KEY finding of a
// proved private-key content read: the call's own finding takes the rule's
// severity and enforcement, else the rule is added.
func withProvedPrivateKeyRead(
	findings []RuleFinding,
	generation *compiledRulePackCategories,
	request trustedActionRequest,
) []RuleFinding {
	_, rule, ok := trustedActionCatalogRule(generation, "PATH-SSH-KEY")
	if !ok {
		return findings
	}
	enforcement := recordProof
	if request.EnforcementCapable {
		enforcement = enforcingProof
	}
	for index := range findings {
		if findings[index].RuleID == "PATH-SSH-KEY" ||
			findings[index].RuleID == "PATH-WIN-SSH-KEY" {
			findings[index].Proof = enforcement
			findings[index].Severity = rule.Severity
			return findings
		}
	}
	return append(findings, adjustConfidence(request.Input.Tool, RuleFinding{
		RuleID: rule.ID, Title: rule.Title, Severity: rule.Severity,
		Confidence: rule.Confidence, Evidence: trustedActionInputText(request.Input, ""),
		Tags: append([]string(nil), rule.Tags...), LineNumber: 1,
		Proof: enforcement,
	}))
}
