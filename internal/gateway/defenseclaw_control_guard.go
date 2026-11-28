// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// The DefenseClaw self-protection rules (GAP-0596, claim C4). A tool call
// that runs the DefenseClaw CLI or gateway to turn the guardrail off, or a
// service manager or kill to stop its services, has the effect of the file
// write tamper.detector_state_write already reports. Both rules are code-owned
// (their pack pattern is inert): the proof is the parse
// (actionfacts.DefenseClawControl), the tiers are the packs' severities.
//
//	tamper.defenseclaw_control_disable   CRITICAL: a proven stop, disable,
//	    uninstall, reset, weaker mode or configuration change. Owner ruling
//	    (2026-11-14): an alert in the default and permissive packs of a
//	    per-user install, a block in the strict pack and in every managed
//	    install. On the owner's DefenseClaw development traces a block in the
//	    default pack stopped 25 agent sessions that test DefenseClaw. The
//	    pack data keeps the rule at CRITICAL; the per-user default and
//	    permissive tiers build the finding alert-only (the same split as an
//	    unresolved authorized-keys write, unprovenKeyWriteMayWarn).
//	tamper.defenseclaw_control_unproven  HIGH: a DefenseClaw command or a
//	    dynamic target the parse could not resolve. The unknown tier: an
//	    alert in the default and permissive packs, a block in strict.
const (
	defenseClawControlDisableRuleID  = "tamper.defenseclaw_control_disable"
	defenseClawControlUnprovenRuleID = "tamper.defenseclaw_control_unproven"
)

// defenseClawControlReader is actionfacts.DefenseClawControl; tests replace
// it to inject a reader fault.
var defenseClawControlReader = actionfacts.DefenseClawControl

// defenseClawControlFindings adds the DefenseClaw self-protection findings of
// one call. A rule the active pack does not hold adds nothing. Read-only
// DefenseClaw commands and restarts add nothing.
func defenseClawControlFindings(ctx context.Context, request trustedActionRequest, findings []RuleFinding) []RuleFinding {
	if !request.EnforcementCapable || request.SkipLocalFilesystemResolution || isSandboxHookRequest(ctx) {
		return findings
	}
	text := agentHookConfigRawShellCommand(request.Input)
	if text == "" && len(request.Input.Argv) != 0 {
		text = strings.Join(request.Input.Argv, " ")
	}
	if text == "" {
		return findings
	}
	controls := defenseClawControlReader(actionfacts.Analyze(request.Input), text)
	// A program run through static prefix wrappers that hand it its argv
	// unchanged (chrt -i 0 pkill -f defenseclaw, taskset 0x1 defenseclaw
	// uninstall --all) is read as its plain call too (GAP-1494,
	// actionfacts.WrapperUnwrapExactTwin).
	if twin, ok := actionfacts.WrapperUnwrapExactTwin(text); ok {
		input := request.Input
		input.Command, input.Args, input.Argv = twin, nil, nil
		controls = append(controls, defenseClawControlReader(actionfacts.Analyze(input), twin)...)
	}
	if len(controls) == 0 {
		return findings
	}
	out := append([]RuleFinding(nil), findings...)
	if fault := slices.IndexFunc(controls, func(control actionfacts.DefenseClawControlFact) bool {
		return control.Kind == actionfacts.DefenseClawControlFault
	}); fault >= 0 {
		// A reader fault is the evaluation fault of the call, the answer of
		// trustedToolCallFindings' recovery (a block in every pack and mode),
		// with the facts read before it kept (GAP-1936).
		logEvaluatorFault("defenseclaw control connector="+request.Connector, controls[fault].Fault)
		out = withEvaluationFaultFinding(out, evaluatorFaultTitle, request.EnforcementCapable)
		controls = slices.Delete(slices.Clone(controls), fault, fault+1)
	}
	generation := snapshotRulePackGenerationFor(ctx, request.Connector)
	if generation == nil {
		return out
	}
	// A proven self-disable is an alert where the user runs DefenseClaw
	// themselves with the default or permissive pack, a block under the strict
	// pack and in every managed install.
	add := func(ruleID, note string, tiered bool) {
		if slices.ContainsFunc(out, func(finding RuleFinding) bool { return finding.RuleID == ruleID }) {
			return
		}
		_, rule, ok := trustedActionCatalogRule(generation, ruleID)
		if !ok {
			return
		}
		out = append(out, RuleFinding{
			RuleID: rule.ID, Title: rule.Title + " (" + note + ")", Severity: rule.Severity, Confidence: rule.Confidence,
			Evidence: "defenseclaw " + note, Tags: append([]string(nil), rule.Tags...), LineNumber: 1,
			proof: newExactFallbackFindingProof(rule.ID, true, true, true, true),
		})
		if tiered {
			out[len(out)-1].Proof = request.tieredProof(out[len(out)-1].Proof, tierGateManaged)
		}
	}
	for _, control := range controls {
		if control.Proven {
			add(defenseClawControlDisableRuleID, string(control.Kind), true)
		} else {
			add(defenseClawControlUnprovenRuleID, string(control.Kind), false)
		}
	}
	return out
}
