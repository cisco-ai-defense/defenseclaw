// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import "github.com/defenseclaw/defenseclaw/internal/guardrail/decide"

// joinEffectFindings is the call's findings with the effect lane's joined
// (raise only). An effect finding whose protected set a 1.0.10 finding of
// the call names is folded into that finding (decide.FoldsIntoLegacy, DET111
// ruling A): the rule naming the set already grades it with its own 1.0.10
// cell, so the effect finding adds no action and no verdict severity. Every
// other effect finding joins and its tier table row decides. The fold reads
// the same decide findings Decide and the verdict severity read.
func joinEffectFindings(findings, effect []RuleFinding) []RuleFinding {
	if len(effect) == 0 {
		return findings
	}
	call := decideFindings(findings)
	for _, f := range effect {
		if decide.FoldsIntoLegacy(decideFinding(f), call) {
			continue
		}
		findings = append(findings, f)
	}
	return findings
}
