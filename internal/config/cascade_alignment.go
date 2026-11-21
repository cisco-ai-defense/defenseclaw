// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

// CascadeLaneAlignment is the alignment check (rel-1-0-10:GAP-0553): on a
// side-effecting tool call the judge model is asked whether the call is
// needed for, or consistent with, the task the user gave, and a call that is
// not gets its own finding, ALIGNMENT-DRIFT. It never changes or removes
// a finding of the rules, System One or the tool judge.
//
//	off     the lane does not run (the shipped default)
//	shadow  the lane runs and records its finding in the audit only
//	alert   ALIGNMENT-DRIFT alerts
//	block   ALIGNMENT-DRIFT blocks
//
// The lane needs a configured judge (guardrail.judge); without one it is
// off whatever it is set to. A judge failure or a late answer is no finding.
const CascadeLaneAlignment = "alignment"

func init() {
	RegisterCascadeLane(CascadeLane{
		Name:    CascadeLaneAlignment,
		Default: CascadeLaneOff,
		Values:  []string{CascadeLaneOff, CascadeLaneShadow, CascadeLaneAlert, CascadeLaneBlock},
		Description: "alignment check: the judge asks whether a side-effecting tool call serves the task the user gave; " +
			"its own finding ALIGNMENT-DRIFT (off, shadow, alert or block)",
	})
}
