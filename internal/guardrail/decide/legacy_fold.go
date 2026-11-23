// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"slices"
	"strings"
)

// SourceEffects is the Proof.Source of every effects-lane finding (the
// effect model beside the 1.0.10 readers).
const SourceEffects = "effects"

// legacySet is the protected set a 1.0.10 rule names: the target classes
// its findings grade and, for a credential file rule, the file class.
type legacySet struct {
	targets []TargetClass
	set     string
}

var credentialTargets = []TargetClass{TargetCredential, TargetOtherHomeCredential}

// legacySetRules are the 1.0.10 rules that each name one protected set, by
// canonical (upper-case) rule id. A finding of one of them is graded by its
// own reader's cell in every tier and deployment; that cell is what the set
// is worth in the call.
var legacySetRules = map[string]legacySet{
	RuleStateWrite:          {targets: []TargetClass{TargetState}},
	RuleAuthorizedKeysWrite: {targets: []TargetClass{TargetAuthorizedKeys}},
	RuleShellProfileWrite:   {targets: []TargetClass{TargetAutostart}},
	RuleGitHookWrite:        {targets: []TargetClass{TargetAutostart}},
	RuleSSHDir:              {targets: credentialTargets},
	"PATH-SSH-KEY":          {targets: credentialTargets, set: SetSSHPrivateKey},
	"PATH-WIN-SSH-KEY":      {targets: credentialTargets, set: SetSSHPrivateKey},
	"PATH-AWS-CREDS":        {targets: credentialTargets, set: SetAWSCredentials},
	"PATH-WIN-AWS-CREDS":    {targets: credentialTargets, set: SetAWSCredentials},
	"PATH-GIT-CREDS":        {targets: credentialTargets, set: SetGitCredentials},
	"PATH-WIN-GIT-CREDS":    {targets: credentialTargets, set: SetGitCredentials},
	"PATH-NETRC":            {targets: credentialTargets, set: SetGitCredentials},
	"PATH-WIN-NETRC":        {targets: credentialTargets, set: SetGitCredentials},
	"PATH-NPMRC":            {targets: credentialTargets, set: SetNpmrc},
	"PATH-PYPIRC":           {targets: credentialTargets, set: SetPypirc},
	"PATH-KUBE":             {targets: credentialTargets, set: SetKubeConfig},
	"PATH-WIN-KUBE-CONFIG":  {targets: credentialTargets, set: SetKubeConfig},
	"PATH-DOCKER":           {targets: credentialTargets, set: SetDockerConfig},
	// The agent instruction file rule (CLAUDE.md), a content rule on a
	// member of the hook config set: its 1.0.10 cell is what the file is
	// worth in the call (GAP-1797).
	"COG-CLAUDE-MD": {targets: []TargetClass{TargetHookConfig}},
	// The agent hook config guard rule, in the upper case NamesSet looks up.
	strings.ToUpper(RuleHookConfigWrite): {targets: []TargetClass{TargetHookConfig}},
}

// Effect-lane rule ids (the gateway's effect.protected_target_<tier>).
const (
	RuleEffectRestricted = "effect.protected_target_restricted"
	RuleEffectUnknown    = "effect.protected_target_unknown"
)

// ShadowOnly reports an effects-lane finding the built-in table records in
// every tier and deployment (RowRecord, RowEffectUnknown,
// RowEffectContentDecided, RowEffectLink, RowEffectRead): it never moves the live verdict, so the effect
// join keeps it out of the call's findings, the one place the rule holds
// for every route.
func ShadowOnly(f Finding) bool {
	if f.Proof.Source != SourceEffects {
		return false
	}
	row := builtin.match(f, SurfaceTool, false)
	if row == nil {
		return false
	}
	for _, cells := range row.Cells {
		for _, c := range cells {
			if c.Ceiling != CeilingRecord {
				return false
			}
		}
	}
	return true
}

// NamesSet reports that ruleID is a 1.0.10 rule naming the protected set of
// proof p: p's target is a class the rule grades and, when both name a
// credential file class, the same class.
func NamesSet(ruleID string, p Proof) bool {
	n, ok := legacySetRules[strings.ToUpper(strings.TrimSpace(ruleID))]
	if !ok || !slices.Contains(n.targets, p.Target) {
		return false
	}
	return p.Set == "" || n.set == "" || n.set == p.Set
}

// FoldsIntoLegacy reports that effects-lane finding f takes the tier of a
// 1.0.10 finding of the same call (DET111 ruling A, 2026-11-22T08:30Z: the
// GAP-1244 rule, a spelling takes the cell of the 1.0.10 rule naming the
// same file class, generalised from reads to every known effect). f is known
// (or known and graded alert-only) on a protected set, and a finding of the
// call that is not the effect lane's carries the 1.0.10 rule naming that
// set. That rule's own cell is what the set is worth in this call, so f is
// folded into it and adds no action and no severity of its own: the effect
// lane never grades a set above the rule that names it (a variant spelling
// gets the plain spelling's tier, never above it). Where no 1.0.10 finding
// of the call names the set (a spelling only the effect lane resolves), f
// stands and its own table row decides. A Known protected write finding
// (RowKnownProtectedWrite) carries the rule of the plain spelling on its
// set, so it names the set as the 1.0.10 finding does: the effect lane
// finding beside it folds into it, and the call carries the rules of the
// plain spelling only (GAP-1243, GAP-1308 after the GAP-1478 ruling of
// 2026-11-23).
func FoldsIntoLegacy(f Finding, call []Finding) bool {
	p := f.Proof
	if p.Source != SourceEffects || !(p.Certainty == CertKnown || p.Advisory()) {
		return false
	}
	known := knownProtectedWrite(f)
	for _, g := range call {
		// A 1.0.10 finding names its set; a Known protected write finding
		// names it for the other effect findings of the call, never for
		// itself or another Known write.
		names := g.Proof.Source != SourceEffects || (!known && knownProtectedWrite(g))
		if names && NamesSet(g.RuleID, p) {
			return true
		}
	}
	return false
}

// knownProtectedWrite reports a Known protected write finding of the effects
// lane (RowKnownProtectedWrite): a resolved write or append proof on a
// restricted set that carries the rule the plain spelling fires on it
// (RuleFor). An effect finding that only bears such a rule id, without that
// proof, is not one: it names no set.
func knownProtectedWrite(f Finding) bool {
	p := f.Proof
	if p.Source != SourceEffects || (p.Kind != KindWrite && p.Kind != KindAppend) {
		return false
	}
	rule := RuleFor(p)
	return rule != "" && strings.EqualFold(rule, strings.TrimSpace(f.RuleID))
}
