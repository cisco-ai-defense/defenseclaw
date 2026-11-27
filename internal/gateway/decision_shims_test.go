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

package gateway

import (
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
)

// The unit tests of the tier rules were written against the 1.0.10
// entry points (guardrailActionForProfile, profileClassFloor, ...) with a
// severity -> action closure. These test-only forms keep those tests as
// they are and run them through decide.Decide: the closure becomes the
// levels it maps by (levelsFromActionFor), the strict closure the tier, and
// the unknown closure the cascade unknown tier ("" maps the limit finding by
// the levels: the strict pack column).

var decideProbeSeverities = []decide.Severity{decide.SevLow, decide.SevMedium, decide.SevHigh, decide.SevCritical}

// levelsFromActionFor is the decide.Levels a monotone severity -> action
// closure maps by.
func levelsFromActionFor(actionFor func(severity string) string) decide.Levels {
	never := decide.Severity(255)
	l := decide.Levels{Block: never, Alert: never, ConfirmAt: never}
	for _, sev := range decideProbeSeverities {
		switch normalizedGuardrailAction(actionFor(sev.String())) {
		case guardrailActionBlock:
			l.Block = min(l.Block, sev)
			l.Alert = min(l.Alert, sev)
		case guardrailActionConfirm:
			l.Confirm = true
			l.ConfirmAt = min(l.ConfirmAt, sev)
			l.Alert = min(l.Alert, sev)
		case guardrailActionAlert:
			l.Alert = min(l.Alert, sev)
		}
	}
	return l
}

func strictTierFn(strict func() bool) func() decide.Tier {
	return func() decide.Tier {
		if strict != nil && strict() {
			return decide.TierStrict
		}
		return decide.TierDefault
	}
}

func guardrailActionForProfile(
	findings []RuleFinding, secureClient bool, strict func() bool, actionFor func(severity string) string,
) string {
	return guardrailActionForProfileUnknown(findings, secureClient, strict, func() string {
		if strict() {
			return ""
		}
		return guardrailActionAlert
	}, actionFor)
}

func guardrailActionForProfileUnknown(
	findings []RuleFinding, secureClient bool, strict func() bool, unknown func() string,
	actionFor func(severity string) string,
) string {
	var u string
	read := false
	unknownOnce := func() string {
		if !read {
			u, read = unknown(), true
		}
		return u
	}
	return decideAction(decide.Decide(decide.Input{
		Findings: decideFindings(findings), SecureClient: secureClient,
		Levels: levelsFromActionFor(actionFor), Tier: strictTierFn(strict),
		PackTier: func() decide.Tier {
			if unknownOnce() == "" {
				return decide.TierStrict
			}
			return decide.TierDefault
		},
		Unknown: func() (decide.Action, bool) {
			if v := unknownOnce(); v != "" {
				return decide.ParseAction(v), true
			}
			return decide.Allow, false
		},
	}).Action)
}

func profileClassFloor(findings []RuleFinding, secureClient bool, strict func() bool) string {
	never := decide.Severity(255)
	return decideAction(decide.Decide(decide.Input{
		Findings: decideFindings(findings), SecureClient: secureClient,
		Levels: decide.Levels{Block: never, Alert: never, ConfirmAt: never}, Tier: strictTierFn(strict),
		// The class floor never read the unknown tier: a limit finding maps
		// by the (never) levels.
		PackTier: func() decide.Tier { return decide.TierStrict },
	}).Action)
}

func guardrailActionForFindings(findings []RuleFinding, actionFor func(severity string) string) string {
	return decideAction(decide.Decide(decide.Input{
		Findings: decideFindings(findings), Surface: decide.SurfaceContent, Levels: levelsFromActionFor(actionFor),
	}).Action)
}

func cascadeUnknownForConfig(cfg *config.Config, connector string) string {
	if cfg == nil || cfg.SecureClientIntegration() {
		return ""
	}
	in := decideInputForConfig(cfg, connector, nil, false, false, false)
	if a, ok := in.Unknown(); ok {
		return decideAction(a)
	}
	if in.PackTier() == decide.TierStrict {
		return ""
	}
	return guardrailActionAlert
}
