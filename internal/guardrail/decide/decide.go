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

import "strings"

// Action is a guardrail verdict, ordered weakest to strongest.
type Action uint8

const (
	Allow Action = iota
	Alert
	Confirm
	Block
)

func (a Action) String() string {
	switch a {
	case Alert:
		return "alert"
	case Confirm:
		return "confirm"
	case Block:
		return "block"
	default:
		return "allow"
	}
}

// ParseAction reads an action name (block/deny, confirm/ask, alert/warn);
// anything else is Allow.
func ParseAction(s string) Action {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "block", "deny":
		return Block
	case "confirm", "ask":
		return Confirm
	case "alert", "warn", "warning":
		return Alert
	default:
		return Allow
	}
}

// Stronger is the stronger of two actions.
func Stronger(a, b Action) Action {
	if b > a {
		return b
	}
	return a
}

// Severity is a finding severity, ordered weakest to strongest.
type Severity uint8

const (
	SevNone Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevLow:
		return "LOW"
	case SevMedium:
		return "MEDIUM"
	case SevHigh:
		return "HIGH"
	case SevCritical:
		return "CRITICAL"
	default:
		return "NONE"
	}
}

// ParseSeverity reads a severity label, case-insensitive; anything else is
// SevNone.
func ParseSeverity(s string) Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return SevCritical
	case "HIGH":
		return SevHigh
	case "MEDIUM":
		return SevMedium
	case "LOW":
		return SevLow
	default:
		return SevNone
	}
}

// Tier is a rule pack's tier: its own tier field (GAP-1562), never its
// folder name.
type Tier uint8

const (
	TierDefault Tier = iota
	TierPermissive
	TierStrict
	tierCount
)

var tierNames = [...]string{TierDefault: "default", TierPermissive: "permissive", TierStrict: "strict"}

func (t Tier) String() string {
	if t < tierCount {
		return tierNames[t]
	}
	return "default"
}

// ParseTier reads a tier name; ok is false for anything else.
func ParseTier(s string) (Tier, bool) { return parseName[Tier](tierNames[:], s) }

// Deployment is how DefenseClaw is installed for the call.
type Deployment uint8

const (
	// PerUser is the OSS per-user install.
	PerUser Deployment = iota
	// Managed is an enterprise-managed install (an enterprise profile with
	// local rules).
	Managed
	deploymentCount
)

var deploymentNames = [...]string{PerUser: "per_user", Managed: "managed"}

func (d Deployment) String() string {
	if d < deploymentCount {
		return deploymentNames[d]
	}
	return "per_user"
}

// Surface is what was scanned.
type Surface uint8

const (
	// SurfaceTool is a tool call or a shell command (the trusted-action
	// readers ran on it).
	SurfaceTool Surface = iota
	// SurfaceContent is a prompt, completion, tool response or message.
	SurfaceContent
)

// Ceiling is how far a finding may move the verdict.
type Ceiling uint8

const (
	// CeilingNone: the finding enforces (block and confirm included).
	CeilingNone Ceiling = iota
	// CeilingAlert: the finding is a visible alert at most.
	CeilingAlert
	// CeilingRecord: detection only, the finding never moves the verdict.
	CeilingRecord
)

// Finding is one finding as Decide sees it.
type Finding struct {
	RuleID   string
	Severity Severity
	Proof    Proof
	Ceiling  Ceiling
}

// Levels are the severity levels of the connector and surface: block at or
// above Block, confirm (when Confirm is armed) at or above ConfirmAt, alert
// at or above Alert. They come from guardrail.block_at / alert_at / hilt at
// the global, connector and profile scopes, else the pack's tier.
type Levels struct {
	Block     Severity
	Alert     Severity
	Confirm   bool
	ConfirmAt Severity
}

// TierLevels are a pack tier's own levels: strict blocks MEDIUM and up and
// alerts LOW and up, permissive blocks CRITICAL and alerts HIGH and up,
// default blocks CRITICAL and alerts MEDIUM and up.
func TierLevels(t Tier) Levels {
	switch t {
	case TierStrict:
		return Levels{Block: SevMedium, Alert: SevLow, ConfirmAt: SevHigh}
	case TierPermissive:
		return Levels{Block: SevCritical, Alert: SevHigh, ConfirmAt: SevHigh}
	default:
		return Levels{Block: SevCritical, Alert: SevMedium, ConfirmAt: SevHigh}
	}
}

// ActionFor maps one severity by the levels.
func (l Levels) ActionFor(s Severity) Action {
	switch {
	case s == SevNone:
		return Allow
	case s >= l.Block:
		return Block
	case l.Confirm && s >= l.ConfirmAt:
		return Confirm
	case s >= l.Alert:
		return Alert
	default:
		return Allow
	}
}

// Input is everything a verdict depends on. Tier and PackTier are read
// lazily, and only when a table row needs them, so a call with no tiered
// finding never resolves the pack.
type Input struct {
	Findings []Finding
	Surface  Surface
	// Deployment selects the table column.
	Deployment Deployment
	// SecureClient is the Cisco Secure Client integration: AI Defense
	// decides, so no table row applies except a row marked secure_client.
	SecureClient bool
	// Levels map severities to actions.
	Levels Levels
	// Tier is the hook policy tier of the connector: the column of the
	// self-protection and fault rows.
	Tier func() Tier
	// PackTier is the pack posture the levels read: the column of the
	// truncated row. It is Tier in every built-in pack; the two differ only
	// for a pack whose posture comes from its folder name (GAP-1562).
	// nil reads Tier.
	PackTier func() Tier
	// Unknown is guardrail.cascade.unknown when set (alert, confirm,
	// block): it replaces the truncated row's cell in every tier. ok false
	// is "pack": the table decides.
	Unknown func() (Action, bool)
	// Table is the tier table; nil is Builtin().
	Table *Table
}

// Output is the verdict.
type Output struct {
	Action Action
	// Severity is the highest severity of the findings that enforce.
	Severity Severity
	// RuleIDs are the findings that set Action, in input order: the floor
	// rows and the findings whose severity maps to it.
	RuleIDs []string
}

// Decide is the one decision function. The order, documented once:
//
//  1. Each finding's row in the table (by its proof) gives its cell for
//     the deployment and the tier: a floor action, and whether the finding
//     still maps by its severity.
//  2. The truncated row's cell is replaced by guardrail.cascade.unknown when
//     that is set; under the Secure Client integration only rows marked
//     secure_client apply.
//  3. The findings that map by severity give the levels' action for the
//     highest enforcing severity; alert-ceiling findings add at most an
//     alert; record-ceiling findings add nothing.
//  4. The verdict is the strongest of the floors and the levels' action.
func Decide(in Input) Output {
	table := in.Table
	if table == nil {
		table = Builtin()
	}
	tierOf := lazyTier(in.Tier)
	packTierOf := tierOf
	if in.PackTier != nil {
		packTierOf = lazyTier(in.PackTier)
	}
	unknownSet := false
	var unknown Action
	unknownRead := false

	var out Output
	floor := Allow
	var floorRules []string
	var enforce, alertOnly Severity
	var levelRules []struct {
		id      string
		sev     Severity
		ceiling Ceiling
	}
	for _, f := range in.Findings {
		if f.Ceiling == CeilingRecord {
			continue
		}
		mapsBySeverity := true
		sev := f.Severity
		if f.Ceiling == CeilingNone {
			if row := table.match(f.Proof, in.Surface, in.SecureClient); row != nil {
				tier := tierOf
				if row.PackTier {
					tier = packTierOf
				}
				cell := row.cell(in.Deployment, tier)
				if row.Unknown {
					if !unknownRead {
						if in.Unknown != nil {
							unknown, unknownSet = in.Unknown()
						}
						unknownRead = true
					}
					if unknownSet {
						cell = Cell{Floor: unknown}
					}
				}
				if cell.Floor > Allow {
					if cell.Floor > floor {
						floor = cell.Floor
						floorRules = floorRules[:0]
					}
					if cell.Floor == floor {
						floorRules = append(floorRules, f.RuleID)
					}
				}
				mapsBySeverity = cell.Levels
				if cell.Severity != SevNone {
					sev = cell.Severity
				}
			}
		}
		if !mapsBySeverity {
			continue
		}
		switch f.Ceiling {
		case CeilingNone:
			enforce = max(enforce, sev)
		case CeilingAlert:
			alertOnly = max(alertOnly, sev)
		}
		levelRules = append(levelRules, struct {
			id      string
			sev     Severity
			ceiling Ceiling
		}{f.RuleID, sev, f.Ceiling})
	}
	levels := Allow
	if enforce > SevNone {
		levels = in.Levels.ActionFor(enforce)
	}
	if alertOnly > SevNone {
		levels = Stronger(levels, min(in.Levels.ActionFor(alertOnly), Alert))
	}
	out.Action = Stronger(floor, levels)
	out.Severity = enforce
	if out.Action == Allow {
		return out
	}
	if floor == out.Action {
		out.RuleIDs = append(out.RuleIDs, floorRules...)
	}
	if levels == out.Action {
		for _, r := range levelRules {
			if r.ceiling == CeilingNone && r.sev == enforce || r.ceiling == CeilingAlert && r.sev == alertOnly {
				out.RuleIDs = append(out.RuleIDs, r.id)
			}
		}
	}
	return out
}

func lazyTier(read func() Tier) func() Tier {
	var t Tier
	done := false
	return func() Tier {
		if !done {
			if read != nil {
				t = read()
			}
			done = true
		}
		return t
	}
}
