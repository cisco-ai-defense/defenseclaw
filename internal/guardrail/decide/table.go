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
	"bytes"
	"fmt"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Cell is what a proof is worth in one tier and deployment.
type Cell struct {
	// Floor is the least action the finding gets, whatever its severity.
	Floor Action
	// Levels keeps the finding in the severity mapping; false leaves only
	// its floor (the truncated row in the default and permissive tiers).
	Levels bool
	// Severity, when set, is the severity the finding maps with instead of
	// its own (a bound-only finding: GAP-0851, GAP-0962).
	Severity Severity
}

// Row is one row of the tier table: the proofs it matches and a cell per
// deployment and tier. An empty match list matches anything.
type Row struct {
	ID        string
	Kinds     []ProofKind
	Targets   []TargetClass
	Certainty []Certainty
	Reach     []string
	// Content: the row applies on the content surface too.
	Content bool
	// SecureClient: the row applies under the Secure Client integration.
	SecureClient bool
	// Unknown: guardrail.cascade.unknown, when set, replaces the cell.
	Unknown bool
	// PackTier: the column is the pack posture (Input.PackTier).
	PackTier bool
	// Source names the 1.0.10 rule or gap the row carries.
	Source string
	Cells  [deploymentCount][tierCount]Cell
}

// Table is the tier table, rows in match order (the first matching row
// decides a finding).
type Table struct {
	Rows []Row
}

func (t *Table) match(p Proof, surface Surface, secureClient bool) *Row {
	if p.IsZero() {
		return nil
	}
	for i := range t.Rows {
		row := &t.Rows[i]
		if surface == SurfaceContent && !row.Content || secureClient && !row.SecureClient {
			continue
		}
		if row.matches(p) {
			return row
		}
	}
	return nil
}

func (r *Row) matches(p Proof) bool {
	return (len(r.Kinds) == 0 || slices.Contains(r.Kinds, p.Kind)) &&
		(len(r.Targets) == 0 || slices.Contains(r.Targets, p.Target)) &&
		(len(r.Certainty) == 0 || slices.Contains(r.Certainty, p.Certainty)) &&
		(len(r.Reach) == 0 || slices.Contains(r.Reach, p.Reach))
}

// cell is the row's cell for d, reading the tier only when the row's cells
// for d differ by tier.
func (r *Row) cell(d Deployment, tier func() Tier) Cell {
	if d >= deploymentCount {
		d = PerUser
	}
	cells := r.Cells[d]
	if cells[TierDefault] == cells[TierPermissive] && cells[TierDefault] == cells[TierStrict] {
		return cells[TierDefault]
	}
	t := tier()
	if t >= tierCount {
		t = TierDefault
	}
	return cells[t]
}

// Row ids of the built-in table.
const (
	RowEvaluationFault = "evaluation-fault"
	RowUnverifiedPath  = "unverified-path"
	RowTruncated       = "truncated"
	RowStateWrite      = "state-write"
	RowProtectedFile   = "shell-protected-file"
)

var mutatingKinds = []ProofKind{KindWrite, KindAppend, KindDelete, KindLink, KindPerm}

func uniform(c Cell) [tierCount]Cell { return [tierCount]Cell{c, c, c} }

// Builtin is the 1.0.10 tier table, row for row what the gateway's special
// cases did before DET111 (characterized at a64bfdb931). Each built-in
// pack's tiers.yaml is its column of this table (TestShippedTiersMatchBuiltin).
func Builtin() *Table { return &builtin }

var builtin = Table{Rows: []Row{
	{
		// A call the evaluation failed on blocks in every pack
		// (rel-1-0-10:GAP-0486).
		ID: RowEvaluationFault, Kinds: []ProofKind{KindUnread}, Source: "rel-1-0-10:GAP-0486",
		Cells: [deploymentCount][tierCount]Cell{
			uniform(Cell{Floor: Block, Levels: true}), uniform(Cell{Floor: Block, Levels: true}),
		},
	},
	{
		// A managed install fails closed on a path the file system would
		// not answer for, on every surface, in every tier; per-user keeps
		// the pack's levels.
		ID: RowUnverifiedPath, Certainty: []Certainty{CertMaybe}, Reach: []string{ReachFS},
		Content: true, SecureClient: true, Source: "managedClosesOnUnverifiedPath",
		Cells: [deploymentCount][tierCount]Cell{
			uniform(Cell{Levels: true}), uniform(Cell{Floor: Block, Levels: true}),
		},
	},
	{
		// A truncated call is the unknown tier: an alert in the default and
		// permissive packs, by the levels in strict (rel-1-0-6:GAP-0675,
		// GAP-0313, GAP-0688); guardrail.cascade.unknown replaces it.
		ID: RowTruncated, Kinds: []ProofKind{KindTruncated}, Unknown: true, PackTier: true,
		Source: "rel-1-0-6:GAP-0675",
		Cells: [deploymentCount][tierCount]Cell{
			{TierDefault: {Floor: Alert}, TierPermissive: {Floor: Alert}, TierStrict: {Levels: true}},
			{TierDefault: {Floor: Alert}, TierPermissive: {Floor: Alert}, TierStrict: {Levels: true}},
		},
	},
	{
		// A proven DefenseClaw state write: at least an alert, a block in
		// strict (GAP-0747, self-protection).
		ID: RowStateWrite, Kinds: mutatingKinds, Targets: []TargetClass{TargetState},
		Certainty: []Certainty{CertKnown}, Source: "rel-1-0-10:GAP-0747",
		Cells: [deploymentCount][tierCount]Cell{
			{TierDefault: {Floor: Alert, Levels: true}, TierPermissive: {Floor: Alert, Levels: true}, TierStrict: {Floor: Block, Levels: true}},
			{TierDefault: {Floor: Alert, Levels: true}, TierPermissive: {Floor: Alert, Levels: true}, TierStrict: {Floor: Block, Levels: true}},
		},
	},
	{
		// A shell command on a protected file (authorized_keys, the ssh
		// folder, a shell profile, a git hook): never allowed silently
		// (rel-1-0-6:GAP-0675).
		ID: RowProtectedFile, Kinds: mutatingKinds,
		Targets:   []TargetClass{TargetAuthorizedKeys, TargetCredential, TargetAutostart},
		Certainty: []Certainty{CertKnown}, Source: "rel-1-0-6:GAP-0675",
		Cells: [deploymentCount][tierCount]Cell{
			uniform(Cell{Floor: Alert, Levels: true}), uniform(Cell{Floor: Alert, Levels: true}),
		},
	},
}}

// Column is one pack's tiers.yaml: the pack's own tier and its cells.
type Column struct {
	Tier Tier
	Rows []ColumnRow
}

// ColumnRow is a row of a pack's tiers.yaml.
type ColumnRow struct {
	ID      string
	PerUser Cell
	Managed Cell
}

type yamlCell struct {
	Floor    string `yaml:"floor"`
	Levels   *bool  `yaml:"levels,omitempty"`
	Severity string `yaml:"severity,omitempty"`
}

type yamlRow struct {
	ID      string   `yaml:"id"`
	Source  string   `yaml:"source,omitempty"`
	PerUser yamlCell `yaml:"per_user"`
	Managed yamlCell `yaml:"managed"`
}

type yamlColumn struct {
	Version int       `yaml:"version"`
	Tier    string    `yaml:"tier"`
	Rows    []yamlRow `yaml:"rows"`
}

// ParseColumn reads and checks a pack's tiers.yaml: version 1, a known tier,
// every row id a row of the built-in table and listed once, known actions
// and severities, and a floor of allow only where the cell keeps the levels
// (a cell that maps nothing would allow the finding silently).
func ParseColumn(data []byte) (*Column, error) {
	var raw yamlColumn
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("tiers.yaml: %w", err)
	}
	if raw.Version != 1 {
		return nil, fmt.Errorf("tiers.yaml: version %d, want 1", raw.Version)
	}
	tier, ok := ParseTier(raw.Tier)
	if !ok {
		return nil, fmt.Errorf("tiers.yaml: tier %q is not default, permissive or strict", raw.Tier)
	}
	col := &Column{Tier: tier}
	seen := map[string]bool{}
	for _, r := range raw.Rows {
		if builtin.row(r.ID) == nil {
			return nil, fmt.Errorf("tiers.yaml: unknown row %q", r.ID)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("tiers.yaml: row %q listed twice", r.ID)
		}
		seen[r.ID] = true
		perUser, err := r.PerUser.cell(r.ID, "per_user")
		if err != nil {
			return nil, err
		}
		managed, err := r.Managed.cell(r.ID, "managed")
		if err != nil {
			return nil, err
		}
		col.Rows = append(col.Rows, ColumnRow{ID: r.ID, PerUser: perUser, Managed: managed})
	}
	return col, nil
}

func (c yamlCell) cell(row, deployment string) (Cell, error) {
	floor := strings.ToLower(strings.TrimSpace(c.Floor))
	switch floor {
	case "allow", "alert", "confirm", "block":
	default:
		return Cell{}, fmt.Errorf("tiers.yaml: row %q %s: floor %q is not allow, alert, confirm or block", row, deployment, c.Floor)
	}
	out := Cell{Floor: ParseAction(floor), Levels: c.Levels == nil || *c.Levels}
	if c.Severity != "" {
		out.Severity = ParseSeverity(c.Severity)
		if out.Severity == SevNone {
			return Cell{}, fmt.Errorf("tiers.yaml: row %q %s: severity %q is not LOW, MEDIUM, HIGH or CRITICAL", row, deployment, c.Severity)
		}
	}
	if out.Floor == Allow && !out.Levels {
		return Cell{}, fmt.Errorf("tiers.yaml: row %q %s: floor allow with levels false allows the finding silently", row, deployment)
	}
	return out, nil
}

func (t *Table) row(id string) *Row {
	for i := range t.Rows {
		if t.Rows[i].ID == id {
			return &t.Rows[i]
		}
	}
	return nil
}

// WithColumn is t with col's cells in col's tier column; rows col does not
// list keep t's cells.
func (t *Table) WithColumn(col *Column) *Table {
	if col == nil {
		return t
	}
	out := &Table{Rows: slices.Clone(t.Rows)}
	for _, cr := range col.Rows {
		if row := out.row(cr.ID); row != nil {
			row.Cells[PerUser][col.Tier] = cr.PerUser
			row.Cells[Managed][col.Tier] = cr.Managed
		}
	}
	return out
}

// ColumnOf is the column of t for tier, in row order (what a pack's
// tiers.yaml holds).
func (t *Table) ColumnOf(tier Tier) *Column {
	col := &Column{Tier: tier}
	for _, r := range t.Rows {
		col.Rows = append(col.Rows, ColumnRow{ID: r.ID, PerUser: r.Cells[PerUser][tier], Managed: r.Cells[Managed][tier]})
	}
	return col
}

// MarshalColumn writes col as tiers.yaml, with each row's source as written
// in the built-in table.
func MarshalColumn(col *Column) ([]byte, error) {
	raw := yamlColumn{Version: 1, Tier: col.Tier.String()}
	for _, r := range col.Rows {
		source := ""
		if b := builtin.row(r.ID); b != nil {
			source = b.Source
		}
		raw.Rows = append(raw.Rows, yamlRow{ID: r.ID, Source: source, PerUser: toYAMLCell(r.PerUser), Managed: toYAMLCell(r.Managed)})
	}
	var buf bytes.Buffer
	buf.WriteString("# Tier table of this rule pack (DET111 D4, internal/guardrail/decide).\n")
	buf.WriteString("# One row per proof class; floor is the least action, levels false drops the\n")
	buf.WriteString("# finding from the severity mapping, severity replaces the finding's own.\n")
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(raw); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func toYAMLCell(c Cell) yamlCell {
	out := yamlCell{Floor: c.Floor.String()}
	if !c.Levels {
		f := false
		out.Levels = &f
	}
	if c.Severity != SevNone {
		out.Severity = c.Severity.String()
	}
	return out
}
