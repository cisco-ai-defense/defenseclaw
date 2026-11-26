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
	// its own, and its verdict severity (a bound-only finding is MEDIUM:
	// GAP-0851, GAP-0962).
	Severity Severity
	// Ceiling caps what the finding may do: CeilingAlert is an alert at
	// most (its floor too), CeilingRecord never moves the verdict.
	Ceiling Ceiling
}

// Row is one row of the tier table: the proofs it matches and a cell per
// deployment and tier. An empty match list matches anything.
type Row struct {
	ID string
	// Rules: the row matches only a finding of one of these rule ids
	// (case-insensitive), with or without a proof. A row with no rules
	// matches a finding by its proof only, and never a finding with none.
	Rules     []string
	Kinds     []ProofKind
	Targets   []TargetClass
	Certainty []Certainty
	Reach     []string
	// Sets: the row matches only a proof naming one of these file classes
	// (Proof.Set); empty matches any proof, with or without a set.
	Sets []string
	// Sources: the row matches only a proof from one of these readers
	// (Proof.Source, e.g. SourceEffects); empty matches any reader. It keeps
	// an effects-lane row off the 1.0.10 reader's finding of the same rule.
	Sources []string
	// LinkAt: the row matches only a proof that is not a link to the member
	// (Proof.LinkTo false): a link placed at the member, or any other kind.
	LinkAt bool
	// Flows: the row matches only a proof whose content flow is one of
	// these (Proof.Flow); empty matches any flow.
	Flows []ReadFlow
	// Content: the row applies on the content surface too.
	Content bool
	// SecureClient: the row applies under the Secure Client integration.
	SecureClient bool
	// Unknown: guardrail.cascade.unknown, when set, replaces the cell.
	Unknown bool
	// PackTier: the column is the pack posture (Input.PackTier).
	PackTier bool
	// Gate: the row grades a reader's tiered conclusion by name
	// (Table.GateCeiling); it never matches a finding's proof.
	Gate bool
	// Source names the 1.0.10 rule or gap the row carries.
	Source string
	Cells  [deploymentCount][tierCount]Cell
}

// Table is the tier table, rows in match order (the first matching row
// decides a finding).
type Table struct {
	Rows []Row
}

// match is the first row that decides f: a rule row when f's rule is
// listed (and its proof matches the row's proof selectors), else a proof
// row when f has a proof. Gate rows never match a finding.
func (t *Table) match(f Finding, surface Surface, secureClient bool) *Row {
	noProof := f.Proof.IsZero()
	for i := range t.Rows {
		row := &t.Rows[i]
		if row.Gate {
			continue
		}
		if len(row.Rules) > 0 {
			if !slices.ContainsFunc(row.Rules, func(id string) bool { return strings.EqualFold(id, strings.TrimSpace(f.RuleID)) }) {
				continue
			}
		} else if noProof {
			continue
		}
		if surface == SurfaceContent && !row.Content || secureClient && !row.SecureClient {
			continue
		}
		if row.matches(f.Proof) {
			return row
		}
	}
	return nil
}

func (r *Row) matches(p Proof) bool {
	return (len(r.Kinds) == 0 || slices.Contains(r.Kinds, p.Kind)) &&
		(len(r.Targets) == 0 || slices.Contains(r.Targets, p.Target)) &&
		(len(r.Certainty) == 0 || slices.Contains(r.Certainty, p.Certainty)) &&
		(len(r.Reach) == 0 || slices.Contains(r.Reach, p.Reach)) &&
		(len(r.Sets) == 0 || slices.Contains(r.Sets, p.Set)) &&
		(len(r.Sources) == 0 || slices.Contains(r.Sources, p.Source)) &&
		(!r.LinkAt || !p.LinkTo) &&
		(len(r.Flows) == 0 || slices.Contains(r.Flows, p.Flow))
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
	RowRecord              = "record"
	RowKnownProtectedWrite = "known-protected-write"
	// RowEffectUnknown: the effect lane's unknown tier is a shadow record on
	// every set and never moves the live verdict, whatever its Known flag,
	// target or tier (the MAYBE rule, DET111 PLAN 5.3, GAP-1796; DET111
	// ruling 2026-11-22T17:00Z: the target-decided exception raised 70
	// benign cells of the T17 large-trace sweep, 26 of them new blocks).
	RowEffectUnknown = "effect-unknown"
	// RowEffectContentDecided: a set whose 1.0.10 rule is decided by the
	// content written, not by the target (persistence.shell_profile_write on
	// the shell startup files): the effect lane proves the target only, so
	// its write there is a shadow record until the effects IR carries the
	// content (GAP-1795). Target-decided sets (authorized_keys, DefenseClaw
	// state, hook config, credential files) keep their rows.
	RowEffectContentDecided = "effect-content-decided"
	// RowEffectOwnKeyWrite: a Known effects write or mode change of one's
	// own SSH private key file (~/.ssh/id_rsa and its siblings) is a shadow
	// record. No 1.0.10 rule names that shape (PATH-SSH-KEY grades
	// reads of the key, persistence.ssh_authorized_keys_command the keys
	// file), so 1.0.10 allows it; the provisioning step that installs a
	// deploy key from the environment into ~/.ssh is benign (rel-1-0-10:
	// GAP-1878, infraset-v1: 9 benign rows raised to alert and strict
	// block). A read or copy of an existing key keeps its PATH-SSH-KEY row
	// (the read proof is its own finding), and a write of authorized_keys
	// keeps its row. An append changes the key file that is there, so it is
	// not the install shape and keeps the credential row (rel-1-0-10:
	// GAP-1666/114, `timeout --signal=KILL 5 echo marker >> ~/.ssh/id_ed25519`
	// CRITICAL at 1.0.10: with its effect finding recorded the call fell to
	// PATH-SSH-DIR HIGH beside the bound MEDIUM).
	RowEffectOwnKeyWrite = "effect-own-key-write"
	// RowEffectLink: a Known effects link placed at a protected member other
	// than the DefenseClaw state (ln -s T ~/.ssh/authorized_keys, the
	// dotfiles shape) is a shadow record. The 1.0.10 reader of the set blocks
	// every plain spelling of it on its own (persistence.ssh_authorized_keys_command),
	// and the effect finding folds there; the effects reading of a script
	// spelling that reader does not name raised 6 benign owner cells of the
	// T17 sweep, all new blocks. A link at the state keeps its row
	// (self-protection), and so does a link TO a member (Proof.LinkTo: ln -s
	// ~/.ssh/authorized_keys s, then a write through s; GAP-1530, GAP-1538,
	// GAP-1548, GAP-0659), which the row once muted on 15 attack cells.
	RowEffectLink = "effect-link"
	// RowEffectRead: a Known read of one's own credential file the effects
	// lane proves, whose content stays local (Proof.Flow FlowNone: counted,
	// tested, discarded, or copied beside the file), is a shadow record.
	// Those shapes (grep -c, install of a key to a .bak) raised 12 benign
	// owner cells (6 new blocks) of the T17 sweep (GAP-1825, GAP-1826). A
	// read whose content is shown to the agent, sent off the host or
	// copied out of its folder takes the read row of its class below, the
	// cell 1.0.10 gives the plain spelling (GAP-1846). A read of another
	// account's credential file keeps its row (GAP-0888, GAP-0898).
	RowEffectRead = "effect-read"
	// RowCopyGitCredential: one's own .git-credentials or .netrc copied out
	// of its folder keeps the rel copy tier: CRITICAL, an alert per-user
	// default and permissive, a block in strict and in every managed
	// install (lead ruling 2026-11-16, GAP-1794). Other classes: copy = read.
	RowCopyGitCredential = "copy-git-credential"
	RowAdvisory          = "advisory"
	// RowAskTicketRequest: a Kerberos ticket request (or credentialed
	// domain service use) asks for a person's confirmation in the default
	// tier where the agent can ask, and is an alert where it cannot; never a
	// block in default. Strict keeps its block, permissive its alert
	// (rel-1-0-10:GAP-0017, GAP-0067).
	RowAskTicketRequest = "ask-ticket-request"
	RowEvaluationFault  = "evaluation-fault"
	RowUnverifiedPath   = "unverified-path"
	RowTruncated        = "truncated"
	RowStateWrite       = "state-write"
	RowProtectedFile    = "shell-protected-file"
	// The known credential reads (GAP-1244, GAP-0888, GAP-0898/0899): a
	// read proven on a credential file class takes the cell the 1.0.10
	// rule naming that class gives its plain spelling (cat <the file>),
	// characterized at a64bfdb931 in the five tiers, so a spelling only the
	// effects reader resolves gets the plain spelling's verdict.
	RowReadSSHPrivateKey            = "read-ssh-private-key"
	RowReadCredential               = "read-credential"
	RowEffectOtherHomeSSHPrivateKey = "effect-read-other-home-ssh-private-key"
	RowReadOtherHomeSSHPrivateKey   = "read-other-home-ssh-private-key"
	RowReadOtherHomeGitCredential   = "read-other-home-git-credential"
	RowReadOtherHomeCredential      = "read-other-home-credential"
	// RowTieredStrict grades a conclusion the 1.0.10 readers enforced in the
	// strict tier only (an alert in default and permissive, per-user and
	// managed alike): an inline handoff of unknown state, file tool targets
	// past the verification bound, a strict-enforced semantic owner, the
	// omitted plain operands of a keys write, another account's key read.
	RowTieredStrict = "tiered-strict"
	// RowTieredManaged grades a conclusion the 1.0.10 readers enforced in
	// the strict tier and in every managed install (an alert in a per-user
	// default or permissive install): a proven DefenseClaw self-disable, a
	// proven critical scope, a fetched-content execution, a non-shell tool
	// credential or account reach, a read-only keys mention, an unproven
	// key write that may warn.
	RowTieredManaged = "tiered-managed"
)

var mutatingKinds = []ProofKind{KindWrite, KindAppend, KindDelete, KindLink, KindPerm}

// cloudCredentialSets are the credential classes 1.0.10 grades alike in
// one's own and another account's home: an alert MEDIUM, nothing in
// permissive (GAP-0888).
var cloudCredentialSets = []string{SetAWSCredentials, SetNpmrc, SetPypirc, SetKubeConfig, SetDockerConfig}

// alertMedium is the GAP-0888 cell: the read maps as MEDIUM and is an
// alert at most (an alert in default, strict and managed; nothing in
// permissive, which alerts from HIGH).
var alertMedium = Cell{Levels: true, Severity: SevMedium, Ceiling: CeilingAlert}

func uniform(c Cell) [tierCount]Cell { return [tierCount]Cell{c, c, c} }

// Builtin is the 1.0.10 tier table, row for row what the gateway's special
// cases did before DET111 (characterized at a64bfdb931). Each built-in
// pack's tiers.yaml is its column of this table (TestShippedTiersMatchBuiltin).
func Builtin() *Table { return &builtin }

// knownProtectedWriteRules are the rules RuleFor names for a Known write:
// the plain spelling's rule of each restricted set.
var knownProtectedWriteRules = []string{RuleAuthorizedKeysWrite, RuleStateWrite, RuleHookConfigWrite,
	"PATH-AWS-CREDS", "PATH-GIT-CREDS", "PATH-NPMRC", "PATH-PYPIRC", "PATH-KUBE", "PATH-DOCKER"}

var builtin = Table{Rows: []Row{
	{
		// A resolved write, append or delete of an exact member of a restricted set
		// (authorized_keys, DefenseClaw state, an agent hook config, a
		// credential file) has the plain spelling's 1.0.10 decision whatever
		// program the program table modeled it for: the rule the plain
		// spelling fires (RuleFor) at that rule's pack severity
		// (PlainWriteSeverity), mapped by the tier levels as that rule's
		// finding is (GAP-1865, GAP-1478, GAP-1500, GAP-0662, GAP-0506).
		ID: RowKnownProtectedWrite, Rules: knownProtectedWriteRules,
		Kinds:     []ProofKind{KindWrite, KindAppend, KindDelete},
		Targets:   []TargetClass{TargetAuthorizedKeys, TargetState, TargetHookConfig, TargetCredential},
		Certainty: []Certainty{CertKnown}, Sources: []string{SourceEffects},
		Content: true, SecureClient: true, Source: "rel-1-0-10:plain spelling of each restricted set (GAP-1865, GAP-1478)",
		Cells: [deploymentCount][tierCount]Cell{uniform(Cell{Levels: true}), uniform(Cell{Levels: true})},
	},
	{
		ID: RowEffectUnknown, Rules: []string{RuleEffectUnknown},
		Content: true, SecureClient: true, Source: "DET111 PLAN 5.3 MAYBE rule (GAP-1796)",
		Cells: [deploymentCount][tierCount]Cell{
			uniform(Cell{Levels: true, Ceiling: CeilingRecord}), uniform(Cell{Levels: true, Ceiling: CeilingRecord}),
		},
	},
	{
		ID: RowEffectContentDecided, Rules: []string{RuleEffectRestricted, RuleEffectUnknown}, Kinds: mutatingKinds,
		Targets: []TargetClass{TargetAutostart}, Content: true, SecureClient: true,
		Source: "rel-1-0-10:persistence.shell_profile_write content-decided (GAP-1795)",
		Cells: [deploymentCount][tierCount]Cell{
			uniform(Cell{Levels: true, Ceiling: CeilingRecord}), uniform(Cell{Levels: true, Ceiling: CeilingRecord}),
		},
	},
	{
		ID: RowEffectOwnKeyWrite, Rules: []string{RuleEffectRestricted, RuleEffectUnknown},
		Kinds: []ProofKind{KindWrite, KindPerm}, Targets: []TargetClass{TargetCredential},
		Sets: []string{SetSSHPrivateKey}, Sources: []string{SourceEffects}, Content: true, SecureClient: true,
		Source: "rel-1-0-10:no rule on an own SSH private key write (GAP-1878)",
		Cells: [deploymentCount][tierCount]Cell{
			uniform(Cell{Levels: true, Ceiling: CeilingRecord}), uniform(Cell{Levels: true, Ceiling: CeilingRecord}),
		},
	},
	{
		ID: RowEffectLink, Rules: []string{RuleEffectRestricted, RuleEffectUnknown}, Kinds: []ProofKind{KindLink}, LinkAt: true,
		Targets: []TargetClass{TargetHookConfig, TargetAuthorizedKeys, TargetCredential, TargetOtherHomeCredential, TargetAutostart, TargetSystem, TargetProject, TargetOther, TargetNone},
		Content: true, SecureClient: true, Source: "DET111 effects link at a member (sweep T17)",
		Cells: [deploymentCount][tierCount]Cell{
			uniform(Cell{Levels: true, Ceiling: CeilingRecord}), uniform(Cell{Levels: true, Ceiling: CeilingRecord}),
		},
	},
	{
		ID: RowEffectRead, Kinds: []ProofKind{KindRead}, Targets: []TargetClass{TargetCredential}, Sources: []string{SourceEffects},
		Flows: []ReadFlow{FlowNone}, Content: true, SecureClient: true, Source: "DET111 effects credential read (GAP-1825, GAP-1826, GAP-1846)",
		Cells: [deploymentCount][tierCount]Cell{
			uniform(Cell{Levels: true, Ceiling: CeilingRecord}), uniform(Cell{Levels: true, Ceiling: CeilingRecord}),
		},
	},
	{
		// A proof with no reach never moves the verdict (DET111 PLAN 5.3,
		// the precision rule): the finding is recorded only, on every
		// surface and in every tier (the 1.0.10 detection-only class).
		ID: RowRecord, Certainty: []Certainty{CertMaybe}, Reach: []string{""},
		Content: true, SecureClient: true, Source: "rel-1-0-10:detection-only",
		Cells: [deploymentCount][tierCount]Cell{
			uniform(Cell{Levels: true, Ceiling: CeilingRecord}), uniform(Cell{Levels: true, Ceiling: CeilingRecord}),
		},
	},
	{
		// An advisory proof (ReachAdvisory) maps by its severity and is an
		// alert at most, on every surface and in every tier (the 1.0.10
		// alert-only class).
		ID: RowAdvisory, Certainty: []Certainty{CertMaybe}, Reach: []string{ReachAdvisory},
		Content: true, SecureClient: true, Source: "rel-1-0-10:alert-only",
		Cells: [deploymentCount][tierCount]Cell{
			uniform(Cell{Levels: true, Ceiling: CeilingAlert}), uniform(Cell{Levels: true, Ceiling: CeilingAlert}),
		},
	},
	{
		// A ticket request confirms in the default tier, per-user and
		// managed alike: a confirm floor over the severity mapping, so the
		// HIGH finding asks where it alerted (the hook asks where the agent
		// can and alerts where it cannot, never a block: GAP-0371). Strict
		// and permissive keep the 1.0.10 mapping (strict blocks HIGH). The
		// record and advisory rows come first, so a ticket finding a reader
		// only recorded or advised keeps that cell.
		ID: RowAskTicketRequest, Rules: []string{"credential.directory_ticket_request"},
		Source: "rel-1-0-10:GAP-0017/GAP-0067",
		Cells: [deploymentCount][tierCount]Cell{
			{TierDefault: {Floor: Confirm, Levels: true}, TierPermissive: {Levels: true}, TierStrict: {Levels: true}},
			{TierDefault: {Floor: Confirm, Levels: true}, TierPermissive: {Levels: true}, TierStrict: {Levels: true}},
		},
	},
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
		Content: true, SecureClient: true, Source: "rel-1-0-10:TOOL-PATH-UNVERIFIED managed close",
		Cells: [deploymentCount][tierCount]Cell{
			uniform(Cell{Levels: true}), uniform(Cell{Floor: Block, Levels: true}),
		},
	},
	{
		// A truncated call is the unknown tier: an alert in the default and
		// permissive packs, a block in strict (rel-1-0-6:GAP-0675, GAP-0313,
		// GAP-0688); guardrail.cascade.unknown replaces it. A bound alone is
		// MEDIUM, and the row applies on the content surface too, so every
		// route gives the same verdict (owner ruling 2026-11-21,
		// GAP-0851, GAP-0962: in 1.0.10 the bound finding was CRITICAL so
		// that strict blocked, and the content surface blocked it in
		// every pack).
		ID: RowTruncated, Kinds: []ProofKind{KindTruncated}, Unknown: true, PackTier: true,
		Content: true, Source: "rel-1-0-6:GAP-0675; rel-1-0-10:GAP-0851",
		Cells: [deploymentCount][tierCount]Cell{
			{TierDefault: {Floor: Alert, Severity: SevMedium}, TierPermissive: {Floor: Alert, Severity: SevMedium}, TierStrict: {Floor: Block, Levels: true, Severity: SevMedium}},
			{TierDefault: {Floor: Alert, Severity: SevMedium}, TierPermissive: {Floor: Alert, Severity: SevMedium}, TierStrict: {Floor: Block, Levels: true, Severity: SevMedium}},
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
	{
		ID: RowCopyGitCredential, Kinds: []ProofKind{KindRead}, Targets: []TargetClass{TargetCredential},
		Certainty: []Certainty{CertKnown}, Sets: []string{SetGitCredentials}, Flows: []ReadFlow{FlowCopied}, SecureClient: true,
		Source: "rel-1-0-10:PATH-GIT-CREDS copy (lead ruling 2026-11-16, GAP-1794)",
		Cells: [deploymentCount][tierCount]Cell{
			{
				TierDefault:    {Levels: true, Severity: SevCritical, Ceiling: CeilingAlert},
				TierPermissive: {Levels: true, Severity: SevCritical, Ceiling: CeilingAlert},
				TierStrict:     {Levels: true, Severity: SevCritical},
			},
			uniform(Cell{Levels: true, Severity: SevCritical}),
		},
	},
	{
		// One's own SSH private key: CRITICAL, a block in every pack
		// (PATH-SSH-KEY on cat ~/.ssh/id_rsa).
		ID: RowReadSSHPrivateKey, Kinds: []ProofKind{KindRead}, Targets: []TargetClass{TargetCredential},
		Certainty: []Certainty{CertKnown}, Sets: []string{SetSSHPrivateKey}, SecureClient: true,
		Source: "rel-1-0-10:PATH-SSH-KEY",
		Cells: [deploymentCount][tierCount]Cell{
			uniform(Cell{Levels: true, Severity: SevCritical}), uniform(Cell{Levels: true, Severity: SevCritical}),
		},
	},
	{
		// One's own cloud, git and package credentials: the GAP-0888 cell.
		ID: RowReadCredential, Kinds: []ProofKind{KindRead}, Targets: []TargetClass{TargetCredential},
		Certainty: []Certainty{CertKnown}, Sets: append([]string{SetGitCredentials}, cloudCredentialSets...), SecureClient: true,
		Source: "rel-1-0-10:GAP-0888",
		Cells:  [deploymentCount][tierCount]Cell{uniform(alertMedium), uniform(alertMedium)},
	},
	{
		// An effects-proven read of another account's SSH private key takes
		// the raised plain-form GAP-2135 cell. The legacy row below stays at
		// its shipped-default cell for findings from the 1.0.10 readers.
		ID: RowEffectOtherHomeSSHPrivateKey, Kinds: []ProofKind{KindRead},
		Targets: []TargetClass{TargetOtherHomeCredential}, Certainty: []Certainty{CertKnown},
		Sets: []string{SetSSHPrivateKey}, Sources: []string{SourceEffects}, SecureClient: true,
		Source: "DET111 GAP-2135 effect-proven other-home key read",
		Cells: [deploymentCount][tierCount]Cell{
			{TierDefault: {Levels: true, Severity: SevHigh, Ceiling: CeilingAlert},
				TierPermissive: {Levels: true, Severity: SevHigh, Ceiling: CeilingAlert},
				TierStrict:     {Levels: true, Severity: SevCritical}},
			{TierDefault: {Levels: true, Severity: SevHigh, Ceiling: CeilingAlert},
				TierPermissive: {Levels: true, Severity: SevHigh, Ceiling: CeilingAlert},
				TierStrict:     {Levels: true, Severity: SevCritical}},
		},
	},
	{
		// Another account's SSH private key: an alert MEDIUM in default and
		// managed default, nothing in permissive, a CRITICAL block in strict
		// (PATH-SSH-KEY on cat /home/<other>/.ssh/id_rsa).
		ID: RowReadOtherHomeSSHPrivateKey, Kinds: []ProofKind{KindRead}, Targets: []TargetClass{TargetOtherHomeCredential},
		Certainty: []Certainty{CertKnown}, Sets: []string{SetSSHPrivateKey}, SecureClient: true,
		Source: "rel-1-0-10:PATH-SSH-KEY other home (GAP-0837)",
		Cells: [deploymentCount][tierCount]Cell{
			{TierDefault: alertMedium, TierPermissive: alertMedium, TierStrict: {Levels: true, Severity: SevCritical}},
			{TierDefault: alertMedium, TierPermissive: alertMedium, TierStrict: {Levels: true, Severity: SevCritical}},
		},
	},
	{
		// Another account's .git-credentials or .netrc: CRITICAL, an alert
		// per-user (default and permissive), a block in strict and in every
		// managed install (PATH-GIT-CREDS, GAP-0835).
		ID: RowReadOtherHomeGitCredential, Kinds: []ProofKind{KindRead}, Targets: []TargetClass{TargetOtherHomeCredential},
		Certainty: []Certainty{CertKnown}, Sets: []string{SetGitCredentials}, SecureClient: true,
		Source: "rel-1-0-10:PATH-GIT-CREDS other home (GAP-0835)",
		Cells: [deploymentCount][tierCount]Cell{
			{
				TierDefault:    {Levels: true, Severity: SevCritical, Ceiling: CeilingAlert},
				TierPermissive: {Levels: true, Severity: SevCritical, Ceiling: CeilingAlert},
				TierStrict:     {Levels: true, Severity: SevCritical},
			},
			uniform(Cell{Levels: true, Severity: SevCritical}),
		},
	},
	{
		// Another account's cloud and package credentials: as one's own
		// (GAP-0888 cell).
		ID: RowReadOtherHomeCredential, Kinds: []ProofKind{KindRead}, Targets: []TargetClass{TargetOtherHomeCredential},
		Certainty: []Certainty{CertKnown}, Sets: cloudCredentialSets, SecureClient: true,
		Source: "rel-1-0-10:PATH-AWS-CREDS other home (GAP-0837)",
		Cells:  [deploymentCount][tierCount]Cell{uniform(alertMedium), uniform(alertMedium)},
	},
	{
		ID: RowTieredStrict, Gate: true, Content: true, SecureClient: true,
		Source: "rel-1-0-10:request.StrictPolicy readers (GAP-0810, GAP-1069)",
		Cells: [deploymentCount][tierCount]Cell{
			{TierDefault: {Levels: true, Ceiling: CeilingAlert}, TierPermissive: {Levels: true, Ceiling: CeilingAlert}, TierStrict: {Levels: true}},
			{TierDefault: {Levels: true, Ceiling: CeilingAlert}, TierPermissive: {Levels: true, Ceiling: CeilingAlert}, TierStrict: {Levels: true}},
		},
	},
	{
		ID: RowTieredManaged, Gate: true, Content: true, SecureClient: true,
		Source: "rel-1-0-10:request.StrictPolicy||ManagedInstall readers (GAP-0594, GAP-0843)",
		Cells: [deploymentCount][tierCount]Cell{
			{TierDefault: {Levels: true, Ceiling: CeilingAlert}, TierPermissive: {Levels: true, Ceiling: CeilingAlert}, TierStrict: {Levels: true}},
			uniform(Cell{Levels: true}),
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

// CellYAML, RowYAML and ColumnYAML are the tiers.yaml schema.
type CellYAML struct {
	Floor    string `yaml:"floor"`
	Levels   *bool  `yaml:"levels,omitempty"`
	Severity string `yaml:"severity,omitempty"`
	Ceiling  string `yaml:"ceiling,omitempty"`
}

type RowYAML struct {
	ID      string   `yaml:"id"`
	Source  string   `yaml:"source,omitempty"`
	PerUser CellYAML `yaml:"per_user"`
	Managed CellYAML `yaml:"managed"`
}

type ColumnYAML struct {
	Version int       `yaml:"version"`
	Tier    string    `yaml:"tier"`
	Rows    []RowYAML `yaml:"rows"`
}

// TiersFile is the tier table file of a rule pack.
const TiersFile = "tiers.yaml"

// ParseColumn reads and checks a pack's tiers.yaml (ColumnYAML.Column).
func ParseColumn(data []byte) (*Column, error) {
	var raw ColumnYAML
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("tiers.yaml: %w", err)
	}
	return raw.Column()
}

// Column checks a decoded tiers.yaml: version 1, a known tier, every row id
// a row of the built-in table and listed once, known actions and
// severities, and a floor of allow only where the cell keeps the levels (a
// cell that maps nothing would allow the finding silently). A cell must
// also keep what the built-in table holds for every pack (packCellError):
// its severity, a hard-floor row's floor, and whether its row is recorded
// in every cell.
func (raw ColumnYAML) Column() (*Column, error) {
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
		if err := packCellError(r.ID, tier, perUser, managed); err != nil {
			return nil, err
		}
		col.Rows = append(col.Rows, ColumnRow{ID: r.ID, PerUser: perUser, Managed: managed})
	}
	return col, nil
}

// hardFloorRows are the rows whose built-in cells were code at 1.0.10, which
// no pack file could change: an evaluation fault, a DefenseClaw state
// write, a truncated reading, an unverified path and a shell command on a
// protected file. A pack may raise them, never lower them (DET111 T19
// review P3-2).
var hardFloorRows = []string{RowEvaluationFault, RowStateWrite, RowTruncated, RowUnverifiedPath, RowProtectedFile}

// packCellError refuses a pack cell for row id in tier that would make the
// pack's table disagree with what every caller reads from the built-in
// table, so the readers of the built-in table (ShadowOnly, the verdict
// severity) and Decide on the pack table give one answer (DET111 T19 review
// P3-1, P3-2):
//   - a cell's severity is the built-in one: the verdict severity of a
//     finding is the built-in table's (Table.Severity);
//   - a row recorded in every cell of the built-in table stays so, and no
//     row becomes so: the effect join keeps such a finding out of the call
//     (ShadowOnly) before Decide sees it;
//   - a hard-floor row (hardFloorRows) keeps at least its built-in floor,
//     its levels and its ceiling.
func packCellError(id string, tier Tier, perUser, managed Cell) error {
	row := builtin.row(id)
	cells := [deploymentCount]Cell{PerUser: perUser, Managed: managed}
	names := [deploymentCount]string{PerUser: "per_user", Managed: "managed"}
	for d, c := range cells {
		b := row.Cells[d][tier]
		if c.Severity != b.Severity {
			return fmt.Errorf("tiers.yaml: row %q %s: severity %s, the built-in row has %s: a pack does not change a row's severity",
				id, names[d], severityName(c.Severity), severityName(b.Severity))
		}
		if slices.Contains(hardFloorRows, id) &&
			(c.Floor < b.Floor || c.Ceiling > b.Ceiling || (b.Levels && !c.Levels)) {
			return fmt.Errorf("tiers.yaml: row %q %s: lowers the built-in cell (floor %s): a pack may raise this row, never lower it",
				id, names[d], b.Floor)
		}
	}
	recordedOnly := func(cell func(d Deployment, t Tier) Cell) bool {
		for d := range Deployment(deploymentCount) {
			for t := range Tier(tierCount) {
				if cell(d, t).Ceiling != CeilingRecord {
					return false
				}
			}
		}
		return true
	}
	builtinRecorded := recordedOnly(func(d Deployment, t Tier) Cell { return row.Cells[d][t] })
	packRecorded := recordedOnly(func(d Deployment, t Tier) Cell {
		if t == tier {
			return cells[d]
		}
		return row.Cells[d][t]
	})
	if builtinRecorded != packRecorded {
		return fmt.Errorf("tiers.yaml: row %q: the built-in row is recorded in every cell=%v, the pack's=%v: a pack does not turn a row's recording in every cell on or off",
			id, builtinRecorded, packRecorded)
	}
	return nil
}

func severityName(s Severity) string {
	if s == SevNone {
		return "none"
	}
	return s.String()
}

func (c CellYAML) cell(row, deployment string) (Cell, error) {
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
	switch strings.ToLower(strings.TrimSpace(c.Ceiling)) {
	case "", "none":
	case "alert":
		out.Ceiling = CeilingAlert
	case "record":
		out.Ceiling = CeilingRecord
	default:
		return Cell{}, fmt.Errorf("tiers.yaml: row %q %s: ceiling %q is not alert or record", row, deployment, c.Ceiling)
	}
	if out.Ceiling == CeilingRecord && out.Floor != Allow {
		return Cell{}, fmt.Errorf("tiers.yaml: row %q %s: a record ceiling with floor %q", row, deployment, c.Floor)
	}
	if out.Floor == Allow && !out.Levels && out.Ceiling != CeilingRecord {
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
// list keep t's cells. A column that changes no cell is t itself (a built-in
// pack's tiers.yaml decides with Builtin()).
func (t *Table) WithColumn(col *Column) *Table {
	if col == nil || !t.changedBy(col) {
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

func (t *Table) changedBy(col *Column) bool {
	for _, cr := range col.Rows {
		if row := t.row(cr.ID); row != nil &&
			(row.Cells[PerUser][col.Tier] != cr.PerUser || row.Cells[Managed][col.Tier] != cr.Managed) {
			return true
		}
	}
	return false
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
	raw := ColumnYAML{Version: 1, Tier: col.Tier.String()}
	for _, r := range col.Rows {
		source := ""
		if b := builtin.row(r.ID); b != nil {
			source = b.Source
		}
		raw.Rows = append(raw.Rows, RowYAML{ID: r.ID, Source: source, PerUser: toYAMLCell(r.PerUser), Managed: toYAMLCell(r.Managed)})
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

func toYAMLCell(c Cell) CellYAML {
	out := CellYAML{Floor: c.Floor.String()}
	if !c.Levels {
		f := false
		out.Levels = &f
	}
	if c.Severity != SevNone {
		out.Severity = c.Severity.String()
	}
	switch c.Ceiling {
	case CeilingAlert:
		out.Ceiling = "alert"
	case CeilingRecord:
		out.Ceiling = "record"
	}
	return out
}

// Severity is the severity the table gives finding f on the tool surface
// when every cell of its row agrees (the truncated row: a bound alone is
// MEDIUM), else SevNone: the finding's own severity stands. It is the
// severity a verdict reports for the finding (HighestSeverity).
func (t *Table) Severity(f Finding) Severity {
	row := t.match(f, SurfaceTool, false)
	if row == nil {
		return SevNone
	}
	sev := row.Cells[PerUser][TierDefault].Severity
	for d := range row.Cells {
		for _, c := range row.Cells[d] {
			if c.Severity != sev {
				return SevNone
			}
		}
	}
	return sev
}

// GateCeiling is the ceiling the gate row id gives a reader's tiered
// conclusion for deployment d in tier: CeilingNone enforces, CeilingAlert
// is an alert at most, CeilingRecord records only. An id the table has no
// row for enforces (fail closed).
func (t *Table) GateCeiling(id string, d Deployment, tier Tier) Ceiling {
	if t == nil {
		t = Builtin()
	}
	row := t.row(id)
	if row == nil {
		return CeilingNone
	}
	if d >= deploymentCount {
		d = PerUser
	}
	if tier >= tierCount {
		tier = TierDefault
	}
	return row.Cells[d][tier].Ceiling
}
