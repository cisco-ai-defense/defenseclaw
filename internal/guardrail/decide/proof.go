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

// Package decide is the one place a guardrail tier is chosen (DET111 D4).
//
// A reader says what it proved about a call as a Proof (what the call does,
// to which class of target, how sure it is); the rule pack says what a proof
// is worth per tier and deployment in its tier table (tiers.yaml); Decide
// maps proofs, severities and the table to one action. No reader picks a
// tier, and nothing here reads the host: no runtime.GOOS, no file system, no
// config package. The package has no gateway import, so every route (hook,
// proxy, inspect, ACP) can call it with the same inputs.
package decide

import (
	"fmt"
	"strings"
)

// ProofKind is what a call is proven to do to its target.
type ProofKind uint8

const (
	// KindUnspecified is a finding whose reader set no proof. Decide maps
	// it by its severity alone, as every finding was mapped before DET111.
	KindUnspecified ProofKind = iota
	KindWrite
	KindAppend
	KindDelete
	KindLink
	KindRead
	KindExec
	KindSend
	KindFetch
	KindPerm
	// KindContent is a content finding (a pattern rule, CodeGuard, a judge):
	// no effect on a target, only a severity.
	KindContent
	// KindTruncated is the call a reader read only in part (a cap hit, the
	// evaluation limit, a parse failure that proves no target). Its
	// Certainty is CertBound and Cap names the cap.
	KindTruncated
	// KindUnread is the call the evaluation failed on (a parser fault, a
	// reader panic): nothing proves what it does.
	KindUnread
	kindCount
)

var kindNames = [...]string{
	KindUnspecified: "unspecified", KindWrite: "write", KindAppend: "append", KindDelete: "delete",
	KindLink: "link", KindRead: "read", KindExec: "exec", KindSend: "send", KindFetch: "fetch",
	KindPerm: "perm", KindContent: "content", KindTruncated: "truncated", KindUnread: "unread",
}

func (k ProofKind) String() string {
	if k < kindCount {
		return kindNames[k]
	}
	return fmt.Sprintf("kind(%d)", uint8(k))
}

// TargetClass is the protected set a proof's target is in.
type TargetClass uint8

const (
	TargetNone TargetClass = iota
	// TargetState is the DefenseClaw state folder (self-protection).
	TargetState
	TargetHookConfig
	TargetAuthorizedKeys
	TargetCredential
	TargetOtherHomeCredential
	// TargetAutostart is a file the user's shell, git or session runs
	// (shell profiles, git hooks, login items).
	TargetAutostart
	TargetSystem
	TargetProject
	TargetOther
	targetCount
)

var targetNames = [...]string{
	TargetNone: "none", TargetState: "state", TargetHookConfig: "hook_config",
	TargetAuthorizedKeys: "authorized_keys", TargetCredential: "credential",
	TargetOtherHomeCredential: "other_home_credential", TargetAutostart: "autostart",
	TargetSystem: "system", TargetProject: "project", TargetOther: "other",
}

func (t TargetClass) String() string {
	if t < targetCount {
		return targetNames[t]
	}
	return fmt.Sprintf("target(%d)", uint8(t))
}

// Certainty is how sure the reader is of the target.
type Certainty uint8

const (
	// CertKnown: the target is resolved and in the class.
	CertKnown Certainty = iota
	// CertMaybe: the target may be in the class; Reach says why.
	CertMaybe
	// CertBound: a bound stopped the reading; Cap names the bound.
	CertBound
	certCount
)

var certNames = [...]string{CertKnown: "known", CertMaybe: "maybe", CertBound: "bound"}

func (c Certainty) String() string {
	if c < certCount {
		return certNames[c]
	}
	return fmt.Sprintf("certainty(%d)", uint8(c))
}

// Reach reasons of a CertMaybe proof (DET111 PLAN 5.3). An unknown reaches
// the unknown tier only with one of them.
const (
	// ReachName: a word of the call, after resolution, names a protected
	// set member (GAP-0843).
	ReachName = "R-NAME"
	// ReachGlob: an unquoted glob can match a protected path.
	ReachGlob = "R-GLOB"
	// ReachCwd: the working folder is unknown and a relative operand could
	// land in a protected set.
	ReachCwd = "R-CWD"
	// ReachRole: the program table says the program writes or sends an
	// operand that is unknown (dd of=$X), or the hook client left a named
	// operand out of its bounded map.
	ReachRole = "R-ROLE"
	// ReachCode: opaque code named a protected set member as a literal.
	ReachCode = "R-CODE"
	// ReachFS: the file system would not answer for a named path
	// (TOOL-PATH-UNVERIFIED: an opened Windows path that could not be
	// verified).
	ReachFS = "R-FS"
	// ReachAdvisory: the reader proved its pattern but nothing that may
	// enforce (no protected target, no proven effect it can stop): an
	// advisory finding, an alert at most. It is the 1.0.10 alert-only class.
	ReachAdvisory = "R-ADVISORY"
)

// Record is the proof of a finding that proves nothing a verdict may act
// on: CertMaybe with no reach. By the precision rule (DET111 PLAN 5.3) an
// unknown without reach never moves the verdict; the finding is recorded
// (the 1.0.10 detection-only class). Kind and Target, when the reader knows
// them, stay.
func (p Proof) Record() Proof {
	p.Certainty, p.Reach = CertMaybe, ""
	return p
}

// Advise is p as an advisory proof (ReachAdvisory).
func (p Proof) Advise() Proof {
	p.Certainty, p.Reach = CertMaybe, ReachAdvisory
	return p
}

// Enforce is p as a proof that may enforce: the reader's uncertainty
// marks (Record, Advise) are dropped.
func (p Proof) Enforce() Proof {
	if p.Certainty == CertMaybe && (p.Reach == "" || p.Reach == ReachAdvisory) {
		p.Certainty, p.Reach = CertKnown, ""
	}
	return p
}

// Recorded reports a Record proof.
func (p Proof) Recorded() bool { return p.Certainty == CertMaybe && p.Reach == "" }

// Advisory reports an Advise proof.
func (p Proof) Advisory() bool { return p.Certainty == CertMaybe && p.Reach == ReachAdvisory }

// Proof is what a finding proves about the call, value-free: no paths, no
// argv, no matched text. It never leaves the process (not in the public
// finding schema, not in audit rows), so a remote input cannot pick a tier.
type Proof struct {
	Kind      ProofKind
	Target    TargetClass
	Certainty Certainty
	// Reach is set for CertMaybe only: one of the Reach* reasons.
	Reach string
	// Cap is set for CertBound only: the bounded cap name.
	Cap string
	// Source is the reader, twin or rule id that made the proof. It is the
	// key of the effects shadow report; Decide does not read it.
	Source string
	// Set is the protected file class a known read names (the Set*
	// constants, CredentialSet). A row with Sets matches only a proof that
	// names one of them, so a read takes the cell of the 1.0.10 rule that
	// names the same file class whatever the spelling (GAP-1244).
	Set string
	// LinkTo marks a KindLink proof whose protected member is the link's
	// target (ln -s ~/.ssh/authorized_keys s: an alias of the member the
	// call can write or read through), not the place the link is put.
	LinkTo bool
	// Flow is where a read's content goes in the call (KindRead only): an
	// own credential read the effects lane proves raises only with a flow
	// (GAP-1846), and a copy takes the copy cell of its class (GAP-1794).
	Flow ReadFlow
}

// ReadFlow is where the content of a read goes in the call (DET111
// GAP-1846, GAP-1794).
type ReadFlow uint8

const (
	// FlowNone: the content stays local: discarded, counted, tested, or
	// copied beside the file in its own folder.
	FlowNone ReadFlow = iota
	// FlowShown: printed on the call's own output (what the agent sees).
	FlowShown
	// FlowSent: sent off the host (a network send of the bytes).
	FlowSent
	// FlowCopied: copied or moved out of the file's folder.
	FlowCopied
)

// IsZero reports a finding with no proof: no kind and no uncertainty mark
// (a Record or Advise proof with no kind is not zero: its row decides).
func (p Proof) IsZero() bool { return p.Kind == KindUnspecified && p.Certainty == CertKnown }

// String is a stable, value-free key of the proof (characterization and
// shadow-report rows).
func (p Proof) String() string {
	var b strings.Builder
	b.WriteString(p.Kind.String())
	b.WriteByte('/')
	b.WriteString(p.Target.String())
	b.WriteByte('/')
	b.WriteString(p.Certainty.String())
	if p.Set != "" {
		b.WriteByte('{')
		b.WriteString(p.Set)
		b.WriteByte('}')
	}
	switch {
	case p.Reach != "":
		b.WriteByte('(')
		b.WriteString(p.Reach)
		b.WriteByte(')')
	case p.Cap != "":
		b.WriteByte('(')
		b.WriteString(p.Cap)
		b.WriteByte(')')
	}
	return b.String()
}

// ParseKind, ParseTarget and ParseCertainty read the names String gives.
func ParseKind(s string) (ProofKind, bool) { return parseName[ProofKind](kindNames[:], s) }

func ParseTarget(s string) (TargetClass, bool) { return parseName[TargetClass](targetNames[:], s) }

func ParseCertainty(s string) (Certainty, bool) { return parseName[Certainty](certNames[:], s) }

func parseName[T ~uint8](names []string, s string) (T, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	for i, name := range names {
		if name == s {
			return T(i), true
		}
	}
	return 0, false
}

// Canonical rule ids named by a proof's target (DESIGN D4): attribution
// comes from what was proven, not from which reader fired first
// (GAP-1634, GAP-1568, GAP-1327).
const (
	RuleStateWrite          = "TAMPER.DETECTOR_STATE_WRITE"
	RuleAuthorizedKeysWrite = "PERSISTENCE.SSH_AUTHORIZED_KEYS_COMMAND"
	RuleShellProfileWrite   = "PERSISTENCE.SHELL_PROFILE_WRITE"
	RuleGitHookWrite        = "PERSISTENCE.GIT_HOOK_WRITE"
	RuleSSHDir              = "PATH-SSH-DIR"
	RuleEvaluationLimit     = "ACTION-COMPOUND-LIMIT"
)

// RuleHookConfigWrite is the agent hook config guard rule as the packs and
// the plain spelling write it: a Known write finding carries the same id, so
// the call shows the rule set of the plain spelling (GAP-1243, GAP-1308).
const RuleHookConfigWrite = "tamper.agent_hook_config_write"

// Credential file classes (Proof.Set) of a known read: one per 1.0.10 rule
// that names the file, so the read is named and graded by that rule's row
// whatever the spelling (DET111 ruling 2026-11-22T04:12Z, GAP-1244).
const (
	SetSSHPrivateKey  = "ssh_private_key"
	SetAWSCredentials = "aws_credentials"
	// SetGitCredentials is .git-credentials and .netrc: 1.0.10 names both
	// PATH-GIT-CREDS and grades them alike.
	SetGitCredentials = "git_credentials"
	SetNpmrc          = "npmrc"
	SetPypirc         = "pypirc"
	SetKubeConfig     = "kube_config"
	SetDockerConfig   = "docker_config"
)

// setRules is the rule a credential file class names.
var setRules = map[string]string{
	SetSSHPrivateKey:  "PATH-SSH-KEY",
	SetAWSCredentials: "PATH-AWS-CREDS",
	SetGitCredentials: "PATH-GIT-CREDS",
	SetNpmrc:          "PATH-NPMRC",
	SetPypirc:         "PATH-PYPIRC",
	SetKubeConfig:     "PATH-KUBE",
	SetDockerConfig:   "PATH-DOCKER",
}

// credentialTails are the home-relative files of each class.
var credentialTails = map[string]string{
	".ssh/id_rsa": SetSSHPrivateKey, ".ssh/id_ed25519": SetSSHPrivateKey,
	".ssh/id_ecdsa": SetSSHPrivateKey, ".ssh/id_dsa": SetSSHPrivateKey,
	".aws/credentials": SetAWSCredentials,
	".git-credentials": SetGitCredentials, ".netrc": SetGitCredentials,
	".npmrc": SetNpmrc, ".pypirc": SetPypirc,
	".kube/config": SetKubeConfig, ".docker/config.json": SetDockerConfig,
}

// CredentialSet is the credential file class of a protected credential
// member, given as its path relative to the home that holds it (".ssh/id_rsa",
// `.aws\credentials`), or "" for a member of no class. It reads no file: the
// caller has already proven the member (the protected-set classifier); this
// only names its row. Separators and letter case are folded (the classifier
// decides whether the spelling is the file on the host).
func CredentialSet(tail string) string {
	t := strings.ToLower(strings.ReplaceAll(strings.Trim(tail, `/\`), `\`, "/"))
	return credentialTails[t]
}

// RuleFor is the rule id a proof's target names: for a mutating proof
// (write, append, delete, link, perm) known on the target, the target
// class's rule; for a known read naming a credential file class, that
// class's 1.0.10 rule. "" when the proof names no single rule (the
// reader's own rule id stands).
func RuleFor(p Proof) string {
	if p.Certainty != CertKnown {
		return ""
	}
	if p.Kind == KindRead {
		if p.Target == TargetCredential || p.Target == TargetOtherHomeCredential {
			return setRules[p.Set]
		}
		return ""
	}
	switch p.Kind {
	case KindWrite, KindAppend, KindDelete, KindLink, KindPerm:
	default:
		return ""
	}
	switch p.Target {
	case TargetState:
		return RuleStateWrite
	case TargetAuthorizedKeys:
		return RuleAuthorizedKeysWrite
	case TargetCredential:
		if p.Set == SetSSHPrivateKey && (p.Kind == KindWrite || p.Kind == KindAppend || p.Kind == KindDelete) {
			return ""
		}
		return setRules[p.Set]
	case TargetOtherHomeCredential:
		return setRules[p.Set]
	}
	// A write, append or delete of a hook config names the rule the
	// plain spelling fires on it (rm FILE fires it too: GAP-1478,
	// GAP-1500). Credential class rules were returned above; an own
	// SSH private key write has none in 1.0.10 (GAP-1878).
	if p.Kind != KindWrite && p.Kind != KindAppend && p.Kind != KindDelete {
		return ""
	}
	switch p.Target {
	case TargetHookConfig:
		return RuleHookConfigWrite
	}
	return ""
}

// plainWriteSeverity is the severity every shipped pack gives the 1.0.10
// rule a Known protected write names (policies/guardrail/*/rules,
// TestPlainWriteSeverityIsThePackSeverity). The effect finding carries it,
// so its cell maps it as the plain spelling's finding.
var plainWriteSeverity = map[string]Severity{
	RuleAuthorizedKeysWrite: SevCritical,
	RuleStateWrite:          SevHigh,
	RuleHookConfigWrite:     SevHigh,
	"PATH-AWS-CREDS":        SevCritical,
	"PATH-GIT-CREDS":        SevCritical,
	"PATH-NPMRC":            SevMedium,
	"PATH-PYPIRC":           SevMedium,
	"PATH-KUBE":             SevHigh,
	"PATH-DOCKER":           SevHigh,
}

// PlainWriteSeverity is the pack severity of rule ruleID on a Known
// protected write (RuleFor).
func PlainWriteSeverity(ruleID string) Severity {
	if s, ok := plainWriteSeverity[ruleID]; ok {
		return s
	}
	return SevHigh
}
