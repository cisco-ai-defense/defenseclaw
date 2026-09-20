// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

// Package benchmark implements the local, publication-oriented benchmark
// harness. It stores labels and value-free predictions; source payloads never
// enter result records.
package benchmark

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

const SchemaVersion = "1"

const maxPredictionFindingCount = 1_000_000

const (
	maxToolResultArgsBytes    = 1 << 20
	maxToolResultContentBytes = 256 << 10
)

const (
	TruthBenign    = "benign"
	TruthMalicious = "malicious"
	TruthSensitive = "sensitive"
	TruthUnknown   = "unknown"

	InScope    = "in_scope"
	OutOfScope = "out_of_scope"

	DispositionAllow      = "allow"
	DispositionDetectOnly = "detect_only"
	DispositionBlock      = "block"

	DeterministicMalicious  = "deterministic_malicious"
	DeterministicContextual = "contextual_or_dual_use"
	DeterministicBenign     = "benign"

	StatefulAtomicTerminal  = "atomic_terminal"
	StatefulBoundedIntent   = "bounded_intent"
	StatefulBoundedComplete = "bounded_completed"
)

var validProfiles = map[string]bool{
	"default":    true,
	"permissive": true,
	"strict":     true,
}

var validOptInPolicyPacks = map[string]bool{
	"cloud-production-protection":           true,
	"database-destruction-protection":       true,
	"infrastructure-destruction-protection": true,
	"kubernetes-production-protection":      true,
	"privacy-high-assurance":                true,
}

const optInPolicyLabelPrefix = "opt-in/"

// Case is one normalized benchmark input and its independent source,
// applicability, and enforcement labels.
type Case struct {
	SchemaVersion string  `json:"schema_version"`
	ID            string  `json:"id"`
	Source        Source  `json:"source"`
	Split         string  `json:"split"`
	Surface       string  `json:"surface"`
	Payload       Payload `json:"payload"`
	Truth         Truth   `json:"truth"`
	Strata        Strata  `json:"strata,omitempty"`
}

type Source struct {
	Dataset        string `json:"dataset"`
	Revision       string `json:"revision"`
	OriginalID     string `json:"original_id"`
	License        string `json:"license"`
	Redistribution string `json:"redistribution"`
}

type Payload struct {
	Direction string          `json:"direction,omitempty"`
	Content   string          `json:"content,omitempty"`
	ToolName  string          `json:"tool_name,omitempty"`
	Command   string          `json:"command,omitempty"`
	Argv      []string        `json:"argv,omitempty"`
	Args      json.RawMessage `json:"args,omitempty"`
	// ToolResourceIdentity is benchmark-authenticated connector context for an
	// atomic structured action. It must be derived by the normalizer from source
	// metadata, never copied from model-controlled arguments.
	ToolResourceIdentity string          `json:"tool_resource_identity,omitempty"`
	Dialect              string          `json:"dialect,omitempty"`
	CWD                  string          `json:"cwd,omitempty"`
	ActiveHome           string          `json:"active_home,omitempty"`
	ActiveAgentFiles     []string        `json:"active_agent_files,omitempty"`
	Filename             string          `json:"filename,omitempty"`
	Target               string          `json:"target,omitempty"`
	AnnotationSpans      []ActionSpan    `json:"annotation_spans,omitempty"`
	Events               []ActionEvent   `json:"events,omitempty"`
	ToolResult           *ToolResultCase `json:"tool_result,omitempty"`
}

// ToolResultCase models one normalized pre-tool proposal and terminal result
// for the classifier-only benchmark lens. Identity is repeated intentionally
// so malformed cross-call joins can be represented and rejected during loading.
// Production lifecycle authority, pending-state, and replay behavior remain
// integration-test concerns. ResultContent must never be copied to Prediction.
type ToolResultCase struct {
	Invocation ToolResultInvocation `json:"invocation"`
	Result     ToolResultTerminal   `json:"result"`
}

type ToolResultInvocation struct {
	Connector    string          `json:"connector"`
	Event        string          `json:"event"`
	SessionID    string          `json:"session_id"`
	InvocationID string          `json:"invocation_id"`
	ToolName     string          `json:"tool_name"`
	Args         json.RawMessage `json:"args"`
}

type ToolResultTerminal struct {
	Connector    string `json:"connector"`
	Event        string `json:"event"`
	SessionID    string `json:"session_id"`
	InvocationID string `json:"invocation_id"`
	Outcome      string `json:"outcome"`
	Content      string `json:"content"`
}

// ActionSpan records source annotation offsets over an atomic command or one
// stateful event command. It is benchmark evidence only and is never projected
// into runtime ActionFacts.
type ActionSpan struct {
	Start      int    `json:"start"`
	End        int    `json:"end"`
	Label      string `json:"label"`
	RuleID     string `json:"rule_id,omitempty"`
	EventIndex *int   `json:"event_index,omitempty"`
}

type ActionEvent struct {
	ToolName string          `json:"tool_name,omitempty"`
	Command  string          `json:"command,omitempty"`
	Argv     []string        `json:"argv,omitempty"`
	Args     json.RawMessage `json:"args,omitempty"`
	// ToolResourceIdentity is benchmark-authenticated connector context used
	// only to replay exact same-resource joins. Normalizers must derive an
	// opaque, stable value from source metadata; it must never be copied from
	// model-controlled tool arguments.
	ToolResourceIdentity string   `json:"tool_resource_identity,omitempty"`
	Dialect              string   `json:"dialect,omitempty"`
	CWD                  string   `json:"cwd,omitempty"`
	ActiveHome           string   `json:"active_home,omitempty"`
	ActiveAgentFiles     []string `json:"active_agent_files,omitempty"`
	Outcome              string   `json:"outcome,omitempty"`
	OffsetSeconds        int      `json:"offset_seconds,omitempty"`
	// ResultProof is a bounded, value-safe synthetic proof used only to replay
	// production result-backed state transitions. Normalizers must never copy a
	// raw tool result into this field.
	ResultProof string `json:"result_proof,omitempty"`
}

type Truth struct {
	SourceTruth            string            `json:"source_truth"`
	DeterministicTruth     string            `json:"deterministic_truth,omitempty"`
	LabelConfidence        string            `json:"label_confidence,omitempty"`
	LabelSource            string            `json:"label_source,omitempty"`
	EnforcementLens        string            `json:"enforcement_lens,omitempty"`
	StatefulLens           string            `json:"stateful_lens,omitempty"`
	Applicability          string            `json:"applicability"`
	ExpectedDisposition    string            `json:"expected_disposition"`
	ExpectedProfileActions map[string]string `json:"expected_profile_actions,omitempty"`
	Categories             []string          `json:"categories,omitempty"`
	RuleIDs                []string          `json:"rule_ids,omitempty"`
	ExclusionReason        string            `json:"exclusion_reason,omitempty"`
	Spans                  []Span            `json:"spans,omitempty"`
}

type Span struct {
	Start  int    `json:"start"`
	End    int    `json:"end"`
	Label  string `json:"label"`
	RuleID string `json:"rule_id,omitempty"`
}

type Strata struct {
	Platform      string `json:"platform,omitempty"`
	Provider      string `json:"provider,omitempty"`
	Dialect       string `json:"dialect,omitempty"`
	Language      string `json:"language,omitempty"`
	Ecosystem     string `json:"ecosystem,omitempty"`
	Campaign      string `json:"campaign,omitempty"`
	Domain        string `json:"domain,omitempty"`
	DocumentType  string `json:"document_type,omitempty"`
	HardNegative  bool   `json:"hard_negative,omitempty"`
	SplitGroup    string `json:"split_group,omitempty"`
	TrajectoryID  string `json:"trajectory_id,omitempty"`
	SequenceIndex *int   `json:"sequence_index,omitempty"`
	CallIndex     *int   `json:"call_index,omitempty"`
}

// Prediction is deliberately value-free. It is safe to publish after the
// verifier confirms that IDs and error codes meet the bounded schema.
type Prediction struct {
	SchemaVersion           string   `json:"schema_version"`
	RunID                   string   `json:"run_id"`
	CaseID                  string   `json:"case_id"`
	Engine                  string   `json:"engine"`
	Profile                 string   `json:"profile"`
	Applicable              bool     `json:"applicable"`
	Detected                bool     `json:"detected"`
	Alerted                 bool     `json:"alerted,omitempty"`
	Action                  string   `json:"action"`
	Severity                string   `json:"severity"`
	Route                   string   `json:"route,omitempty"`
	ParseStatus             string   `json:"parse_status,omitempty"`
	EvaluationStatus        string   `json:"evaluation_status,omitempty"`
	Authoritative           bool     `json:"authoritative,omitempty"`
	EnforcementEligible     bool     `json:"enforcement_eligible,omitempty"`
	DetectionStepMask       uint64   `json:"detection_step_mask,omitempty"`
	EnforcementStepMask     uint64   `json:"enforcement_step_mask,omitempty"`
	IssueCodes              []string `json:"issue_codes,omitempty"`
	RuleIDs                 []string `json:"rule_ids,omitempty"`
	FindingCount            int      `json:"finding_count"`
	AuditFindingCount       int      `json:"audit_finding_count,omitempty"`
	AdvisoryFindingCount    int      `json:"advisory_finding_count,omitempty"`
	DetectOnlyFindingCount  int      `json:"detect_only_finding_count,omitempty"`
	EnforceableFindingCount int      `json:"enforceable_finding_count,omitempty"`
	AlertFindingCount       int      `json:"alert_finding_count,omitempty"`
	DurationMicros          int64    `json:"duration_micros"`
	ErrorCode               string   `json:"error_code,omitempty"`
	Spans                   []Span   `json:"spans,omitempty"`
}

type Environment struct {
	RunID                   string            `json:"run_id"`
	CaseCount               int               `json:"case_count"`
	PredictionCount         int               `json:"prediction_count"`
	DefenseClawCommit       string            `json:"defenseclaw_commit"`
	Dirty                   bool              `json:"dirty"`
	BinaryProvenanceVersion int               `json:"binary_provenance_version,omitempty"`
	BinaryVCSRevision       string            `json:"binary_vcs_revision,omitempty"`
	BinaryVCSModified       *bool             `json:"binary_vcs_modified,omitempty"`
	GOOS                    string            `json:"goos"`
	GOARCH                  string            `json:"goarch"`
	GoVersion               string            `json:"go_version"`
	PythonVersion           string            `json:"python_version"`
	Profiles                []string          `json:"profiles"`
	PolicyRoot              string            `json:"policy_root"`
	OptInPolicyPacks        []string          `json:"opt_in_policy_packs,omitempty"`
	OptInPolicyRoot         string            `json:"opt_in_policy_root,omitempty"`
	PolicyPostures          map[string]string `json:"policy_postures,omitempty"`
	CorpusSHA256            string            `json:"corpus_sha256"`
	TruthCorpusSHA256       string            `json:"truth_corpus_sha256,omitempty"`
	DatasetLockSHA256       string            `json:"dataset_lock_sha256"`
	PolicyDigests           map[string]string `json:"policy_digests"`
	ClassificationSHA256    string            `json:"classification_sha256"`
	Command                 []string          `json:"command"`
	Seed                    int64             `json:"seed"`
}

const BinaryProvenanceSchemaVersion = 1

var boundedIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)

func (p Prediction) Validate() error {
	if p.SchemaVersion != SchemaVersion || strings.TrimSpace(p.RunID) == "" ||
		strings.TrimSpace(p.CaseID) == "" || strings.TrimSpace(p.Engine) == "" {
		return errors.New("incomplete prediction identity")
	}
	if len(p.RunID) > 160 || len(p.CaseID) > 240 || len(p.Engine) > 120 {
		return errors.New("prediction identity exceeds schema bounds")
	}
	if err := ValidateBenchmarkProfile(p.Profile); err != nil {
		return err
	}
	if p.DetectionStepMask&^guardrail.ToolChainKnownStepMask != 0 ||
		p.EnforcementStepMask&^guardrail.ToolChainKnownStepMask != 0 ||
		p.EnforcementStepMask&^p.DetectionStepMask != 0 {
		return errors.New("invalid tool-chain projection masks")
	}
	switch p.Action {
	case "allow", "alert", "confirm", "block", "not_applicable", "error":
	default:
		return fmt.Errorf("unsupported prediction action %q", p.Action)
	}
	switch p.Severity {
	case "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL":
	default:
		return fmt.Errorf("unsupported prediction severity %q", p.Severity)
	}
	switch p.Route {
	case "", "none", "semantic", "fallback", "mixed":
	default:
		return fmt.Errorf("unsupported prediction route %q", p.Route)
	}
	if p.FindingCount < 0 || p.FindingCount > maxPredictionFindingCount ||
		p.AuditFindingCount < 0 || p.AuditFindingCount > maxPredictionFindingCount ||
		p.AdvisoryFindingCount < 0 || p.AdvisoryFindingCount > maxPredictionFindingCount ||
		p.DetectOnlyFindingCount < 0 || p.EnforceableFindingCount < 0 || p.AlertFindingCount < 0 ||
		p.DurationMicros < 0 || len(p.ParseStatus) > 80 || len(p.ErrorCode) > 120 {
		return errors.New("prediction contains an invalid count, duration, or bounded field")
	}
	if p.DetectOnlyFindingCount > maxPredictionFindingCount ||
		p.EnforceableFindingCount > maxPredictionFindingCount || p.AlertFindingCount > maxPredictionFindingCount {
		return errors.New("prediction finding count exceeds schema bounds")
	}
	dispositionCount := p.AuditFindingCount + p.AdvisoryFindingCount +
		p.DetectOnlyFindingCount + p.EnforceableFindingCount
	if dispositionCount > 0 {
		if dispositionCount != p.FindingCount {
			return errors.New("finding disposition counts do not equal finding_count")
		}
		alertCount := p.AdvisoryFindingCount + p.DetectOnlyFindingCount + p.EnforceableFindingCount
		if p.AlertFindingCount != alertCount {
			return errors.New("alert_finding_count does not equal alert dispositions")
		}
		if p.Alerted != (alertCount > 0) {
			return errors.New("alerted does not match alert_finding_count")
		}
	} else if p.AlertFindingCount != 0 || p.Alerted {
		return errors.New("alert fields require finding disposition counts")
	}
	if p.FindingCount == 0 && (p.AlertFindingCount != 0 || p.Alerted) {
		return errors.New("zero-finding prediction cannot be alerted")
	}
	if len(p.EvaluationStatus) > 80 || strings.ContainsAny(p.EvaluationStatus, "\r\n\t") {
		return errors.New("prediction evaluation status exceeds schema bounds")
	}
	seen := make(map[string]struct{}, len(p.RuleIDs))
	for _, issueCode := range p.IssueCodes {
		if len(issueCode) > 80 || !boundedIdentifier.MatchString(issueCode) {
			return fmt.Errorf("invalid or potentially value-bearing issue code %q", issueCode)
		}
	}
	for _, ruleID := range p.RuleIDs {
		if len(ruleID) > 160 || !boundedIdentifier.MatchString(ruleID) {
			return fmt.Errorf("invalid or potentially value-bearing rule ID %q", ruleID)
		}
		if _, exists := seen[ruleID]; exists {
			return fmt.Errorf("duplicate rule ID %q", ruleID)
		}
		seen[ruleID] = struct{}{}
	}
	for _, span := range p.Spans {
		if span.Start < 0 || span.End <= span.Start || strings.TrimSpace(span.Label) == "" || len(span.Label) > 120 || len(span.RuleID) > 160 ||
			(span.RuleID != "" && !boundedIdentifier.MatchString(span.RuleID)) {
			return errors.New("invalid prediction span")
		}
	}
	return nil
}

func (c Case) Validate() error {
	if c.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version=%q, want %q", c.SchemaVersion, SchemaVersion)
	}
	if strings.TrimSpace(c.ID) == "" {
		return errors.New("id is required")
	}
	if strings.TrimSpace(c.Source.Dataset) == "" ||
		strings.TrimSpace(c.Source.Revision) == "" ||
		strings.TrimSpace(c.Source.OriginalID) == "" ||
		strings.TrimSpace(c.Source.License) == "" ||
		strings.TrimSpace(c.Source.Redistribution) == "" {
		return errors.New("complete source provenance is required")
	}
	switch c.Split {
	case "smoke", "development", "validation", "test":
	default:
		return fmt.Errorf("unsupported split %q", c.Split)
	}
	if c.Strata.SplitGroup != "" {
		if len(c.Strata.SplitGroup) != 24 {
			return errors.New("strata.split_group must be a 24-character lowercase hex digest")
		}
		for _, character := range c.Strata.SplitGroup {
			if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
				return errors.New("strata.split_group must be a 24-character lowercase hex digest")
			}
		}
	}
	hasTrajectoryID := c.Strata.TrajectoryID != ""
	hasSequenceIndex := c.Strata.SequenceIndex != nil
	hasCallIndex := c.Strata.CallIndex != nil
	if hasTrajectoryID != hasSequenceIndex || hasTrajectoryID != hasCallIndex {
		return errors.New("strata.trajectory_id, sequence_index, and call_index must be provided together")
	}
	if hasTrajectoryID {
		if len(c.Strata.TrajectoryID) < 24 || len(c.Strata.TrajectoryID) > 64 {
			return errors.New("strata.trajectory_id must be a 24 to 64 character lowercase hex digest")
		}
		for _, character := range c.Strata.TrajectoryID {
			if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
				return errors.New("strata.trajectory_id must be a 24 to 64 character lowercase hex digest")
			}
		}
		if *c.Strata.SequenceIndex < 0 || *c.Strata.CallIndex < 0 {
			return errors.New("strata.sequence_index and call_index must be non-negative")
		}
	}
	switch c.Truth.SourceTruth {
	case TruthBenign, TruthMalicious, TruthSensitive, TruthUnknown:
	default:
		return fmt.Errorf("unsupported source_truth %q", c.Truth.SourceTruth)
	}
	switch c.Truth.DeterministicTruth {
	case "":
		if c.Truth.LabelConfidence != "" || c.Truth.LabelSource != "" {
			return errors.New("label metadata requires deterministic_truth")
		}
	case DeterministicMalicious, DeterministicContextual, DeterministicBenign:
		if c.Truth.LabelSource == "" || !boundedIdentifier.MatchString(c.Truth.LabelSource) {
			return errors.New("deterministic truth requires a bounded label_source")
		}
		switch c.Truth.LabelConfidence {
		case "high", "medium", "low":
		default:
			return errors.New("deterministic truth requires high, medium, or low label_confidence")
		}
	default:
		return fmt.Errorf("unsupported deterministic_truth %q", c.Truth.DeterministicTruth)
	}
	switch c.Truth.Applicability {
	case InScope:
	case OutOfScope:
		if strings.TrimSpace(c.Truth.ExclusionReason) == "" {
			return errors.New("out-of-scope case requires exclusion_reason")
		}
	default:
		return fmt.Errorf("unsupported applicability %q", c.Truth.Applicability)
	}
	switch c.Truth.EnforcementLens {
	case "", "monitor", "egress":
	default:
		return fmt.Errorf("unsupported enforcement_lens %q", c.Truth.EnforcementLens)
	}
	switch c.Truth.StatefulLens {
	case "":
	case StatefulAtomicTerminal, StatefulBoundedIntent, StatefulBoundedComplete:
		if c.Surface != "stateful" {
			return errors.New("stateful_lens is reserved for stateful cases")
		}
	default:
		return fmt.Errorf("unsupported stateful_lens %q", c.Truth.StatefulLens)
	}
	if c.Truth.StatefulLens == StatefulBoundedIntent &&
		c.Truth.ExpectedDisposition == DispositionBlock {
		return errors.New("bounded_intent cannot have expected_disposition=block")
	}
	switch c.Truth.ExpectedDisposition {
	case DispositionAllow, DispositionDetectOnly, DispositionBlock:
	default:
		return fmt.Errorf("unsupported expected_disposition %q", c.Truth.ExpectedDisposition)
	}
	if c.Truth.DeterministicTruth == "" && c.Truth.SourceTruth == TruthBenign && c.Truth.ExpectedDisposition != DispositionAllow {
		return errors.New("benign case must have expected_disposition=allow")
	}
	if c.Truth.DeterministicTruth == DeterministicBenign && c.Truth.ExpectedDisposition != DispositionAllow {
		return errors.New("deterministically benign case must have expected_disposition=allow")
	}
	if c.Truth.DeterministicTruth == DeterministicContextual && c.Truth.ExpectedDisposition == DispositionBlock {
		return errors.New("contextual case cannot have expected_disposition=block")
	}
	for index, span := range c.Truth.Spans {
		if c.Payload.Content == "" || span.Start < 0 || span.End <= span.Start || span.End > len(c.Payload.Content) ||
			strings.TrimSpace(span.Label) == "" || len(span.Label) > 120 || len(span.RuleID) > 160 ||
			(span.RuleID != "" && !boundedIdentifier.MatchString(span.RuleID)) {
			return fmt.Errorf("invalid truth span %d", index)
		}
	}
	for index, span := range c.Payload.AnnotationSpans {
		command := c.Payload.Command
		if span.EventIndex != nil {
			if c.Surface != "stateful" || *span.EventIndex < 0 || *span.EventIndex >= len(c.Payload.Events) {
				return fmt.Errorf("invalid action annotation span %d", index)
			}
			command = c.Payload.Events[*span.EventIndex].Command
		} else if c.Surface != "action" {
			return fmt.Errorf("invalid action annotation span %d", index)
		}
		if command == "" || span.Start < 0 || span.End <= span.Start || span.End > len(command) ||
			strings.TrimSpace(span.Label) == "" || len(span.Label) > 120 || len(span.RuleID) > 160 ||
			(span.RuleID != "" && !boundedIdentifier.MatchString(span.RuleID)) {
			return fmt.Errorf("invalid action annotation span %d", index)
		}
	}
	for profile, action := range c.Truth.ExpectedProfileActions {
		if c.Split != "smoke" {
			return errors.New("expected_profile_actions is reserved for smoke gates")
		}
		if err := ValidateProfile(profile); err != nil {
			return err
		}
		switch action {
		case "allow", "alert", "confirm", "block":
		default:
			return fmt.Errorf("unsupported expected action %q for profile %q", action, profile)
		}
	}
	switch c.Surface {
	case "text":
		if c.Payload.Content == "" || c.Payload.Direction == "" {
			return errors.New("text case requires payload.content and payload.direction")
		}
	case "action":
		if c.Payload.Command == "" && len(c.Payload.Argv) == 0 && len(c.Payload.Args) == 0 {
			return errors.New("action case requires command, argv, or args")
		}
		if len(c.Payload.ToolResourceIdentity) > 1024 ||
			strings.IndexByte(c.Payload.ToolResourceIdentity, 0) >= 0 {
			return errors.New("action case has invalid tool_resource_identity")
		}
	case "tool_result":
		if err := c.Payload.validateToolResult(); err != nil {
			return err
		}
	case "code":
		if c.Payload.Content == "" && c.Payload.Target == "" {
			return errors.New("code case requires content or target")
		}
		if c.Payload.Content != "" && c.Payload.Filename == "" {
			return errors.New("inline code case requires filename")
		}
	case "skill", "plugin", "mcp":
		if c.Payload.Target == "" {
			return fmt.Errorf("%s case requires payload.target", c.Surface)
		}
	case "stateful", "e2e":
		if c.Surface == "stateful" {
			if len(c.Payload.Events) < 2 || len(c.Payload.Events) > 64 {
				return errors.New("stateful case requires 2 to 64 action events")
			}
			priorOffset := -1
			for index, event := range c.Payload.Events {
				if event.Command == "" && len(event.Argv) == 0 && len(event.Args) == 0 {
					return fmt.Errorf("stateful event %d requires command, argv, or args", index)
				}
				if event.OffsetSeconds < priorOffset || event.OffsetSeconds > 1800 {
					return fmt.Errorf("stateful event %d has invalid offset_seconds", index)
				}
				if len(event.ToolResourceIdentity) > 1024 || strings.IndexByte(event.ToolResourceIdentity, 0) >= 0 {
					return fmt.Errorf("stateful event %d has invalid tool_resource_identity", index)
				}
				if c.Truth.StatefulLens != "" {
					switch event.Outcome {
					case "succeeded", "failed", "denied", "cancelled", "unknown":
					default:
						return fmt.Errorf("stateful event %d requires an explicit outcome for an adjudicated truth lens", index)
					}
				}
				if c.Truth.StatefulLens == StatefulBoundedComplete && event.Outcome == "unknown" {
					return fmt.Errorf("stateful event %d has unknown outcome under bounded_completed", index)
				}
				if event.ResultProof != "" {
					if event.Outcome != "succeeded" {
						return fmt.Errorf("stateful event %d result proof requires succeeded outcome", index)
					}
					if len(event.ResultProof) > 256*1024 || strings.IndexByte(event.ResultProof, 0) >= 0 {
						return fmt.Errorf("stateful event %d has invalid result proof", index)
					}
				}
				priorOffset = event.OffsetSeconds
			}
		} else if c.Payload.Content == "" || c.Payload.Direction == "" {
			return errors.New("e2e case requires payload.content and payload.direction")
		}
	default:
		return fmt.Errorf("unsupported surface %q", c.Surface)
	}
	if c.Surface != "tool_result" && c.Payload.ToolResult != nil {
		return errors.New("payload.tool_result is reserved for tool_result cases")
	}
	return nil
}

func (p Payload) validateToolResult() error {
	if p.ToolResult == nil {
		return errors.New("tool_result case requires payload.tool_result")
	}
	if p.Direction != "" || p.Content != "" || p.ToolName != "" || p.Command != "" ||
		len(p.Argv) != 0 || len(p.Args) != 0 || p.Dialect != "" || p.CWD != "" ||
		p.ActiveHome != "" || len(p.ActiveAgentFiles) != 0 || p.Filename != "" ||
		p.Target != "" || len(p.AnnotationSpans) != 0 || len(p.Events) != 0 {
		return errors.New("tool_result payload cannot mix legacy payload fields")
	}

	invocation := p.ToolResult.Invocation
	result := p.ToolResult.Result
	if invocation.Connector == "" || invocation.Event == "" || invocation.SessionID == "" ||
		invocation.InvocationID == "" || invocation.ToolName == "" || len(invocation.Args) == 0 ||
		result.Connector == "" || result.Event == "" || result.SessionID == "" ||
		result.InvocationID == "" || result.Outcome == "" {
		return errors.New("tool_result requires complete invocation and terminal result fields")
	}
	for name, value := range map[string]string{
		"connector": invocation.Connector, "pre event": invocation.Event,
		"session ID": invocation.SessionID, "invocation ID": invocation.InvocationID,
		"tool name": invocation.ToolName, "result event": result.Event,
	} {
		if len(value) > 240 || !boundedIdentifier.MatchString(value) {
			return fmt.Errorf("tool_result has invalid %s", name)
		}
	}
	if invocation.Connector != strings.ToLower(invocation.Connector) ||
		invocation.Connector != result.Connector {
		return errors.New("tool_result connector identity must match exactly and be lowercase")
	}
	if invocation.SessionID != result.SessionID || invocation.InvocationID != result.InvocationID {
		return errors.New("tool_result session and invocation identity must match exactly")
	}
	if len(invocation.Args) > maxToolResultArgsBytes || !json.Valid(invocation.Args) {
		return errors.New("tool_result args must be bounded valid JSON")
	}
	var args map[string]json.RawMessage
	if err := json.Unmarshal(invocation.Args, &args); err != nil || args == nil {
		return errors.New("tool_result args must be a JSON object")
	}
	if len(result.Content) > maxToolResultContentBytes {
		return errors.New("tool_result content exceeds the classifier input bound")
	}
	if err := validateToolResultLifecycle(invocation.Connector, invocation.Event, result.Event, result.Outcome); err != nil {
		return err
	}
	return nil
}

func validateToolResultLifecycle(connector, preEvent, resultEvent, outcome string) error {
	type lifecycle struct {
		pre     string
		success string
		failure string
	}
	known := map[string]lifecycle{
		"amp":        {pre: "tool.call", success: "tool.result", failure: "tool.result"},
		"claudecode": {pre: "PreToolUse", success: "PostToolUse", failure: "PostToolUseFailure"},
		"codex":      {pre: "PreToolUse", success: "PostToolUse", failure: "PostToolUseFailure"},
		"opencode":   {pre: "tool.execute.before", success: "tool.execute.after", failure: "tool.execute.after"},
	}
	contract, ok := known[connector]
	if !ok {
		return fmt.Errorf("tool_result has unsupported connector %q", connector)
	}
	if preEvent != contract.pre {
		return fmt.Errorf("tool_result has invalid pre event for connector %q", connector)
	}
	switch outcome {
	case "succeeded":
		if resultEvent != contract.success {
			return fmt.Errorf("tool_result has invalid success event for connector %q", connector)
		}
	case "failed", "denied", "cancelled":
		if resultEvent != contract.failure {
			return fmt.Errorf("tool_result has invalid failure event for connector %q", connector)
		}
	default:
		return fmt.Errorf("tool_result requires an authoritative terminal outcome, got %q", outcome)
	}
	return nil
}

// detectionTruth selects independently adjudicated command truth when it is
// available. Contextual/dual-use commands are excluded from binary scoring;
// their source provenance remains available as a diagnostic dimension.
func detectionTruth(benchmarkCase Case) (positive bool, scorable bool) {
	if benchmarkCase.Surface == "stateful" {
		switch benchmarkCase.Truth.StatefulLens {
		case StatefulAtomicTerminal, "":
			return false, false
		case StatefulBoundedIntent, StatefulBoundedComplete:
			if !hasTruthRulePrefix(benchmarkCase.Truth.RuleIDs, "chain.") {
				return false, false
			}
			switch benchmarkCase.Truth.DeterministicTruth {
			case DeterministicMalicious:
				return true, true
			case DeterministicBenign:
				return false, true
			default:
				return false, false
			}
		}
	}
	switch benchmarkCase.Truth.DeterministicTruth {
	case DeterministicMalicious:
		return true, true
	case DeterministicBenign:
		return false, true
	case DeterministicContextual:
		return false, false
	}
	switch benchmarkCase.Truth.SourceTruth {
	case TruthMalicious, TruthSensitive:
		return true, true
	case TruthBenign:
		return false, true
	default:
		return false, false
	}
}

func benignTruth(benchmarkCase Case) bool {
	if benchmarkCase.Surface == "stateful" &&
		benchmarkCase.Truth.StatefulLens == StatefulAtomicTerminal {
		return false
	}
	if benchmarkCase.Truth.DeterministicTruth != "" {
		return benchmarkCase.Truth.DeterministicTruth == DeterministicBenign
	}
	return benchmarkCase.Truth.SourceTruth == TruthBenign
}

func detectionPrediction(benchmarkCase Case, prediction Prediction, positive bool) bool {
	if benchmarkCase.Surface == "stateful" && benchmarkCase.Truth.StatefulLens != "" &&
		benchmarkCase.Truth.StatefulLens != StatefulAtomicTerminal && len(benchmarkCase.Truth.RuleIDs) > 0 {
		if !prediction.Detected {
			return false
		}
		for _, expected := range benchmarkCase.Truth.RuleIDs {
			for _, actual := range prediction.RuleIDs {
				if actual == expected {
					return true
				}
			}
		}
		return false
	}
	if !prediction.Detected || !positive || len(benchmarkCase.Truth.RuleIDs) == 0 {
		return prediction.Detected
	}
	for _, expected := range benchmarkCase.Truth.RuleIDs {
		for _, actual := range prediction.RuleIDs {
			if actual == expected {
				return true
			}
		}
	}
	return false
}

func enforcementTruth(benchmarkCase Case) (positive bool, scorable bool) {
	if benchmarkCase.Surface == "stateful" {
		switch benchmarkCase.Truth.StatefulLens {
		case StatefulAtomicTerminal, StatefulBoundedIntent, "":
			return false, false
		case StatefulBoundedComplete:
			return benchmarkCase.Truth.ExpectedDisposition == DispositionBlock, true
		}
	}
	return benchmarkCase.Truth.ExpectedDisposition == DispositionBlock, true
}

func hasTruthRulePrefix(ruleIDs []string, prefix string) bool {
	for _, ruleID := range ruleIDs {
		if strings.HasPrefix(ruleID, prefix) {
			return true
		}
	}
	return false
}

func ValidateProfile(profile string) error {
	if !validProfiles[profile] {
		return fmt.Errorf("unsupported profile %q", profile)
	}
	return nil
}

// ValidateOptInPolicyPack restricts benchmark policy selection to the public,
// repository-owned opt-in packs. Keeping this allowlist separate from runtime
// profiles prevents a benchmark argument from becoming an arbitrary path.
func ValidateOptInPolicyPack(name string) error {
	if !validOptInPolicyPacks[name] {
		return fmt.Errorf("unsupported opt-in policy pack %q", name)
	}
	return nil
}

// OptInPolicyLabel returns the distinct score/report dimension for a named
// opt-in pack. Opt-in packs use the balanced/default action posture, but are
// never reported as the default profile.
func OptInPolicyLabel(name string) (string, error) {
	if err := ValidateOptInPolicyPack(name); err != nil {
		return "", err
	}
	return optInPolicyLabelPrefix + name, nil
}

// ValidateBenchmarkProfile accepts standard runtime profiles and the closed
// set of benchmark-only opt-in labels emitted by Runner.
func ValidateBenchmarkProfile(profile string) error {
	if validProfiles[profile] {
		return nil
	}
	if !strings.HasPrefix(profile, optInPolicyLabelPrefix) {
		return fmt.Errorf("unsupported benchmark profile %q", profile)
	}
	return ValidateOptInPolicyPack(strings.TrimPrefix(profile, optInPolicyLabelPrefix))
}
