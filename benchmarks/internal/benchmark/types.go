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
)

var validProfiles = map[string]bool{
	"default":    true,
	"permissive": true,
	"strict":     true,
}

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
	Direction        string          `json:"direction,omitempty"`
	Content          string          `json:"content,omitempty"`
	ToolName         string          `json:"tool_name,omitempty"`
	Command          string          `json:"command,omitempty"`
	Argv             []string        `json:"argv,omitempty"`
	Args             json.RawMessage `json:"args,omitempty"`
	Dialect          string          `json:"dialect,omitempty"`
	CWD              string          `json:"cwd,omitempty"`
	ActiveHome       string          `json:"active_home,omitempty"`
	ActiveAgentFiles []string        `json:"active_agent_files,omitempty"`
	Filename         string          `json:"filename,omitempty"`
	Target           string          `json:"target,omitempty"`
	Events           []ActionEvent   `json:"events,omitempty"`
}

type ActionEvent struct {
	ToolName         string          `json:"tool_name,omitempty"`
	Command          string          `json:"command,omitempty"`
	Argv             []string        `json:"argv,omitempty"`
	Args             json.RawMessage `json:"args,omitempty"`
	Dialect          string          `json:"dialect,omitempty"`
	CWD              string          `json:"cwd,omitempty"`
	ActiveHome       string          `json:"active_home,omitempty"`
	ActiveAgentFiles []string        `json:"active_agent_files,omitempty"`
	Outcome          string          `json:"outcome,omitempty"`
	OffsetSeconds    int             `json:"offset_seconds,omitempty"`
}

type Truth struct {
	SourceTruth            string            `json:"source_truth"`
	DeterministicTruth     string            `json:"deterministic_truth,omitempty"`
	LabelConfidence        string            `json:"label_confidence,omitempty"`
	LabelSource            string            `json:"label_source,omitempty"`
	EnforcementLens        string            `json:"enforcement_lens,omitempty"`
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
	RunID                string            `json:"run_id"`
	CaseCount            int               `json:"case_count"`
	PredictionCount      int               `json:"prediction_count"`
	DefenseClawCommit    string            `json:"defenseclaw_commit"`
	Dirty                bool              `json:"dirty"`
	GOOS                 string            `json:"goos"`
	GOARCH               string            `json:"goarch"`
	GoVersion            string            `json:"go_version"`
	PythonVersion        string            `json:"python_version"`
	Profiles             []string          `json:"profiles"`
	PolicyRoot           string            `json:"policy_root"`
	CorpusSHA256         string            `json:"corpus_sha256"`
	TruthCorpusSHA256    string            `json:"truth_corpus_sha256,omitempty"`
	DatasetLockSHA256    string            `json:"dataset_lock_sha256"`
	PolicyDigests        map[string]string `json:"policy_digests"`
	ClassificationSHA256 string            `json:"classification_sha256"`
	Command              []string          `json:"command"`
	Seed                 int64             `json:"seed"`
}

var boundedIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)

func (p Prediction) Validate() error {
	if p.SchemaVersion != SchemaVersion || strings.TrimSpace(p.RunID) == "" ||
		strings.TrimSpace(p.CaseID) == "" || strings.TrimSpace(p.Engine) == "" {
		return errors.New("incomplete prediction identity")
	}
	if len(p.RunID) > 160 || len(p.CaseID) > 240 || len(p.Engine) > 120 {
		return errors.New("prediction identity exceeds schema bounds")
	}
	if err := ValidateProfile(p.Profile); err != nil {
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
				priorOffset = event.OffsetSeconds
			}
		} else if c.Payload.Content == "" || c.Payload.Direction == "" {
			return errors.New("e2e case requires payload.content and payload.direction")
		}
	default:
		return fmt.Errorf("unsupported surface %q", c.Surface)
	}
	return nil
}

// detectionTruth selects independently adjudicated command truth when it is
// available. Contextual/dual-use commands are excluded from binary scoring;
// their source provenance remains available as a diagnostic dimension.
func detectionTruth(benchmarkCase Case) (positive bool, scorable bool) {
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
	if benchmarkCase.Truth.DeterministicTruth != "" {
		return benchmarkCase.Truth.DeterministicTruth == DeterministicBenign
	}
	return benchmarkCase.Truth.SourceTruth == TruthBenign
}

func ValidateProfile(profile string) error {
	if !validProfiles[profile] {
		return fmt.Errorf("unsupported profile %q", profile)
	}
	return nil
}
