// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

// Package scanoutput projects scanner results for machine-readable output.
// Canonical scanner and audit values remain untouched; only the returned copy
// is suitable for CLI stdout or an authenticated API response.
package scanoutput

import (
	"crypto/rand"
	"sort"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

const correlationKeyBytes = 32

const highEntropyDetectorID observabilityredaction.DetectorID = "secrets.high_entropy"

// The complete path is scanned first, then each component is scanned again.
// Generic entropy tokens can consume adjacent separators in the complete pass;
// the component pass recovers a secret used as one filename or directory while
// preserving path separators and independently detected safe components.
var pathComponentDetectorGroups = []observabilityredaction.DetectorGroup{
	observabilityredaction.DetectorGroupCredentials,
	observabilityredaction.DetectorGroupSecrets,
	observabilityredaction.DetectorGroupPII,
}

// Redactor owns an immutable copy of a correlation key. A key-unavailable
// redactor is still safe: every non-empty dynamic string fails closed.
type Redactor struct {
	key       [correlationKeyBytes]byte
	available bool
}

// LoadRedactor loads or securely creates the installation correlation key.
func LoadRedactor(dataDir string) (*Redactor, error) {
	key, err := observabilityredaction.LoadOrCreateCorrelationKey(dataDir)
	if err != nil {
		return nil, err
	}
	return NewRedactor(key), nil
}

// NewRedactor snapshots an installation correlation key.
func NewRedactor(key observabilityredaction.CorrelationKey) *Redactor {
	material, available := key.Material()
	redactor := &Redactor{available: available}
	if available {
		copy(redactor.key[:], material[:])
	}
	for i := range material {
		material[i] = 0
	}
	return redactor
}

// NewEphemeralRedactor creates a process-local projector for callers without
// an installation data directory (principally hermetic tests). Production CLI
// and gateway paths use LoadRedactor so tokens correlate within an install.
func NewEphemeralRedactor() (*Redactor, error) {
	redactor := &Redactor{available: true}
	if _, err := rand.Read(redactor.key[:]); err != nil {
		return nil, err
	}
	return redactor, nil
}

// NewUnavailableRedactor returns a fail-closed projector. It is used by the
// long-running API if key custody becomes unavailable: response usability may
// degrade, but raw finding text is never the fallback.
func NewUnavailableRedactor() *Redactor { return &Redactor{} }

// FingerprintRuntimeV8FindingContent exposes only the compact, keyed evidence
// token required by the audit persistence boundary. The method deliberately
// matches audit.RuntimeV8FindingContentFingerprinter by shape without importing
// the audit package, so standalone CLI scans can reuse the same installation
// key as their machine-output projection without starting a telemetry runtime.
func (redactor *Redactor) FingerprintRuntimeV8FindingContent(value string) (string, error) {
	engine, err := observabilityredaction.NewEngine(redactor.keyBytes())
	if err != nil {
		return "", err
	}
	return engine.CorrelationFingerprintV1(value, observability.FieldClassEvidence)
}

// Clone returns an independent result with structured file/line data and no
// redaction. It is reserved for an explicit local CLI raw-output choice.
func Clone(input *scanner.ScanResult) *scanner.ScanResult {
	if input == nil {
		return nil
	}
	output := *input
	output.Findings = make([]scanner.Finding, len(input.Findings))
	for i := range input.Findings {
		output.Findings[i] = cloneFinding(input.Findings[i])
		populateStructuredLocation(&output.Findings[i])
	}
	return &output
}

// Project returns a detached, substring-redacted result. Safe surrounding
// context is preserved. Detector, key, UTF-8, and resource-limit failures use
// the detector's whole-field failed-closed token and never raw input.
func (redactor *Redactor) Project(input *scanner.ScanResult) *scanner.ScanResult {
	output := Clone(input)
	if output == nil {
		return nil
	}
	output.Target = redactor.detectPath(output.Target)
	for i := range output.Findings {
		finding := &output.Findings[i]
		trustDirective := isTrustDirectiveFinding(*finding)
		secretFinding := strings.EqualFold(strings.TrimSpace(finding.Scanner), "clawshield-secrets")
		if trustDirective {
			// Prompt-injection matches are executable model directives, not safe
			// explanatory prose. Keep rule identity, location, and remediation
			// useful while ensuring machine output cannot replay the directive.
			finding.Title = redactor.whole(finding.Title, observability.FieldClassEvidence)
			finding.Description = redactor.whole(finding.Description, observability.FieldClassEvidence)
		} else {
			finding.Title = redactor.detect(finding.Title, observability.FieldClassEvidence)
		}
		if secretFinding {
			finding.Description = redactor.whole(finding.Description, observability.FieldClassEvidence)
		} else if !trustDirective {
			finding.Description = redactor.detect(finding.Description, observability.FieldClassEvidence)
		}
		if trustDirective || secretFinding {
			finding.EvidenceSummary = redactor.whole(
				finding.EvidenceSummary,
				observability.FieldClassEvidence,
			)
		} else {
			finding.EvidenceSummary = redactor.detect(
				finding.EvidenceSummary,
				observability.FieldClassEvidence,
			)
		}
		finding.Location = redactor.detectPath(finding.Location)
		finding.File = redactor.detectPath(finding.File)
		finding.Remediation = redactor.detect(finding.Remediation, observability.FieldClassReason)
		for tagIndex := range finding.Tags {
			finding.Tags[tagIndex] = redactor.detect(
				finding.Tags[tagIndex], observability.FieldClassIdentifier,
			)
		}
	}
	return output
}

func isTrustDirectiveFinding(finding scanner.Finding) bool {
	for _, value := range []string{finding.ID, finding.RuleID} {
		canonical := strings.ToUpper(strings.TrimSpace(value))
		for _, prefix := range []string{"CS-INJ-", "TRUST-", "LP-INJ-", "JUDGE-ADJ-INJECTION"} {
			if strings.HasPrefix(canonical, prefix) {
				return true
			}
		}
	}
	for _, value := range append([]string{finding.Category}, finding.Tags...) {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "injection", "prompt-injection", "trust-exploit":
			return true
		}
	}
	return false
}

// detectPath first scans the complete value, then its filesystem components.
// Detector boundary rules deliberately treat slash as part of some token
// alphabets, so a complete-path-only pass can miss an email or identifier used
// as a directory name. The first pass still catches credentials that span a
// slash; the component pass closes the boundary gap without changing safe
// separators or drive/UNC syntax.
func (redactor *Redactor) detectPath(input string) string {
	if input == "" {
		return ""
	}
	// A field-local budget prevents one attacker-controlled finding from
	// poisoning every later safe field in the same scan result. Each field is
	// still independently bounded by the detector's byte and match ceilings.
	budget := observabilityredaction.NewRecordMatchBudget()
	whole, err := observabilityredaction.DetectAndRedact(
		input,
		observability.FieldClassPath,
		observabilityredaction.DetectorGroups(),
		redactor.keyBytes(),
		budget,
	)
	if err != nil {
		return whole.Value
	}
	matches := make([]observabilityredaction.Match, 0, len(whole.Matches))
	for _, match := range whole.Matches {
		// A filesystem separator is a semantic boundary, not part of one
		// anonymous entropy token. Let named credential/secret/PII recognizers
		// continue to span the complete path, but never let the generic entropy
		// heuristic merge several ordinary components into a false secret.
		if match.ID == highEntropyDetectorID &&
			strings.ContainsAny(input[match.Start:match.End], `/\`) {
			continue
		}
		matches = append(matches, match)
	}
	start := 0
	for index := 0; index <= len(input); index++ {
		if index < len(input) && input[index] != '/' && input[index] != '\\' {
			continue
		}
		if index > start {
			component, componentErr := observabilityredaction.DetectAndRedact(
				input[start:index],
				observability.FieldClassPath,
				pathComponentDetectorGroups,
				redactor.keyBytes(),
				budget,
			)
			if componentErr != nil {
				// A component-level detector failure must fail the complete
				// field closed, not replace a path with one component token.
				return redactor.whole(input, observability.FieldClassPath)
			}
			for _, match := range component.Matches {
				if match.ID == highEntropyDetectorID &&
					!allowPathComponentEntropy(input[start+match.Start:start+match.End]) {
					continue
				}
				match.Start += start
				match.End += start
				if !overlapsScanOutputMatch(matches, match.Start, match.End) {
					matches = append(matches, match)
				}
			}
		}
		start = index + 1
	}
	if len(matches) == 0 {
		return input
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].Start != matches[j].Start {
			return matches[i].Start < matches[j].Start
		}
		return matches[i].End < matches[j].End
	})
	output := input
	for index := len(matches) - 1; index >= 0; index-- {
		match := matches[index]
		output = output[:match.Start] + match.Token + output[match.End:]
	}
	return output
}

func allowPathComponentEntropy(value string) bool {
	// Path components are an unusually noisy entropy surface: build IDs and
	// hyphenated temp directories often satisfy the generic detector at its
	// 20-byte floor. Require enough standalone token material plus a strong
	// base64-style signal before treating an otherwise anonymous component as a
	// secret. Named credential, assignment, URL-query, and PII detectors are not
	// affected by this filter.
	if len(value) < 24 {
		return false
	}
	hasUpper := strings.IndexFunc(value, func(char rune) bool {
		return char >= 'A' && char <= 'Z'
	}) >= 0
	hasEncodingPunctuation := strings.ContainsAny(value, "+_=")
	return hasUpper || hasEncodingPunctuation
}

func overlapsScanOutputMatch(matches []observabilityredaction.Match, start, end int) bool {
	for _, match := range matches {
		if start < match.End && match.Start < end {
			return true
		}
	}
	return false
}

func (redactor *Redactor) detect(
	input string,
	class observability.FieldClass,
) string {
	value, _ := redactor.detectWithFailure(input, class)
	return value
}

func (redactor *Redactor) detectWithFailure(
	input string,
	class observability.FieldClass,
) (string, bool) {
	if input == "" {
		return "", false
	}
	var key []byte
	if redactor != nil && redactor.available {
		key = redactor.keyBytes()
	}
	result, err := observabilityredaction.DetectAndRedact(
		input,
		class,
		observabilityredaction.DetectorGroups(),
		key,
		observabilityredaction.NewRecordMatchBudget(),
	)
	return result.Value, err != nil
}

func (redactor *Redactor) keyBytes() []byte {
	if redactor == nil || !redactor.available {
		return nil
	}
	return redactor.key[:]
}

func (redactor *Redactor) whole(input string, class observability.FieldClass) string {
	if input == "" {
		return ""
	}
	if redactor == nil || !redactor.available {
		token, _ := observabilityredaction.FailedClosedToken(observabilityredaction.FailureKeyUnavailable)
		return token
	}
	token, err := observabilityredaction.WholeToken(class, input, redactor.key[:])
	if err == nil {
		return token
	}
	token, _ = observabilityredaction.FailedClosedToken(observabilityredaction.FailureValidator)
	return token
}

func cloneFinding(input scanner.Finding) scanner.Finding {
	output := input
	output.Tags = append([]string(nil), input.Tags...)
	output.DataAxis = append([]string(nil), input.DataAxis...)
	output.DecisionPath = append([]byte(nil), input.DecisionPath...)
	if input.LineNumber != nil {
		line := *input.LineNumber
		output.LineNumber = &line
	}
	if input.TurnID != nil {
		turn := *input.TurnID
		output.TurnID = &turn
	}
	return output
}

func populateStructuredLocation(finding *scanner.Finding) {
	if finding == nil || finding.Location == "" {
		return
	}
	location := finding.Location
	if finding.LineNumber != nil && *finding.LineNumber > 0 {
		suffix := ":" + strconv.Itoa(*finding.LineNumber)
		if strings.HasSuffix(location, suffix) && len(location) > len(suffix) {
			finding.File = strings.TrimSuffix(location, suffix)
		} else {
			finding.File = location
		}
		return
	}
	// Without a scanner-supplied LineNumber, a final `:<number>` is
	// ambiguous: it can be a legitimate POSIX filename or Windows drive-
	// relative path. Preserve the complete path rather than invent structure.
	finding.File = location
}
