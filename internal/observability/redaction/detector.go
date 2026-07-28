// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

const (
	MaxScannedStringBytes = 256 * 1024
	MaxFieldCandidates    = 512
	MaxFieldMatches       = 256
	MaxRecordMatches      = 4096
)

// Match describes a final non-overlapping replacement interval. Start and End
// are half-open byte offsets into the original valid UTF-8 input. It never
// contains the matched bytes.
type Match struct {
	Start int
	End   int
	ID    DetectorID
	Token string
}

// DetectionResult is a distinct output value and value-free match metadata.
type DetectionResult struct {
	Value             string
	Matches           []Match
	LexicalCandidates int
	AcceptedMatches   int
	Oversize          bool
	Failure           FailureCode
}

// RecordMatchBudget enforces the fixed accepted-match limit across fields. Its
// synchronization prevents races, but callers preserve deterministic field
// exhaustion by consuming it in canonical projection traversal order.
type RecordMatchBudget struct {
	mu        sync.Mutex
	accepted  int
	exhausted bool
}

// NewRecordMatchBudget returns an empty fixed v1 budget.
func NewRecordMatchBudget() *RecordMatchBudget { return &RecordMatchBudget{} }

// Accepted returns the count committed by successfully processed prior fields.
func (budget *RecordMatchBudget) Accepted() int {
	if budget == nil {
		return 0
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	return budget.accepted
}

func (budget *RecordMatchBudget) consume(count int) bool {
	if budget == nil {
		return count <= MaxRecordMatches
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if budget.exhausted || count > MaxRecordMatches-budget.accepted {
		budget.exhausted = true
		return false
	}
	budget.accepted += count
	return true
}

func (budget *RecordMatchBudget) isExhausted() bool {
	if budget == nil {
		return false
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	return budget.exhausted
}

type candidate struct {
	start    int
	end      int
	accepted bool
}

type acceptedMatch struct {
	start int
	end   int
	id    DetectorID
	group DetectorGroup
	order int
}

// DetectAndRedact executes the selected immutable detector groups and replaces
// accepted matches. Every failure returns a complete safe field replacement and
// a typed, value-free error; it never returns a raw prefix or suffix.
func DetectAndRedact(
	input string,
	fieldClass observability.FieldClass,
	groups []DetectorGroup,
	key []byte,
	recordBudget *RecordMatchBudget,
) (DetectionResult, error) {
	if !utf8.ValidString(input) {
		return failedDetection(FailureInvalidUTF8)
	}
	if !observability.IsFieldClass(fieldClass) {
		return failedDetection(FailureValidator)
	}
	if len(key) != hashV1KeySize {
		return failedDetection(FailureKeyUnavailable)
	}
	if recordBudget != nil && recordBudget.isExhausted() {
		return failedDetection(FailureRecordMatchLimit)
	}
	if len(input) > MaxScannedStringBytes {
		token, err := OversizeToken(fieldClass, input, key)
		if err != nil {
			return failedDetection(codeFromError(err))
		}
		return DetectionResult{Value: token, Oversize: true}, nil
	}

	enabled, err := selectedDetectorIDs(groups)
	if err != nil {
		return failedDetection(FailureValidator)
	}
	accepted := make([]acceptedMatch, 0, 8)
	candidateCount := 0
	for _, definition := range generatedCatalogDefinitions {
		if _, ok := enabled[definition.id]; !ok {
			continue
		}
		found, scanErr := recognize(definition.id, input, fieldClass, accepted)
		if scanErr != nil {
			return failedDetection(codeFromError(scanErr))
		}
		for _, item := range found {
			candidateCount++
			if candidateCount > MaxFieldCandidates {
				return failedDetectionWithCandidates(FailureCandidateLimit, candidateCount)
			}
			if !validCandidate(item, len(input), definition.candidateBound) || !item.accepted {
				continue
			}
			accepted = append(accepted, acceptedMatch{
				start: item.start, end: item.end, id: definition.id,
				group: definition.group, order: definition.order,
			})
			if len(accepted) > MaxFieldMatches {
				return failedDetectionWithCandidates(FailureFieldMatchLimit, candidateCount)
			}
		}
	}

	if !recordBudget.consume(len(accepted)) {
		return failedDetectionWithCandidates(FailureRecordMatchLimit, candidateCount)
	}
	clusters := clusterMatches(accepted)
	result := DetectionResult{
		Value: input, LexicalCandidates: candidateCount, AcceptedMatches: len(accepted),
		Matches: make([]Match, len(clusters)),
	}
	for i, item := range clusters {
		token, tokenErr := DetectedToken(item.id, input[item.start:item.end], key)
		if tokenErr != nil {
			return failedDetectionWithCandidates(codeFromError(tokenErr), candidateCount)
		}
		result.Matches[i] = Match{Start: item.start, End: item.end, ID: item.id, Token: token}
	}
	for i := len(result.Matches) - 1; i >= 0; i-- {
		item := result.Matches[i]
		result.Value = result.Value[:item.Start] + item.Token + result.Value[item.End:]
	}
	return result, nil
}

func selectedDetectorIDs(groups []DetectorGroup) (map[DetectorID]struct{}, error) {
	if len(groups) == 0 {
		return nil, detectorError(FailureValidator)
	}
	selected := make(map[DetectorID]struct{}, len(generatedCatalogDefinitions))
	seen := make(map[DetectorGroup]struct{}, len(groups))
	for _, group := range groups {
		if _, duplicate := seen[group]; duplicate {
			continue
		}
		seen[group] = struct{}{}
		members, ok := DetectorsForGroup(group)
		if !ok {
			return nil, detectorError(FailureValidator)
		}
		for _, id := range members {
			selected[id] = struct{}{}
		}
	}
	return selected, nil
}

func validCandidate(item candidate, inputLength, bound int) bool {
	return item.start >= 0 && item.end > item.start && item.end <= inputLength && item.end-item.start <= bound
}

func failedDetection(code FailureCode) (DetectionResult, error) {
	return failedDetectionWithCandidates(code, 0)
}

func failedDetectionWithCandidates(code FailureCode, candidates int) (DetectionResult, error) {
	token, err := FailedClosedToken(code)
	if err != nil {
		code = FailureValidator
		token = "<redacted type=failed_closed v=1 code=validator_failed>"
	}
	return DetectionResult{Value: token, LexicalCandidates: candidates, Failure: code}, detectorError(code)
}

func codeFromError(err error) FailureCode {
	var typed *DetectorError
	if errorsAsDetector(err, &typed) {
		return typed.Code
	}
	return FailureValidator
}

// Kept as a tiny indirection so detector errors cannot accidentally expose a
// wrapped parser error while being classified.
func errorsAsDetector(err error, target **DetectorError) bool {
	if err == nil {
		return false
	}
	typed, ok := err.(*DetectorError)
	if ok {
		*target = typed
	}
	return ok
}

func clusterMatches(matches []acceptedMatch) []acceptedMatch {
	if len(matches) == 0 {
		return nil
	}
	ordered := append([]acceptedMatch(nil), matches...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].start != ordered[j].start {
			return ordered[i].start < ordered[j].start
		}
		if ordered[i].end != ordered[j].end {
			return ordered[i].end > ordered[j].end
		}
		return betterIdentity(ordered[i], ordered[j])
	})
	clusters := make([]acceptedMatch, 0, len(ordered))
	winner := ordered[0]
	unionStart := winner.start
	unionEnd := winner.end
	for _, next := range ordered[1:] {
		if next.start >= unionEnd { // adjacency is not overlap
			output := winner
			output.start, output.end = unionStart, unionEnd
			clusters = append(clusters, output)
			winner = next
			unionStart = next.start
			unionEnd = next.end
			continue
		}
		if next.end > unionEnd {
			unionEnd = next.end
		}
		if betterIdentity(next, winner) {
			winner = next
		}
	}
	output := winner
	output.start, output.end = unionStart, unionEnd
	clusters = append(clusters, output)
	return clusters
}

func betterIdentity(left, right acceptedMatch) bool {
	leftPriority, rightPriority := groupPriority(left.group), groupPriority(right.group)
	if leftPriority != rightPriority {
		return leftPriority < rightPriority
	}
	if left.order != right.order {
		return left.order < right.order
	}
	if left.start != right.start {
		return left.start < right.start
	}
	return left.end-left.start > right.end-right.start
}

func groupPriority(group DetectorGroup) int {
	switch group {
	case DetectorGroupCredentials:
		return 0
	case DetectorGroupSecrets:
		return 1
	case DetectorGroupPII:
		return 2
	default:
		return 3
	}
}

func overlapsCredentialClaim(start, end int, accepted []acceptedMatch) bool {
	for _, match := range accepted {
		if match.group == DetectorGroupCredentials && start < match.end && match.start < end {
			return true
		}
	}
	return false
}

func asciiEqualFold(left, right string) bool { return strings.EqualFold(left, right) }
