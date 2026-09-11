// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package benchmark

import (
	"fmt"
	"math"
	"math/rand"
	"sort"
)

const pairedBootstrapIterations = 2000

// MetricComparison is a candidate-minus-baseline point delta with a paired,
// fixed-seed bootstrap interval.
type MetricComparison struct {
	Baseline  float64  `json:"baseline"`
	Candidate float64  `json:"candidate"`
	Delta     float64  `json:"delta"`
	Delta95   Interval `json:"delta_95"`
}

type RunClassificationChanges struct {
	PositiveDetectionGains  int `json:"positive_detection_gains"`
	PositiveDetectionLosses int `json:"positive_detection_losses"`
	BenignFindingIntroduced int `json:"benign_findings_introduced"`
	BenignFindingResolved   int `json:"benign_findings_resolved"`
	ExpectedBlockGains      int `json:"expected_block_gains"`
	ExpectedBlockLosses     int `json:"expected_block_losses"`
	BenignBlockIntroduced   int `json:"benign_blocks_introduced"`
	BenignBlockResolved     int `json:"benign_blocks_resolved"`
	MoreRestrictiveActions  int `json:"more_restrictive_actions"`
	LessRestrictiveActions  int `json:"less_restrictive_actions"`
}

type RunProfileComparison struct {
	Profile                 string                   `json:"profile"`
	Predictions             int                      `json:"predictions"`
	ComparablePredictions   int                      `json:"comparable_predictions"`
	BaselineErrors          int                      `json:"baseline_errors"`
	CandidateErrors         int                      `json:"candidate_errors"`
	DetectionPrecision      MetricComparison         `json:"detection_precision"`
	DetectionRecall         MetricComparison         `json:"detection_recall"`
	DetectionF1             MetricComparison         `json:"detection_f1"`
	DetectionFPR            MetricComparison         `json:"detection_false_positive_rate"`
	EnforcementPrecision    MetricComparison         `json:"enforcement_precision"`
	EnforcementRecall       MetricComparison         `json:"enforcement_recall"`
	EnforcementF1           MetricComparison         `json:"enforcement_f1"`
	BenignBlockRate         MetricComparison         `json:"benign_block_rate"`
	DetectOnlyOverblockRate MetricComparison         `json:"detect_only_overblock_rate"`
	Changes                 RunClassificationChanges `json:"changes"`
}

type RunComparison struct {
	SchemaVersion     string                 `json:"schema_version"`
	BaselineRunID     string                 `json:"baseline_run_id"`
	CandidateRunID    string                 `json:"candidate_run_id"`
	CorpusSHA256      string                 `json:"corpus_sha256,omitempty"`
	TruthCorpusSHA256 string                 `json:"truth_corpus_sha256,omitempty"`
	Seed              int64                  `json:"seed"`
	Profiles          []RunProfileComparison `json:"profiles"`
}

type jointCounts [4]int

func (j *jointCounts) add(baseline, candidate bool) {
	index := 0
	if baseline {
		index += 2
	}
	if candidate {
		index++
	}
	j[index]++
}

func (j jointCounts) total() int {
	return j[0] + j[1] + j[2] + j[3]
}

type pairedAccumulator struct {
	profile             string
	predictions         int
	comparable          int
	baselineErrors      int
	candidateErrors     int
	detectionPositive   jointCounts
	detectionNegative   jointCounts
	enforcementPositive jointCounts
	enforcementNegative jointCounts
	benignBlock         jointCounts
	detectOnlyBlock     jointCounts
	changes             RunClassificationChanges
}

// CompareRuns compares two complete prediction sets on identical
// profile/case/engine keys. Missing predictions or applicability drift are
// errors so candidate metrics cannot improve by silently dropping hard cases.
func CompareRuns(cases []Case, baseline, candidate []Prediction, seed int64) (RunComparison, error) {
	caseByID := make(map[string]Case, len(cases))
	for _, benchmarkCase := range cases {
		if _, exists := caseByID[benchmarkCase.ID]; exists {
			return RunComparison{}, fmt.Errorf("duplicate case ID %q", benchmarkCase.ID)
		}
		caseByID[benchmarkCase.ID] = benchmarkCase
	}
	baselineRunID, baselineByProfile, err := indexComparisonPredictions(caseByID, baseline)
	if err != nil {
		return RunComparison{}, fmt.Errorf("baseline: %w", err)
	}
	candidateRunID, candidateByProfile, err := indexComparisonPredictions(caseByID, candidate)
	if err != nil {
		return RunComparison{}, fmt.Errorf("candidate: %w", err)
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		if len(baselineByProfile[profile]) != len(candidateByProfile[profile]) {
			return RunComparison{}, fmt.Errorf(
				"profile %s prediction count differs: baseline=%d candidate=%d",
				profile,
				len(baselineByProfile[profile]),
				len(candidateByProfile[profile]),
			)
		}
		for key := range baselineByProfile[profile] {
			if _, ok := candidateByProfile[profile][key]; !ok {
				return RunComparison{}, fmt.Errorf("profile %s candidate is missing prediction key %q", profile, key)
			}
		}
	}

	comparison := RunComparison{
		SchemaVersion:  SchemaVersion,
		BaselineRunID:  baselineRunID,
		CandidateRunID: candidateRunID,
		Seed:           seed,
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		if len(baselineByProfile[profile]) == 0 {
			continue
		}
		accumulator := pairedAccumulator{profile: profile}
		keys := make([]string, 0, len(baselineByProfile[profile]))
		for key := range baselineByProfile[profile] {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			baselinePrediction := baselineByProfile[profile][key]
			candidatePrediction := candidateByProfile[profile][key]
			benchmarkCase := caseByID[baselinePrediction.CaseID]
			if baselinePrediction.Applicable != candidatePrediction.Applicable {
				return RunComparison{}, fmt.Errorf(
					"profile %s case %s applicability differs",
					profile,
					baselinePrediction.CaseID,
				)
			}
			accumulator.record(benchmarkCase, baselinePrediction, candidatePrediction)
		}
		comparison.Profiles = append(comparison.Profiles, accumulator.finish(seed))
	}
	if len(comparison.Profiles) == 0 {
		return RunComparison{}, fmt.Errorf("runs have no shared profiles")
	}
	return comparison, nil
}

func indexComparisonPredictions(
	caseByID map[string]Case,
	predictions []Prediction,
) (string, map[string]map[string]Prediction, error) {
	if len(predictions) == 0 {
		return "", nil, fmt.Errorf("predictions are empty")
	}
	runID := predictions[0].RunID
	indexed := make(map[string]map[string]Prediction)
	for _, prediction := range predictions {
		if prediction.RunID != runID {
			return "", nil, fmt.Errorf("mixed run IDs %q and %q", runID, prediction.RunID)
		}
		if _, ok := caseByID[prediction.CaseID]; !ok {
			return "", nil, fmt.Errorf("prediction references unknown case %q", prediction.CaseID)
		}
		entries := indexed[prediction.Profile]
		if entries == nil {
			entries = make(map[string]Prediction)
			indexed[prediction.Profile] = entries
		}
		key := prediction.CaseID + "\x00" + prediction.Engine
		if _, exists := entries[key]; exists {
			return "", nil, fmt.Errorf("duplicate prediction key for profile=%s case=%s engine=%s", prediction.Profile, prediction.CaseID, prediction.Engine)
		}
		entries[key] = prediction
	}
	return runID, indexed, nil
}

func (a *pairedAccumulator) record(benchmarkCase Case, baseline, candidate Prediction) {
	a.predictions++
	if baseline.ErrorCode != "" || baseline.Action == "error" {
		a.baselineErrors++
	}
	if candidate.ErrorCode != "" || candidate.Action == "error" {
		a.candidateErrors++
	}
	if benchmarkCase.Truth.Applicability != InScope ||
		!baseline.Applicable || !candidate.Applicable ||
		baseline.ErrorCode != "" || baseline.Action == "error" ||
		candidate.ErrorCode != "" || candidate.Action == "error" {
		return
	}
	a.comparable++
	positiveTruth, detectionScorable := detectionTruth(benchmarkCase)
	isBenign := benignTruth(benchmarkCase)
	if detectionScorable {
		if positiveTruth {
			a.detectionPositive.add(baseline.Detected, candidate.Detected)
		} else {
			a.detectionNegative.add(baseline.Detected, candidate.Detected)
		}
	}
	baselineBlocked := baseline.Action == "block"
	candidateBlocked := candidate.Action == "block"
	if benchmarkCase.Truth.ExpectedDisposition == DispositionBlock {
		a.enforcementPositive.add(baselineBlocked, candidateBlocked)
	} else {
		a.enforcementNegative.add(baselineBlocked, candidateBlocked)
	}
	if isBenign {
		a.benignBlock.add(baselineBlocked, candidateBlocked)
	}
	if benchmarkCase.Truth.ExpectedDisposition == DispositionDetectOnly {
		a.detectOnlyBlock.add(baselineBlocked, candidateBlocked)
	}

	if !baseline.Detected && candidate.Detected {
		if positiveTruth {
			a.changes.PositiveDetectionGains++
		}
		if isBenign {
			a.changes.BenignFindingIntroduced++
		}
	}
	if baseline.Detected && !candidate.Detected {
		if positiveTruth {
			a.changes.PositiveDetectionLosses++
		}
		if isBenign {
			a.changes.BenignFindingResolved++
		}
	}
	if benchmarkCase.Truth.ExpectedDisposition == DispositionBlock {
		if !baselineBlocked && candidateBlocked {
			a.changes.ExpectedBlockGains++
		}
		if baselineBlocked && !candidateBlocked {
			a.changes.ExpectedBlockLosses++
		}
	}
	if isBenign {
		if !baselineBlocked && candidateBlocked {
			a.changes.BenignBlockIntroduced++
		}
		if baselineBlocked && !candidateBlocked {
			a.changes.BenignBlockResolved++
		}
	}
	baselineRank, baselineRanked := actionRank(baseline.Action)
	candidateRank, candidateRanked := actionRank(candidate.Action)
	if baselineRanked && candidateRanked {
		if candidateRank > baselineRank {
			a.changes.MoreRestrictiveActions++
		}
		if candidateRank < baselineRank {
			a.changes.LessRestrictiveActions++
		}
	}
}

func (a pairedAccumulator) finish(seed int64) RunProfileComparison {
	detectionBaseline, detectionCandidate := pairedBinary(a.detectionPositive, a.detectionNegative)
	enforcementBaseline, enforcementCandidate := pairedBinary(a.enforcementPositive, a.enforcementNegative)
	result := RunProfileComparison{
		Profile:                 a.profile,
		Predictions:             a.predictions,
		ComparablePredictions:   a.comparable,
		BaselineErrors:          a.baselineErrors,
		CandidateErrors:         a.candidateErrors,
		DetectionPrecision:      pointComparison(detectionBaseline.precision, detectionCandidate.precision),
		DetectionRecall:         pointComparison(detectionBaseline.recall, detectionCandidate.recall),
		DetectionF1:             pointComparison(detectionBaseline.f1, detectionCandidate.f1),
		DetectionFPR:            pointComparison(detectionBaseline.fpr, detectionCandidate.fpr),
		EnforcementPrecision:    pointComparison(enforcementBaseline.precision, enforcementCandidate.precision),
		EnforcementRecall:       pointComparison(enforcementBaseline.recall, enforcementCandidate.recall),
		EnforcementF1:           pointComparison(enforcementBaseline.f1, enforcementCandidate.f1),
		BenignBlockRate:         pointComparison(jointRate(a.benignBlock, true), jointRate(a.benignBlock, false)),
		DetectOnlyOverblockRate: pointComparison(jointRate(a.detectOnlyBlock, true), jointRate(a.detectOnlyBlock, false)),
		Changes:                 a.changes,
	}

	type sampleSet struct {
		detectionPrecision   []float64
		detectionRecall      []float64
		detectionF1          []float64
		detectionFPR         []float64
		enforcementPrecision []float64
		enforcementRecall    []float64
		enforcementF1        []float64
		benignBlock          []float64
		detectOnlyBlock      []float64
	}
	samples := sampleSet{
		detectionPrecision:   make([]float64, 0, pairedBootstrapIterations),
		detectionRecall:      make([]float64, 0, pairedBootstrapIterations),
		detectionF1:          make([]float64, 0, pairedBootstrapIterations),
		detectionFPR:         make([]float64, 0, pairedBootstrapIterations),
		enforcementPrecision: make([]float64, 0, pairedBootstrapIterations),
		enforcementRecall:    make([]float64, 0, pairedBootstrapIterations),
		enforcementF1:        make([]float64, 0, pairedBootstrapIterations),
		benignBlock:          make([]float64, 0, pairedBootstrapIterations),
		detectOnlyBlock:      make([]float64, 0, pairedBootstrapIterations),
	}
	random := rand.New(rand.NewSource(groupSeed(seed, "run-comparison/"+a.profile)))
	for range pairedBootstrapIterations {
		detectionPositive := sampleJointCounts(random, a.detectionPositive)
		detectionNegative := sampleJointCounts(random, a.detectionNegative)
		baselineDetection, candidateDetection := pairedBinary(detectionPositive, detectionNegative)
		samples.detectionPrecision = append(samples.detectionPrecision, candidateDetection.precision-baselineDetection.precision)
		samples.detectionRecall = append(samples.detectionRecall, candidateDetection.recall-baselineDetection.recall)
		samples.detectionF1 = append(samples.detectionF1, candidateDetection.f1-baselineDetection.f1)
		samples.detectionFPR = append(samples.detectionFPR, candidateDetection.fpr-baselineDetection.fpr)

		enforcementPositive := sampleJointCounts(random, a.enforcementPositive)
		enforcementNegative := sampleJointCounts(random, a.enforcementNegative)
		baselineEnforcement, candidateEnforcement := pairedBinary(enforcementPositive, enforcementNegative)
		samples.enforcementPrecision = append(samples.enforcementPrecision, candidateEnforcement.precision-baselineEnforcement.precision)
		samples.enforcementRecall = append(samples.enforcementRecall, candidateEnforcement.recall-baselineEnforcement.recall)
		samples.enforcementF1 = append(samples.enforcementF1, candidateEnforcement.f1-baselineEnforcement.f1)

		benignBlock := sampleJointCounts(random, a.benignBlock)
		samples.benignBlock = append(samples.benignBlock, jointRate(benignBlock, false)-jointRate(benignBlock, true))
		detectOnlyBlock := sampleJointCounts(random, a.detectOnlyBlock)
		samples.detectOnlyBlock = append(samples.detectOnlyBlock, jointRate(detectOnlyBlock, false)-jointRate(detectOnlyBlock, true))
	}
	result.DetectionPrecision.Delta95 = percentileInterval(samples.detectionPrecision)
	result.DetectionRecall.Delta95 = percentileInterval(samples.detectionRecall)
	result.DetectionF1.Delta95 = percentileInterval(samples.detectionF1)
	result.DetectionFPR.Delta95 = percentileInterval(samples.detectionFPR)
	result.EnforcementPrecision.Delta95 = percentileInterval(samples.enforcementPrecision)
	result.EnforcementRecall.Delta95 = percentileInterval(samples.enforcementRecall)
	result.EnforcementF1.Delta95 = percentileInterval(samples.enforcementF1)
	result.BenignBlockRate.Delta95 = percentileInterval(samples.benignBlock)
	result.DetectOnlyOverblockRate.Delta95 = percentileInterval(samples.detectOnlyBlock)
	return result
}

type binaryPoint struct {
	precision float64
	recall    float64
	f1        float64
	fpr       float64
}

func pairedBinary(positive, negative jointCounts) (binaryPoint, binaryPoint) {
	baselineTP := positive[2] + positive[3]
	candidateTP := positive[1] + positive[3]
	baselineFP := negative[2] + negative[3]
	candidateFP := negative[1] + negative[3]
	return binaryPointFromCounts(baselineTP, positive.total()-baselineTP, baselineFP, negative.total()-baselineFP),
		binaryPointFromCounts(candidateTP, positive.total()-candidateTP, candidateFP, negative.total()-candidateFP)
}

func binaryPointFromCounts(truePositive, falseNegative, falsePositive, trueNegative int) binaryPoint {
	precision := ratio(truePositive, truePositive+falsePositive)
	recall := ratio(truePositive, truePositive+falseNegative)
	return binaryPoint{
		precision: precision,
		recall:    recall,
		f1:        harmonic(precision, recall),
		fpr:       ratio(falsePositive, falsePositive+trueNegative),
	}
}

func pointComparison(baseline, candidate float64) MetricComparison {
	return MetricComparison{Baseline: baseline, Candidate: candidate, Delta: candidate - baseline}
}

func jointRate(counts jointCounts, baseline bool) float64 {
	positive := counts[1] + counts[3]
	if baseline {
		positive = counts[2] + counts[3]
	}
	return ratio(positive, counts.total())
}

func sampleJointCounts(random *rand.Rand, population jointCounts) jointCounts {
	remainingPopulation := population.total()
	remainingSample := remainingPopulation
	var sampled jointCounts
	for index := 0; index < len(population)-1; index++ {
		if remainingPopulation == 0 || remainingSample == 0 {
			break
		}
		probability := float64(population[index]) / float64(remainingPopulation)
		sampled[index] = sampleBinomial(random, remainingSample, probability)
		remainingSample -= sampled[index]
		remainingPopulation -= population[index]
	}
	sampled[len(sampled)-1] = remainingSample
	return sampled
}

func percentileInterval(values []float64) Interval {
	if len(values) == 0 {
		return Interval{}
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	lower := int(math.Floor(0.025 * float64(len(sorted)-1)))
	upper := int(math.Ceil(0.975 * float64(len(sorted)-1)))
	return Interval{Lower: sorted[lower], Upper: sorted[upper]}
}
