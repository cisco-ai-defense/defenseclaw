// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package benchmark

import (
	"fmt"
	"hash/fnv"
	"math"
	"math/rand"
	"sort"
)

type Confusion struct {
	TruePositive  int `json:"true_positive"`
	TrueNegative  int `json:"true_negative"`
	FalsePositive int `json:"false_positive"`
	FalseNegative int `json:"false_negative"`
}

type Interval struct {
	Lower float64 `json:"lower"`
	Upper float64 `json:"upper"`
}

type BinaryMetrics struct {
	Confusion   Confusion `json:"confusion"`
	Precision   float64   `json:"precision"`
	Recall      float64   `json:"recall"`
	F1          float64   `json:"f1"`
	FPR         float64   `json:"false_positive_rate"`
	Specificity float64   `json:"specificity"`
	Precision95 Interval  `json:"precision_95"`
	Recall95    Interval  `json:"recall_95"`
	FPR95       Interval  `json:"false_positive_rate_95"`
	F195        Interval  `json:"f1_95"`
}

// SpanMetrics scores value-free byte ranges using one-to-one overlap matching.
// Labels are retained in artifacts for stratification, but this boundary metric
// deliberately measures whether the sensitive value was localized at all.
type SpanMetrics struct {
	TruePositive  int     `json:"true_positive"`
	FalsePositive int     `json:"false_positive"`
	FalseNegative int     `json:"false_negative"`
	Precision     float64 `json:"precision"`
	Recall        float64 `json:"recall"`
	F1            float64 `json:"f1"`
}

type Rate struct {
	Numerator    int      `json:"numerator"`
	Denominator  int      `json:"denominator"`
	Value        float64  `json:"value"`
	Confidence95 Interval `json:"confidence_95"`
}

type Latency struct {
	P50Micros int64 `json:"p50_micros"`
	P95Micros int64 `json:"p95_micros"`
	P99Micros int64 `json:"p99_micros"`
}

type GroupScore struct {
	Profile                 string        `json:"profile"`
	Dimension               string        `json:"dimension"`
	Group                   string        `json:"group"`
	Cases                   int           `json:"cases"`
	Applicable              int           `json:"applicable"`
	OutOfScope              int           `json:"out_of_scope"`
	Errors                  int           `json:"errors"`
	ApplicabilityRate       Rate          `json:"applicability_rate"`
	ErrorRate               Rate          `json:"error_rate"`
	Detection               BinaryMetrics `json:"detection"`
	Alert                   BinaryMetrics `json:"alert"`
	Enforcement             BinaryMetrics `json:"enforcement"`
	Spans                   SpanMetrics   `json:"spans"`
	BenignBlockRate         Rate          `json:"benign_block_rate"`
	AuditTelemetryRate      Rate          `json:"audit_telemetry_rate"`
	DetectOnlyOverblock     Rate          `json:"detect_only_overblock_rate"`
	SafeAbstentionRate      Rate          `json:"safe_abstention_rate"`
	AuthoritativeRate       Rate          `json:"authoritative_rate"`
	EnforcementEligibleRate Rate          `json:"enforcement_eligible_rate"`
	SemanticMatchRouteRate  Rate          `json:"semantic_match_route_rate"`
	FallbackMatchRouteRate  Rate          `json:"fallback_match_route_rate"`
	MixedMatchRouteRate     Rate          `json:"mixed_match_route_rate"`
	Latency                 Latency       `json:"latency"`
	LowSupport              bool          `json:"low_support"`
	FPRClaimMinimum         int           `json:"fpr_claim_minimum"`
	FPRClaimEligible        bool          `json:"fpr_claim_eligible"`
}

type ProfileMacro struct {
	Profile       string  `json:"profile"`
	DetectionF1   float64 `json:"detection_f1"`
	AlertF1       float64 `json:"alert_f1"`
	EnforcementF1 float64 `json:"enforcement_f1"`
	SurfaceCount  int     `json:"surface_count"`
}

// ProfileComparison reports paired classification changes on identical
// case/engine keys. It intentionally contains only aggregate counts and never
// emits source payloads or case identifiers.
type ProfileComparison struct {
	BaselineProfile          string `json:"baseline_profile"`
	ComparisonProfile        string `json:"comparison_profile"`
	SharedPredictions        int    `json:"shared_predictions"`
	ComparablePredictions    int    `json:"comparable_predictions"`
	BaselineErrors           int    `json:"baseline_errors"`
	ComparisonErrors         int    `json:"comparison_errors"`
	SameDetection            int    `json:"same_detection"`
	BaselineOnlyDetections   int    `json:"baseline_only_detections"`
	ComparisonOnlyDetections int    `json:"comparison_only_detections"`
	PositiveDetectionGains   int    `json:"positive_detection_gains"`
	PositiveDetectionLosses  int    `json:"positive_detection_losses"`
	BenignFindingIntroduced  int    `json:"benign_findings_introduced"`
	BenignFindingResolved    int    `json:"benign_findings_resolved"`
	SameAction               int    `json:"same_action"`
	MoreRestrictiveActions   int    `json:"more_restrictive_actions"`
	LessRestrictiveActions   int    `json:"less_restrictive_actions"`
	ExpectedBlockGains       int    `json:"expected_block_gains"`
	ExpectedBlockLosses      int    `json:"expected_block_losses"`
	BenignBlockIntroduced    int    `json:"benign_blocks_introduced"`
	BenignBlockResolved      int    `json:"benign_blocks_resolved"`
}

type Summary struct {
	SchemaVersion      string              `json:"schema_version"`
	RunID              string              `json:"run_id"`
	Groups             []GroupScore        `json:"groups"`
	Macro              []ProfileMacro      `json:"macro"`
	ProfileComparisons []ProfileComparison `json:"profile_comparisons,omitempty"`
}

type groupAccumulator struct {
	profile             string
	dimension           string
	group               string
	cases               int
	applicable          int
	outOfScope          int
	errors              int
	detection           Confusion
	alert               Confusion
	enforcement         Confusion
	benign              int
	benignBlock         int
	detectOnly          int
	detectBlock         int
	latencies           []int64
	parseEligible       int
	authoritative       int
	enforcementEligible int
	safeAbstentions     int
	detected            int
	auditTelemetry      int
	semanticRoute       int
	fallbackRoute       int
	mixedRoute          int
	spanTP              int
	spanFP              int
	spanFN              int
}

func Score(cases []Case, predictions []Prediction, seed int64) (Summary, error) {
	caseByID := make(map[string]Case, len(cases))
	for _, benchmarkCase := range cases {
		if _, exists := caseByID[benchmarkCase.ID]; exists {
			return Summary{}, fmt.Errorf("duplicate case ID %q", benchmarkCase.ID)
		}
		caseByID[benchmarkCase.ID] = benchmarkCase
	}
	if len(predictions) == 0 {
		return Summary{}, fmt.Errorf("no predictions")
	}
	runID := predictions[0].RunID
	groups := make(map[string]*groupAccumulator)
	seen := make(map[string]struct{}, len(predictions))
	for _, prediction := range predictions {
		benchmarkCase, ok := caseByID[prediction.CaseID]
		if !ok {
			return Summary{}, fmt.Errorf("prediction references unknown case %q", prediction.CaseID)
		}
		if prediction.RunID != runID {
			return Summary{}, fmt.Errorf("mixed run IDs %q and %q", runID, prediction.RunID)
		}
		key := prediction.Profile + "\x00" + prediction.CaseID + "\x00" + prediction.Engine
		if _, exists := seen[key]; exists {
			return Summary{}, fmt.Errorf("duplicate prediction for profile=%s case=%s engine=%s", prediction.Profile, prediction.CaseID, prediction.Engine)
		}
		seen[key] = struct{}{}
		for _, grouping := range scoreGroups(benchmarkCase, prediction) {
			groupKey := prediction.Profile + "\x00" + grouping.dimension + "\x00" + grouping.value
			group := groups[groupKey]
			if group == nil {
				group = &groupAccumulator{profile: prediction.Profile, dimension: grouping.dimension, group: grouping.value}
				groups[groupKey] = group
			}
			group.record(benchmarkCase, prediction)
		}
	}

	summary := Summary{SchemaVersion: SchemaVersion, RunID: runID}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		summary.Groups = append(summary.Groups, groups[key].finish(seed))
	}
	summary.Macro = macroScores(summary.Groups)
	summary.ProfileComparisons = compareProfiles(cases, predictions)
	return summary, nil
}

func (g *groupAccumulator) record(benchmarkCase Case, prediction Prediction) {
	g.cases++
	if benchmarkCase.Truth.Applicability != InScope || !prediction.Applicable {
		g.outOfScope++
		return
	}
	g.applicable++
	if prediction.ErrorCode != "" || prediction.Action == "error" {
		g.errors++
		return
	}
	g.latencies = append(g.latencies, prediction.DurationMicros)
	if prediction.ParseStatus != "" {
		g.parseEligible++
		if prediction.Authoritative {
			g.authoritative++
		}
		if prediction.EnforcementEligible {
			g.enforcementEligible++
		}
		if !prediction.Authoritative && prediction.Action != "block" {
			g.safeAbstentions++
		}
	}
	if prediction.Detected {
		g.detected++
		switch prediction.Route {
		case "semantic":
			g.semanticRoute++
		case "fallback":
			g.fallbackRoute++
		case "mixed":
			g.mixedRoute++
		}
	}
	if prediction.AuditFindingCount > 0 {
		g.auditTelemetry++
	}

	if truth, scorable := detectionTruth(benchmarkCase); scorable {
		observe(&g.detection, truth, prediction.Detected)
		observe(&g.alert, truth, predictionIsAlerted(prediction))
	}
	if benchmarkCase.Surface == "text" {
		g.recordSpans(benchmarkCase.Truth.Spans, prediction.Spans)
	}

	blockTruth := benchmarkCase.Truth.ExpectedDisposition == DispositionBlock
	blocked := prediction.Action == "block"
	observe(&g.enforcement, blockTruth, blocked)
	if benignTruth(benchmarkCase) {
		g.benign++
		if blocked {
			g.benignBlock++
		}
	}
	if benchmarkCase.Truth.ExpectedDisposition == DispositionDetectOnly {
		g.detectOnly++
		if blocked {
			g.detectBlock++
		}
	}
}

func (g *groupAccumulator) finish(seed int64) GroupScore {
	bootstrapIterations := g.bootstrapIterations()
	minimum := 30
	if g.dimension == "overall" {
		minimum = 10000
	} else if g.dimension == "surface" && ratio(g.detection.FalsePositive, g.detection.FalsePositive+g.detection.TrueNegative) < 0.001 {
		minimum = 3000
	}
	return GroupScore{
		Profile:                 g.profile,
		Dimension:               g.dimension,
		Group:                   g.group,
		Cases:                   g.cases,
		Applicable:              g.applicable,
		OutOfScope:              g.outOfScope,
		Errors:                  g.errors,
		ApplicabilityRate:       calculateRate(g.applicable, g.cases),
		ErrorRate:               calculateRate(g.errors, g.applicable),
		Detection:               calculateBinary(g.detection, groupSeed(seed, g.profile+"/"+g.dimension+"/"+g.group+"/detection"), bootstrapIterations),
		Alert:                   calculateBinary(g.alert, groupSeed(seed, g.profile+"/"+g.dimension+"/"+g.group+"/alert"), bootstrapIterations),
		Enforcement:             calculateBinary(g.enforcement, groupSeed(seed, g.profile+"/"+g.dimension+"/"+g.group+"/enforcement"), bootstrapIterations),
		Spans:                   calculateSpans(g.spanTP, g.spanFP, g.spanFN),
		BenignBlockRate:         calculateRate(g.benignBlock, g.benign),
		AuditTelemetryRate:      calculateRate(g.auditTelemetry, g.applicable-g.errors),
		DetectOnlyOverblock:     calculateRate(g.detectBlock, g.detectOnly),
		SafeAbstentionRate:      calculateRate(g.safeAbstentions, g.parseEligible),
		AuthoritativeRate:       calculateRate(g.authoritative, g.parseEligible),
		EnforcementEligibleRate: calculateRate(g.enforcementEligible, g.parseEligible),
		SemanticMatchRouteRate:  calculateRate(g.semanticRoute, g.detected),
		FallbackMatchRouteRate:  calculateRate(g.fallbackRoute, g.detected),
		MixedMatchRouteRate:     calculateRate(g.mixedRoute, g.detected),
		Latency:                 calculateLatency(g.latencies),
		LowSupport:              g.detection.TruePositive+g.detection.FalseNegative < 30 || g.detection.TrueNegative+g.detection.FalsePositive < 30,
		FPRClaimMinimum:         minimum,
		FPRClaimEligible:        g.detection.TrueNegative+g.detection.FalsePositive >= minimum,
	}
}

// predictionIsAlerted keeps schema-v1 predictions written before disposition
// aggregates conservative: every legacy detection remains an alert. New
// predictions are distinguished by their non-zero aggregate counts.
func predictionIsAlerted(prediction Prediction) bool {
	dispositionCount := prediction.AuditFindingCount + prediction.AdvisoryFindingCount +
		prediction.DetectOnlyFindingCount + prediction.EnforceableFindingCount
	if dispositionCount == 0 {
		return prediction.Detected
	}
	return prediction.Alerted
}

func (g *groupAccumulator) bootstrapIterations() int {
	switch g.dimension {
	case "overall":
		return 2000
	case "surface", "dataset":
		return 500
	default:
		return 0
	}
}

func (g *groupAccumulator) recordSpans(truth, predicted []Span) {
	matched := make([]bool, len(truth))
	for _, candidate := range predicted {
		bestIndex := -1
		bestOverlap := 0
		for index, expected := range truth {
			if matched[index] {
				continue
			}
			start := candidate.Start
			if expected.Start > start {
				start = expected.Start
			}
			end := candidate.End
			if expected.End < end {
				end = expected.End
			}
			if overlap := end - start; overlap > bestOverlap {
				bestIndex = index
				bestOverlap = overlap
			}
		}
		if bestIndex >= 0 {
			matched[bestIndex] = true
			g.spanTP++
		} else {
			g.spanFP++
		}
	}
	for _, found := range matched {
		if !found {
			g.spanFN++
		}
	}
}

func calculateSpans(truePositive, falsePositive, falseNegative int) SpanMetrics {
	precision := ratio(truePositive, truePositive+falsePositive)
	recall := ratio(truePositive, truePositive+falseNegative)
	return SpanMetrics{
		TruePositive:  truePositive,
		FalsePositive: falsePositive,
		FalseNegative: falseNegative,
		Precision:     precision,
		Recall:        recall,
		F1:            harmonic(precision, recall),
	}
}

type scoreGrouping struct {
	dimension string
	value     string
}

func scoreGroups(benchmarkCase Case, prediction Prediction) []scoreGrouping {
	hardNegative := "false"
	if benchmarkCase.Strata.HardNegative {
		hardNegative = "true"
	}
	groups := []scoreGrouping{
		{dimension: "overall", value: "all"},
		{dimension: "surface", value: benchmarkCase.Surface},
		{dimension: "dataset", value: benchmarkCase.Source.Dataset},
		{dimension: "source_truth", value: benchmarkCase.Truth.SourceTruth},
		{dimension: "expected_disposition", value: benchmarkCase.Truth.ExpectedDisposition},
		{dimension: "hard_negative", value: hardNegative},
	}
	if benchmarkCase.Truth.DeterministicTruth != "" {
		groups = append(groups,
			scoreGrouping{dimension: "deterministic_truth", value: benchmarkCase.Truth.DeterministicTruth},
			scoreGrouping{dimension: "label_confidence", value: benchmarkCase.Truth.LabelConfidence},
			scoreGrouping{dimension: "label_source", value: benchmarkCase.Truth.LabelSource},
		)
	}
	if benchmarkCase.Truth.EnforcementLens != "" {
		groups = append(groups, scoreGrouping{dimension: "enforcement_lens", value: benchmarkCase.Truth.EnforcementLens})
	}
	for _, issueCode := range prediction.IssueCodes {
		groups = append(groups, scoreGrouping{dimension: "parse_issue", value: issueCode})
	}
	for _, category := range compactStrings(append([]string(nil), benchmarkCase.Truth.Categories...)) {
		groups = append(groups, scoreGrouping{dimension: "category", value: category})
	}
	for _, item := range []scoreGrouping{
		{dimension: "platform", value: benchmarkCase.Strata.Platform},
		{dimension: "dialect", value: firstNonEmpty(benchmarkCase.Strata.Dialect, benchmarkCase.Payload.Dialect)},
		{dimension: "language", value: benchmarkCase.Strata.Language},
		{dimension: "ecosystem", value: benchmarkCase.Strata.Ecosystem},
		{dimension: "campaign", value: benchmarkCase.Strata.Campaign},
		{dimension: "domain", value: benchmarkCase.Strata.Domain},
		{dimension: "document_type", value: benchmarkCase.Strata.DocumentType},
		{dimension: "route", value: prediction.Route},
		{dimension: "parse_status", value: prediction.ParseStatus},
		{dimension: "cel_evaluation_status", value: prediction.EvaluationStatus},
	} {
		if item.value != "" && item.value != "none" {
			groups = append(groups, item)
		}
	}
	if prediction.ParseStatus != "" {
		authority := "non_authoritative"
		if prediction.Authoritative {
			authority = "authoritative"
		}
		groups = append(groups, scoreGrouping{dimension: "actionfacts_authority", value: authority})
		eligibility := "not_enforcement_eligible"
		if prediction.EnforcementEligible {
			eligibility = "enforcement_eligible"
		}
		groups = append(groups, scoreGrouping{dimension: "enforcement_eligibility", value: eligibility})
	}
	seen := make(map[string]struct{}, len(groups))
	out := groups[:0]
	for _, group := range groups {
		key := group.dimension + "\x00" + group.value
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, group)
	}
	return out
}

func observe(confusion *Confusion, truth, prediction bool) {
	switch {
	case truth && prediction:
		confusion.TruePositive++
	case truth:
		confusion.FalseNegative++
	case prediction:
		confusion.FalsePositive++
	default:
		confusion.TrueNegative++
	}
}

func calculateBinary(confusion Confusion, seed int64, bootstrapIterations int) BinaryMetrics {
	precision := ratio(confusion.TruePositive, confusion.TruePositive+confusion.FalsePositive)
	recall := ratio(confusion.TruePositive, confusion.TruePositive+confusion.FalseNegative)
	fpr := ratio(confusion.FalsePositive, confusion.FalsePositive+confusion.TrueNegative)
	f1 := harmonic(precision, recall)
	return BinaryMetrics{
		Confusion:   confusion,
		Precision:   precision,
		Recall:      recall,
		F1:          f1,
		FPR:         fpr,
		Specificity: ratio(confusion.TrueNegative, confusion.TrueNegative+confusion.FalsePositive),
		Precision95: wilson(confusion.TruePositive, confusion.TruePositive+confusion.FalsePositive),
		Recall95:    wilson(confusion.TruePositive, confusion.TruePositive+confusion.FalseNegative),
		FPR95:       wilson(confusion.FalsePositive, confusion.FalsePositive+confusion.TrueNegative),
		F195:        bootstrapF1(confusion, seed, bootstrapIterations),
	}
}

func calculateRate(numerator, denominator int) Rate {
	return Rate{
		Numerator:    numerator,
		Denominator:  denominator,
		Value:        ratio(numerator, denominator),
		Confidence95: wilson(numerator, denominator),
	}
}

func ratio(numerator, denominator int) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}

func harmonic(a, b float64) float64 {
	if a+b == 0 {
		return 0
	}
	return 2 * a * b / (a + b)
}

func wilson(successes, total int) Interval {
	if total == 0 {
		return Interval{}
	}
	const z = 1.959963984540054
	n := float64(total)
	p := float64(successes) / n
	z2 := z * z
	center := (p + z2/(2*n)) / (1 + z2/n)
	half := z * math.Sqrt((p*(1-p)+z2/(4*n))/n) / (1 + z2/n)
	return Interval{Lower: math.Max(0, center-half), Upper: math.Min(1, center+half)}
}

func bootstrapF1(confusion Confusion, seed int64, iterations int) Interval {
	positive := confusion.TruePositive + confusion.FalseNegative
	negative := confusion.FalsePositive + confusion.TrueNegative
	if positive+negative == 0 || iterations <= 0 {
		return Interval{}
	}
	rng := rand.New(rand.NewSource(seed)) // #nosec G404 -- fixed seed is required for reproducible statistics.
	tpr := ratio(confusion.TruePositive, positive)
	fpr := ratio(confusion.FalsePositive, negative)
	values := make([]float64, iterations)
	for iteration := range iterations {
		truePositive := sampleBinomial(rng, positive, tpr)
		falsePositive := sampleBinomial(rng, negative, fpr)
		precision := ratio(truePositive, truePositive+falsePositive)
		recall := ratio(truePositive, positive)
		values[iteration] = harmonic(precision, recall)
	}
	sort.Float64s(values)
	return Interval{
		Lower: values[int(0.025*float64(iterations-1))],
		Upper: values[int(0.975*float64(iterations-1))],
	}
}

// sampleBinomial draws an exact binomial variate using the rejection method
// described in Numerical Recipes (3rd ed., section 7.3). Sampling aggregate
// counts is equivalent to independently resampling predictions within the
// positive and negative truth strata, but avoids work proportional to corpus
// size for every bootstrap iteration.
func sampleBinomial(rng *rand.Rand, n int, probability float64) int {
	if n <= 0 || probability <= 0 {
		return 0
	}
	if probability >= 1 {
		return n
	}
	p := probability
	complement := false
	if p > 0.5 {
		p = 1 - p
		complement = true
	}
	mean := float64(n) * p
	var sample int
	switch {
	case n < 25:
		for range n {
			if rng.Float64() < p {
				sample++
			}
		}
	case mean < 1:
		// Skip runs of failures using exact geometric waiting times. The
		// expected loop count is mean rather than n for this sparse case.
		position := 0
		logFailure := math.Log1p(-p)
		for position < n {
			failures := int(math.Floor(-rng.ExpFloat64() / logFailure))
			position += failures
			if position >= n {
				break
			}
			sample++
			position++
		}
	default:
		logFactorialN, _ := math.Lgamma(float64(n) + 1)
		logP := math.Log(p)
		logComplement := math.Log1p(-p)
		scale := math.Sqrt(2 * mean * (1 - p))
		for {
			var candidate, tangent float64
			for {
				tangent = math.Tan(math.Pi * rng.Float64())
				candidate = scale*tangent + mean
				if candidate >= 0 && candidate < float64(n)+1 {
					break
				}
			}
			candidate = math.Floor(candidate)
			logFactorialCandidate, _ := math.Lgamma(candidate + 1)
			logFactorialRemainder, _ := math.Lgamma(float64(n) - candidate + 1)
			acceptance := 1.2 * scale * (1 + tangent*tangent) * math.Exp(
				logFactorialN-logFactorialCandidate-logFactorialRemainder+
					candidate*logP+(float64(n)-candidate)*logComplement,
			)
			if rng.Float64() <= acceptance {
				sample = int(candidate)
				break
			}
		}
	}
	if complement {
		return n - sample
	}
	return sample
}

func calculateLatency(values []int64) Latency {
	if len(values) == 0 {
		return Latency{}
	}
	values = append([]int64(nil), values...)
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	quantile := func(q float64) int64 {
		index := int(math.Ceil(q*float64(len(values)))) - 1
		if index < 0 {
			index = 0
		}
		if index >= len(values) {
			index = len(values) - 1
		}
		return values[index]
	}
	return Latency{P50Micros: quantile(0.50), P95Micros: quantile(0.95), P99Micros: quantile(0.99)}
}

func groupSeed(seed int64, key string) int64 {
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(key))
	return seed ^ int64(hash.Sum64())
}

func macroScores(groups []GroupScore) []ProfileMacro {
	type accumulator struct {
		detection   float64
		alert       float64
		enforcement float64
		count       int
	}
	byProfile := make(map[string]*accumulator)
	for _, group := range groups {
		if group.Dimension != "surface" || group.Applicable == 0 || group.Errors == group.Applicable {
			continue
		}
		entry := byProfile[group.Profile]
		if entry == nil {
			entry = &accumulator{}
			byProfile[group.Profile] = entry
		}
		entry.detection += group.Detection.F1
		entry.alert += group.Alert.F1
		entry.enforcement += group.Enforcement.F1
		entry.count++
	}
	profiles := make([]string, 0, len(byProfile))
	for profile := range byProfile {
		profiles = append(profiles, profile)
	}
	sort.Strings(profiles)
	out := make([]ProfileMacro, 0, len(profiles))
	for _, profile := range profiles {
		entry := byProfile[profile]
		out = append(out, ProfileMacro{
			Profile:       profile,
			DetectionF1:   entry.detection / float64(entry.count),
			AlertF1:       entry.alert / float64(entry.count),
			EnforcementF1: entry.enforcement / float64(entry.count),
			SurfaceCount:  entry.count,
		})
	}
	return out
}

func compareProfiles(cases []Case, predictions []Prediction) []ProfileComparison {
	caseByID := make(map[string]Case, len(cases))
	for _, benchmarkCase := range cases {
		caseByID[benchmarkCase.ID] = benchmarkCase
	}
	byProfile := make(map[string]map[string]Prediction)
	for _, prediction := range predictions {
		entries := byProfile[prediction.Profile]
		if entries == nil {
			entries = make(map[string]Prediction)
			byProfile[prediction.Profile] = entries
		}
		entries[prediction.CaseID+"\x00"+prediction.Engine] = prediction
	}
	var profiles []string
	for _, profile := range []string{"default", "permissive", "strict"} {
		if len(byProfile[profile]) > 0 {
			profiles = append(profiles, profile)
		}
	}
	var comparisons []ProfileComparison
	for leftIndex, baselineProfile := range profiles {
		for _, comparisonProfile := range profiles[leftIndex+1:] {
			comparison := ProfileComparison{
				BaselineProfile:   baselineProfile,
				ComparisonProfile: comparisonProfile,
			}
			for key, baseline := range byProfile[baselineProfile] {
				candidate, ok := byProfile[comparisonProfile][key]
				if !ok {
					continue
				}
				comparison.SharedPredictions++
				if baseline.ErrorCode != "" || baseline.Action == "error" {
					comparison.BaselineErrors++
				}
				if candidate.ErrorCode != "" || candidate.Action == "error" {
					comparison.ComparisonErrors++
				}
				if !baseline.Applicable || !candidate.Applicable ||
					baseline.ErrorCode != "" || candidate.ErrorCode != "" ||
					baseline.Action == "error" || candidate.Action == "error" {
					continue
				}
				comparison.ComparablePredictions++
				benchmarkCase := caseByID[baseline.CaseID]
				positiveTruth, positiveScorable := detectionTruth(benchmarkCase)
				positiveTruth = positiveScorable && positiveTruth
				isBenign := benignTruth(benchmarkCase)
				switch {
				case baseline.Detected == candidate.Detected:
					comparison.SameDetection++
				case baseline.Detected:
					comparison.BaselineOnlyDetections++
					if positiveTruth {
						comparison.PositiveDetectionLosses++
					}
					if isBenign {
						comparison.BenignFindingResolved++
					}
				default:
					comparison.ComparisonOnlyDetections++
					if positiveTruth {
						comparison.PositiveDetectionGains++
					}
					if isBenign {
						comparison.BenignFindingIntroduced++
					}
				}

				baselineRank, baselineRanked := actionRank(baseline.Action)
				comparisonRank, comparisonRanked := actionRank(candidate.Action)
				switch {
				case !baselineRanked || !comparisonRanked || baselineRank == comparisonRank:
					comparison.SameAction++
				case comparisonRank > baselineRank:
					comparison.MoreRestrictiveActions++
				default:
					comparison.LessRestrictiveActions++
				}

				baselineBlocked := baseline.Action == "block"
				comparisonBlocked := candidate.Action == "block"
				if benchmarkCase.Truth.ExpectedDisposition == DispositionBlock {
					if !baselineBlocked && comparisonBlocked {
						comparison.ExpectedBlockGains++
					}
					if baselineBlocked && !comparisonBlocked {
						comparison.ExpectedBlockLosses++
					}
				}
				if isBenign {
					if !baselineBlocked && comparisonBlocked {
						comparison.BenignBlockIntroduced++
					}
					if baselineBlocked && !comparisonBlocked {
						comparison.BenignBlockResolved++
					}
				}
			}
			comparisons = append(comparisons, comparison)
		}
	}
	return comparisons
}

func actionRank(action string) (int, bool) {
	switch action {
	case "allow":
		return 0, true
	case "alert":
		return 1, true
	case "confirm":
		return 2, true
	case "block":
		return 3, true
	default:
		return 0, false
	}
}
