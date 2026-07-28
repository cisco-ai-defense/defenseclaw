// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

type detectorCorpus struct {
	CatalogVersion             int                  `json:"catalog_version"`
	RequiredCategories         []string             `json:"required_categories"`
	GeneratedFromPositive      []string             `json:"generated_from_positive"`
	RequiredMultilineDetectors []DetectorID         `json:"required_multiline_detectors"`
	Cases                      []detectorCorpusCase `json:"cases"`
}

type detectorCorpusCase struct {
	Name     string        `json:"name"`
	Detector DetectorID    `json:"detector"`
	Group    DetectorGroup `json:"group"`
	Category string        `json:"category"`
	Input    string        `json:"input"`
	Match    string        `json:"match"`
}

func TestDetectorV1SyntheticCorpus(t *testing.T) {
	t.Parallel()
	corpus := loadDetectorCorpus(t)
	if corpus.CatalogVersion != DetectorCatalogVersion() {
		t.Fatal("corpus catalog version drift")
	}
	coverage := map[DetectorID]map[string]bool{}
	key := []byte("0123456789abcdef0123456789abcdef")
	for _, fixture := range corpus.Cases {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			result, err := DetectAndRedact(fixture.Input, observability.FieldClassContent, []DetectorGroup{fixture.Group}, key, NewRecordMatchBudget())
			if fixture.Match == "" {
				if err != nil {
					t.Fatalf("negative fixture failed closed instead of being rejected: %v", err)
				}
				for _, match := range result.Matches {
					if match.ID == fixture.Detector {
						t.Fatalf("near miss accepted by %s at [%d,%d)", match.ID, match.Start, match.End)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, match := range result.Matches {
				if match.ID != fixture.Detector {
					continue
				}
				found = true
				if got := fixture.Input[match.Start:match.End]; got != fixture.Match {
					t.Fatalf("original-byte interval: got %q, want %q", got, fixture.Match)
				}
				if strings.Contains(result.Value, fixture.Match) {
					t.Fatal("output retained matched bytes")
				}
			}
			if !found {
				t.Fatalf("expected detector %q; matches: %+v", fixture.Detector, result.Matches)
			}
		})
		if coverage[fixture.Detector] == nil {
			coverage[fixture.Detector] = map[string]bool{}
		}
		coverage[fixture.Detector][fixture.Category] = true
	}
	for _, entry := range DetectorCatalog() {
		if !coverage[entry.ID]["positive"] || !coverage[entry.ID]["near_miss"] {
			t.Fatalf("detector %q lacks positive/near-miss synthetic coverage", entry.ID)
		}
	}
}

func TestEveryDetectorBoundaryUnicodeOverlapAndOversizeProperties(t *testing.T) {
	t.Parallel()
	corpus := loadDetectorCorpus(t)
	positive := map[DetectorID]detectorCorpusCase{}
	nearMiss := map[DetectorID]detectorCorpusCase{}
	for _, fixture := range corpus.Cases {
		if fixture.Category == "positive" {
			positive[fixture.Detector] = fixture
		} else if fixture.Category == "near_miss" {
			nearMiss[fixture.Detector] = fixture
		}
	}
	wantGenerated := []string{"boundary", "unicode_adjacent", "oversized", "overlap"}
	if strings.Join(corpus.GeneratedFromPositive, ",") != strings.Join(wantGenerated, ",") {
		t.Fatalf("generated category contract drift: got %v, want %v", corpus.GeneratedFromPositive, wantGenerated)
	}
	multilineRequired := map[DetectorID]bool{}
	for _, id := range corpus.RequiredMultilineDetectors {
		multilineRequired[id] = true
	}
	coverage := map[DetectorID]map[string]bool{}
	key := make([]byte, 32)
	for _, entry := range DetectorCatalog() {
		entry := entry
		fixture := positive[entry.ID]
		t.Run(string(entry.ID), func(t *testing.T) {
			coverage[entry.ID] = map[string]bool{}
			if fixture.Detector == "" || nearMiss[entry.ID].Detector == "" {
				t.Fatal("missing positive or near-miss fixture")
			}

			baseResult, err := DetectAndRedact(fixture.Input, observability.FieldClassContent, []DetectorGroup{fixture.Group}, key, NewRecordMatchBudget())
			if err != nil {
				t.Fatal(err)
			}
			assertDetectorCoversInterval(t, baseResult, entry.ID, fixture.Input, strings.Index(fixture.Input, fixture.Match), fixture.Match)
			coverage[entry.ID]["positive"] = true

			miss := nearMiss[entry.ID]
			missResult, missErr := DetectAndRedact(miss.Input, observability.FieldClassContent, []DetectorGroup{miss.Group}, key, NewRecordMatchBudget())
			if missErr != nil {
				t.Fatalf("semantic near miss failed closed: %v", missErr)
			}
			for _, match := range missResult.Matches {
				if match.ID == entry.ID {
					t.Fatalf("near miss accepted at [%d,%d)", match.Start, match.End)
				}
			}
			coverage[entry.ID]["near_miss"] = true

			lineOriented := entry.ID == "credentials.private_key" || entry.ID == "credentials.authorization" || entry.ID == "credentials.cookie"
			asciiPrefix, asciiSuffix := "prefix ", " suffix"
			if lineOriented {
				asciiPrefix, asciiSuffix = "prefix\n", "\nsuffix"
			}
			boundaryInput := asciiPrefix + fixture.Input + asciiSuffix
			boundaryResult, boundaryErr := DetectAndRedact(boundaryInput, observability.FieldClassContent, []DetectorGroup{fixture.Group}, key, NewRecordMatchBudget())
			if boundaryErr != nil {
				t.Fatal(boundaryErr)
			}
			wantStart := len(asciiPrefix) + strings.Index(fixture.Input, fixture.Match)
			assertDetectorCoversInterval(t, boundaryResult, entry.ID, boundaryInput, wantStart, fixture.Match)
			coverage[entry.ID]["boundary"] = true

			// Multibyte adjacency proves intervals are original UTF-8 byte offsets,
			// never rune indices or offsets into semantic-decoded values.
			unicodePrefix, unicodeSuffix := "π ", " ß"
			if lineOriented {
				unicodePrefix, unicodeSuffix = "π\n", "\nß"
			}
			unicodeInput := unicodePrefix + fixture.Input + unicodeSuffix
			unicodeResult, unicodeErr := DetectAndRedact(unicodeInput, observability.FieldClassContent, []DetectorGroup{fixture.Group}, key, NewRecordMatchBudget())
			if unicodeErr != nil {
				t.Fatal(unicodeErr)
			}
			wantStart = len(unicodePrefix) + strings.Index(fixture.Input, fixture.Match)
			assertDetectorCoversInterval(t, unicodeResult, entry.ID, unicodeInput, wantStart, fixture.Match)
			coverage[entry.ID]["unicode_adjacent"] = true

			// The fixed field oversize rule applies before every selected detector;
			// no recognizer gets a prefix or suffix from an oversized string.
			oversize := fixture.Input + strings.Repeat("x", MaxScannedStringBytes+1-len(fixture.Input))
			oversizeResult, err := DetectAndRedact(oversize, observability.FieldClassContent, []DetectorGroup{fixture.Group}, key, NewRecordMatchBudget())
			if err != nil || !oversizeResult.Oversize || oversizeResult.LexicalCandidates != 0 || strings.Contains(oversizeResult.Value, fixture.Match) {
				t.Fatalf("oversize handling: %+v, %v", oversizeResult, err)
			}
			coverage[entry.ID]["oversized"] = true

			// Each identity participates in deterministic overlap ordering. A
			// catalog match unioned with a lower-priority tail must cover the tail.
			definition, _ := catalogDefinitionFor(entry.ID)
			primary := acceptedMatch{start: 2, end: 8, id: entry.ID, group: entry.Group, order: entry.Order}
			secondary := acceptedMatch{start: 7, end: 11, id: "pii.ip_address", group: DetectorGroupPII, order: 14}
			if entry.Group == DetectorGroupPII {
				secondary = acceptedMatch{start: 7, end: 11, id: entry.ID, group: entry.Group, order: definition.order}
			}
			clusters := clusterMatches([]acceptedMatch{primary, secondary})
			if len(clusters) != 1 || clusters[0].start != 2 || clusters[0].end != 11 {
				t.Fatalf("overlap union leaked tail: %+v", clusters)
			}
			coverage[entry.ID]["overlap"] = true

			if multilineRequired[entry.ID] {
				multilineInput := "safe-before\n" + fixture.Input + "\nsafe-after"
				multilineResult, multilineErr := DetectAndRedact(multilineInput, observability.FieldClassContent, []DetectorGroup{fixture.Group}, key, NewRecordMatchBudget())
				if multilineErr != nil {
					t.Fatal(multilineErr)
				}
				wantStart = len("safe-before\n") + strings.Index(fixture.Input, fixture.Match)
				assertDetectorCoversInterval(t, multilineResult, entry.ID, multilineInput, wantStart, fixture.Match)
				coverage[entry.ID]["multiline"] = true
			}
		})
	}
	for _, entry := range DetectorCatalog() {
		for _, category := range corpus.RequiredCategories {
			if !coverage[entry.ID][category] {
				t.Fatalf("detector %q lacks executed %q coverage", entry.ID, category)
			}
		}
		if multilineRequired[entry.ID] && !coverage[entry.ID]["multiline"] {
			t.Fatalf("line-oriented detector %q lacks executed multiline coverage", entry.ID)
		}
	}
}

func assertDetectorCoversInterval(t *testing.T, result DetectionResult, id DetectorID, input string, start int, expected string) {
	t.Helper()
	for _, match := range result.Matches {
		if match.ID == id && match.Start <= start && match.End >= start+len(expected) {
			if match.Start < 0 || match.End > len(input) {
				t.Fatal("detector produced an out-of-bounds interval")
			}
			return
		}
	}
	t.Fatalf("detector %q did not cover expected interval [%d,%d): %+v", id, start, start+len(expected), result.Matches)
}

func TestOverlapUnionPriorityAndAdjacency(t *testing.T) {
	t.Parallel()
	matches := []acceptedMatch{
		{start: 0, end: 4, id: "pii.email", group: DetectorGroupPII, order: 10},
		{start: 3, end: 8, id: "secrets.assignment", group: DetectorGroupSecrets, order: 6},
		{start: 7, end: 10, id: "credentials.authorization", group: DetectorGroupCredentials, order: 3},
		{start: 10, end: 12, id: "pii.ip_address", group: DetectorGroupPII, order: 14},
	}
	clusters := clusterMatches(matches)
	if len(clusters) != 2 || clusters[0].start != 0 || clusters[0].end != 10 || clusters[0].id != "credentials.authorization" || clusters[1].start != 10 {
		t.Fatalf("unexpected clusters: %+v", clusters)
	}
	input := "ABCDEFGHIJKL"
	token, err := DetectedToken(clusters[0].id, input[clusters[0].start:clusters[0].end], make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	output := token + input[clusters[0].end:]
	for _, forbidden := range []string{"ABCD", "DEFGH", "HIJ"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("transitive overlap exposed raw tail %q", forbidden)
		}
	}
}

func TestEveryDetectorRegexSourceCompilesUnderGoRE2(t *testing.T) {
	t.Parallel()
	sources := map[string]*regexp.Regexp{
		"provider_token_v1":       providerTokenRE,
		"authorization_header_v1": authorizationRE,
		"assignment_key_v1":       assignmentKeyRE,
		"dsn_key_v1":              dsnKeyRE,
		"entropy_ascii_v1":        entropyRE,
		"absolute_uri_v1":         uriRE,
		"cloud_label_v1":          cloudLabelRE,
		"aws_arn_v1":              arnRE,
		"azure_resource_v1":       azurePathRE,
		"gcp_resource_v1":         gcpPathRE,
		"gcp_service_account_v1":  gcpServiceRE,
		"email_ascii_v1":          emailRE,
		"nanp_telephone_v1":       telephoneRE,
		"us_ssn_v1":               nationalIDRE,
	}
	if len(sources) != 14 {
		t.Fatalf("regex source inventory drift: got %d, want 14", len(sources))
	}
	for name, compiled := range sources {
		if compiled == nil || compiled.String() == "" {
			t.Fatalf("%s has no regex source", name)
		}
		if _, err := regexp.Compile(compiled.String()); err != nil {
			t.Fatalf("%s is not Go RE2-compatible: %v", name, err)
		}
		for _, forbidden := range []string{"(?=", "(?!", "(?<=", "(?<!", "\\1", "(?R"} {
			if strings.Contains(compiled.String(), forbidden) {
				t.Fatalf("%s contains forbidden non-RE2 construct %q", name, forbidden)
			}
		}
	}
}

func TestDetectorFixedWorkLimitsAtBoundary(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	class := observability.FieldClassContent

	rejectedToken := "XAKIAAAAAAAAAAAAAAAAA"
	exactCandidates := strings.Repeat(rejectedToken+" ", MaxFieldCandidates)
	result, err := DetectAndRedact(exactCandidates, class, []DetectorGroup{DetectorGroupCredentials}, key, NewRecordMatchBudget())
	if err != nil || result.LexicalCandidates != MaxFieldCandidates || result.Value != exactCandidates {
		t.Fatalf("exact candidate bound: candidates=%d err=%v", result.LexicalCandidates, err)
	}
	overCandidates := exactCandidates + rejectedToken
	result, err = DetectAndRedact(overCandidates, class, []DetectorGroup{DetectorGroupCredentials}, key, NewRecordMatchBudget())
	if !IsDetectorError(err, FailureCandidateLimit) || result.Failure != FailureCandidateLimit || strings.Contains(result.Value, "AKIA") {
		t.Fatalf("candidate exhaustion: %+v, %v", result, err)
	}

	email := "fixture@example.test"
	exactMatches := strings.TrimSpace(strings.Repeat(email+" ", MaxFieldMatches))
	result, err = DetectAndRedact(exactMatches, class, []DetectorGroup{DetectorGroupPII}, key, NewRecordMatchBudget())
	if err != nil || result.AcceptedMatches != MaxFieldMatches {
		t.Fatalf("exact match bound: matches=%d err=%v", result.AcceptedMatches, err)
	}
	overMatches := exactMatches + " " + email
	result, err = DetectAndRedact(overMatches, class, []DetectorGroup{DetectorGroupPII}, key, NewRecordMatchBudget())
	if !IsDetectorError(err, FailureFieldMatchLimit) || strings.Contains(result.Value, email) {
		t.Fatalf("field match exhaustion: %+v, %v", result, err)
	}

	budget := NewRecordMatchBudget()
	for index := 0; index < MaxRecordMatches/MaxFieldMatches; index++ {
		if _, err := DetectAndRedact(exactMatches, class, []DetectorGroup{DetectorGroupPII}, key, budget); err != nil {
			t.Fatalf("record exact bound field %d: %v", index, err)
		}
	}
	if budget.Accepted() != MaxRecordMatches {
		t.Fatalf("record accepted=%d, want %d", budget.Accepted(), MaxRecordMatches)
	}
	result, err = DetectAndRedact(email, class, []DetectorGroup{DetectorGroupPII}, key, budget)
	if !IsDetectorError(err, FailureRecordMatchLimit) || strings.Contains(result.Value, email) {
		t.Fatalf("record match exhaustion: %+v, %v", result, err)
	}

	exactScan := strings.Repeat("x", MaxScannedStringBytes-len(email)-1) + " " + email
	result, err = DetectAndRedact(exactScan, class, []DetectorGroup{DetectorGroupPII}, key, NewRecordMatchBudget())
	if err != nil || result.Oversize {
		t.Fatalf("exact scan bound: %+v, %v", result, err)
	}
	overScan := exactScan + "x"
	result, err = DetectAndRedact(overScan, class, []DetectorGroup{DetectorGroupPII}, key, NewRecordMatchBudget())
	if err != nil || !result.Oversize || strings.Contains(result.Value, email) {
		t.Fatalf("oversize scan bound: %+v, %v", result, err)
	}
}

func TestMalformedSensitiveURIAndInvalidUTF8FailWholeFieldClosed(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	malformed := "before https://example.test/?token=reserved%zz after"
	result, err := DetectAndRedact(malformed, observability.FieldClassContent, []DetectorGroup{DetectorGroupSecrets}, key, NewRecordMatchBudget())
	if !IsDetectorError(err, FailureValidator) || strings.Contains(result.Value, "reserved") || result.Value[0] != '<' {
		t.Fatalf("malformed URI: %+v, %v", result, err)
	}
	invalid := string([]byte{'a', 0xff, 'b'})
	if utf8.ValidString(invalid) {
		t.Fatal("test input unexpectedly valid")
	}
	result, err = DetectAndRedact(invalid, observability.FieldClassContent, []DetectorGroup{DetectorGroupPII}, key, NewRecordMatchBudget())
	if !IsDetectorError(err, FailureInvalidUTF8) || result.Value != "<redacted type=failed_closed v=1 code=invalid_utf8>" {
		t.Fatalf("invalid UTF-8: %+v, %v", result, err)
	}
}

func TestDetectorResultAndErrorsNeverAliasOrEchoInput(t *testing.T) {
	t.Parallel()
	input := "alice@example.test"
	result, err := DetectAndRedact(input, observability.FieldClassContent, []DetectorGroup{DetectorGroupPII}, make([]byte, 32), NewRecordMatchBudget())
	if err != nil {
		t.Fatal(err)
	}
	copyOfMatches := append([]Match(nil), result.Matches...)
	result.Matches[0].ID = "changed"
	if copyOfMatches[0].ID != "pii.email" {
		t.Fatal("test setup did not capture expected match")
	}
	_, err = DetectAndRedact(input, observability.FieldClassContent, []DetectorGroup{DetectorGroupPII}, []byte("reserved-short-key"), NewRecordMatchBudget())
	if !IsDetectorError(err, FailureKeyUnavailable) || strings.Contains(err.Error(), input) || strings.Contains(err.Error(), "reserved-short-key") {
		t.Fatalf("unsafe error: %v", err)
	}
}

func loadDetectorCorpus(t *testing.T) detectorCorpus {
	t.Helper()
	encoded, err := os.ReadFile("testdata/detector_v1_corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus detectorCorpus
	if err := json.Unmarshal(encoded, &corpus); err != nil {
		t.Fatal(err)
	}
	return corpus
}
