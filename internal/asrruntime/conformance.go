package asrruntime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// ConformanceReport records the bounded startup comparison against the
// embedded cross-language vectors.
type ConformanceReport struct {
	Cases      int
	Passed     bool
	Mismatches []string
}

type conformanceVector struct {
	Name       string               `json:"name"`
	Invocation NormalizedInvocation `json:"invocation"`
	Expected   expectedResult       `json:"expect"`
}

type expectedResult struct {
	Status    Status          `json:"status"`
	Issues    []string        `json:"issues"`
	Semantics json.RawMessage `json:"semantics"`
}

type conformanceDocument struct {
	SchemaVersion string              `json:"schema_version"`
	Cases         []conformanceVector `json:"cases"`
}

func runConformance(runtime *Runtime, vectors []conformanceVector) ConformanceReport {
	report := ConformanceReport{Cases: len(vectors), Passed: len(vectors) != 0}
	for _, vector := range vectors {
		result := runtime.Evaluate(vector.Invocation)
		if result.Status != vector.Expected.Status {
			report.Passed = false
			report.Mismatches = append(
				report.Mismatches,
				evaluatorIssue(vector.Name, result.Status, vector.Expected.Status),
			)
		}
		if !equalStrings(result.Issues, vector.Expected.Issues) {
			report.Passed = false
			report.Mismatches = append(
				report.Mismatches,
				fmt.Sprintf(
					"%s: issues %v, want %v",
					vector.Name,
					result.Issues,
					vector.Expected.Issues,
				),
			)
		}
		if len(vector.Expected.Semantics) != 0 &&
			!canonicalSemanticsEqual(result.Semantics, vector.Expected.Semantics) {
			report.Passed = false
			report.Mismatches = append(
				report.Mismatches,
				fmt.Sprintf("%s: canonical semantics mismatch", vector.Name),
			)
		}
	}
	sort.Strings(report.Mismatches)
	return report
}

func canonicalSemanticsEqual(actual, expected json.RawMessage) bool {
	actualCanonical, actualErr := canonicalJSON(actual)
	expectedCanonical, expectedErr := canonicalJSON(expected)
	return actualErr == nil && expectedErr == nil && bytes.Equal(actualCanonical, expectedCanonical)
}

func canonicalJSON(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	var canonical bytes.Buffer
	encoder := json.NewEncoder(&canonical)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(canonical.Bytes(), []byte{'\n'}), nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
