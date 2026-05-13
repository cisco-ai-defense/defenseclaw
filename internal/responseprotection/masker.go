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

// Package responseprotection masks and caps tool responses before they are
// returned to an agent. It adapts AIMS' response-filtering pattern with an
// opt-in configuration suitable for DefenseClaw hook responses.
package responseprotection

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Config controls response protection behavior.
type Config struct {
	PIIFields    []string
	MaxRows      int
	MaxBytes     int
	CanaryRate   float64
	CanaryPrefix string
}

func DefaultConfig() Config {
	return Config{PIIFields: []string{"email", "phone", "ssn", "salary", "dob", "address", "national_id"}, MaxRows: 500, MaxBytes: 1 << 20, CanaryPrefix: "DEFENSECLAW-CANARY"}
}

// Result describes the applied response transformations.
type Result struct {
	Body           []byte   `json:"-"`
	Truncated      bool     `json:"truncated"`
	FieldsMasked   []string `json:"fields_masked,omitempty"`
	CanaryInjected bool     `json:"canary_injected,omitempty"`
	RowsReturned   int      `json:"rows_returned,omitempty"`
	BytesReturned  int      `json:"bytes_returned"`
}

// Masker applies configured protections.
type Masker struct {
	cfg          Config
	fieldLookup  map[string]string
	jsonFieldREs map[string]*regexp.Regexp
}

func New(cfg Config) *Masker {
	if cfg.CanaryPrefix == "" {
		cfg.CanaryPrefix = "DEFENSECLAW-CANARY"
	}
	lookup := map[string]string{}
	regexes := map[string]*regexp.Regexp{}
	for _, field := range cfg.PIIFields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		lookup[strings.ToLower(field)] = field
		regexes[field] = regexp.MustCompile(fmt.Sprintf(`(?i)("%s"\s*:\s*")[^"]*(")`, regexp.QuoteMeta(field)))
	}
	return &Masker{cfg: cfg, fieldLookup: lookup, jsonFieldREs: regexes}
}

// Mask transforms the body and returns evidence about applied controls.
func (m *Masker) Mask(body []byte, agentID string) Result {
	if m == nil {
		return Result{Body: body, BytesReturned: len(body)}
	}
	var parsed any
	if err := json.Unmarshal(body, &parsed); err == nil {
		masked := map[string]struct{}{}
		parsed, _ = m.maskValue(parsed, masked)
		parsed, rows, truncatedRows := m.truncateRows(parsed)
		result := Result{RowsReturned: rows, Truncated: truncatedRows}
		if m.cfg.CanaryRate >= 1 {
			parsed, result.CanaryInjected = injectCanary(parsed, agentID, m.cfg.CanaryPrefix)
		}
		out, err := json.Marshal(parsed)
		if err == nil {
			body = out
		}
		result.FieldsMasked = sortedKeys(masked)
		if m.cfg.MaxBytes > 0 && len(body) > m.cfg.MaxBytes {
			body = body[:m.cfg.MaxBytes]
			result.Truncated = true
		}
		result.Body = body
		result.BytesReturned = len(body)
		return result
	}
	return m.maskText(body)
}

func (m *Masker) maskValue(v any, masked map[string]struct{}) (any, int) {
	switch x := v.(type) {
	case map[string]any:
		rows := 0
		for k, val := range x {
			canonical, isPII := m.fieldLookup[strings.ToLower(k)]
			if isPII && val != nil {
				x[k] = maskedToken(canonical, fmt.Sprint(val))
				masked[canonical] = struct{}{}
				continue
			}
			var childRows int
			x[k], childRows = m.maskValue(val, masked)
			rows += childRows
		}
		return x, rows
	case []any:
		rows := len(x)
		for i, val := range x {
			x[i], _ = m.maskValue(val, masked)
		}
		return x, rows
	default:
		return v, 0
	}
}

func (m *Masker) truncateRows(v any) (any, int, bool) {
	if m.cfg.MaxRows <= 0 {
		return v, countRows(v), false
	}
	switch x := v.(type) {
	case []any:
		if len(x) > m.cfg.MaxRows {
			return x[:m.cfg.MaxRows], m.cfg.MaxRows, true
		}
		return x, len(x), false
	case map[string]any:
		for _, key := range []string{"data", "rows", "results", "items", "records"} {
			if arr, ok := x[key].([]any); ok {
				if len(arr) > m.cfg.MaxRows {
					x[key] = arr[:m.cfg.MaxRows]
					return x, m.cfg.MaxRows, true
				}
				return x, len(arr), false
			}
		}
	}
	return v, countRows(v), false
}

func (m *Masker) maskText(body []byte) Result {
	text := string(body)
	masked := map[string]struct{}{}
	for field, re := range m.jsonFieldREs {
		if re.MatchString(text) {
			masked[field] = struct{}{}
			text = re.ReplaceAllString(text, `${1}[MASKED]${2}`)
		}
	}
	out := []byte(text)
	result := Result{Body: out, FieldsMasked: sortedKeys(masked), BytesReturned: len(out)}
	if m.cfg.MaxBytes > 0 && len(out) > m.cfg.MaxBytes {
		result.Body = out[:m.cfg.MaxBytes]
		result.Truncated = true
		result.BytesReturned = len(result.Body)
	}
	return result
}

func countRows(v any) int {
	switch x := v.(type) {
	case []any:
		return len(x)
	case map[string]any:
		for _, key := range []string{"data", "rows", "results", "items", "records"} {
			if arr, ok := x[key].([]any); ok {
				return len(arr)
			}
		}
	}
	return 0
}

func injectCanary(v any, agentID, prefix string) (any, bool) {
	canary := canaryRecord(agentID, prefix)
	switch x := v.(type) {
	case []any:
		return append([]any{canary}, x...), true
	case map[string]any:
		for _, key := range []string{"data", "rows", "results", "items", "records"} {
			if arr, ok := x[key].([]any); ok {
				x[key] = append([]any{canary}, arr...)
				return x, true
			}
		}
	}
	return v, false
}

func canaryRecord(agentID, prefix string) map[string]any {
	h := sha256.Sum256([]byte(agentID + ":" + prefix))
	id := fmt.Sprintf("%s-%x", prefix, h[:6])
	return map[string]any{"id": id, "email": id + "@canary.defenseclaw.local", "_defenseclaw_canary": true, "_agent": agentID}
}

func maskedToken(field, value string) string {
	h := sha256.Sum256([]byte(value))
	return fmt.Sprintf("[%s:sha256:%x]", strings.ToUpper(field), h[:4])
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
