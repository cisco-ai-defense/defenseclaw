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

package guardrail

import (
	"regexp"
	"strconv"
	"strings"
	"sync"
)

var (
	regexCacheMu sync.RWMutex
	regexCache   = make(map[string]*regexp.Regexp)
)

// compileRegex returns a compiled regex from cache or compiles and caches it.
// Returns nil if the pattern is invalid.
func compileRegex(pattern string) *regexp.Regexp {
	regexCacheMu.RLock()
	if re, ok := regexCache[pattern]; ok {
		regexCacheMu.RUnlock()
		return re
	}
	regexCacheMu.RUnlock()

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}

	regexCacheMu.Lock()
	regexCache[pattern] = re
	regexCacheMu.Unlock()
	return re
}

// PIIEntity represents a single PII entity detected by the judge.
type PIIEntity struct {
	Category  string
	FindingID string
	Entity    string
	Severity  string
}

// SuppressedEntity records why an entity was suppressed.
type SuppressedEntity struct {
	PIIEntity
	SuppressionID string
	Reason        string
}

// PreJudgeStripContent applies all pre-judge strip rules to the content
// before it is sent to the LLM judge. Returns the stripped content.
func PreJudgeStripContent(content string, strips []PreJudgeStrip, judgeType string) string {
	if len(strips) == 0 {
		return content
	}
	result := content
	for _, strip := range strips {
		if !stripApplies(strip, judgeType) {
			continue
		}
		re := compileRegex(strip.Pattern)
		if re == nil {
			continue
		}
		result = re.ReplaceAllString(result, "")
	}
	return result
}

func stripApplies(strip PreJudgeStrip, judgeType string) bool {
	if len(strip.AppliesTo) == 0 {
		return true
	}
	for _, t := range strip.AppliesTo {
		if t == judgeType {
			return true
		}
	}
	return false
}

// FilterPIIEntities applies finding suppressions and returns kept and
// suppressed entities separately.
func FilterPIIEntities(entities []PIIEntity, supps []FindingSuppression) (kept []PIIEntity, suppressed []SuppressedEntity) {
	for _, ent := range entities {
		if sid, reason := matchSuppression(ent, supps); sid != "" {
			suppressed = append(suppressed, SuppressedEntity{
				PIIEntity:     ent,
				SuppressionID: sid,
				Reason:        reason,
			})
			continue
		}
		kept = append(kept, ent)
	}
	return
}

func matchSuppression(ent PIIEntity, supps []FindingSuppression) (id, reason string) {
	for _, s := range supps {
		if s.FindingPattern != ent.FindingID {
			continue
		}
		re := compileRegex(s.EntityPattern)
		if re == nil {
			continue
		}
		if !re.MatchString(ent.Entity) {
			continue
		}
		if s.Condition != "" && !checkCondition(s.Condition, ent.Entity) {
			continue
		}
		return s.ID, s.Reason
	}
	return "", ""
}

func checkCondition(condition, value string) bool {
	switch condition {
	case "is_epoch":
		return IsEpoch(value)
	case "is_platform_id":
		return IsPlatformID(value)
	default:
		return false
	}
}

// IsEpoch returns true if value is a plausible Unix timestamp
// (between 2001-09-09 and ~2036-07-18).
func IsEpoch(value string) bool {
	n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return false
	}
	return n >= 1_000_000_000 && n <= 2_100_000_000
}

// IsPlatformID returns true if value looks like a channel platform numeric
// ID (Telegram, Slack, etc.) rather than a phone number. Heuristic: a bare
// 9-12 digit number that does NOT have formatted phone structure.
func IsPlatformID(value string) bool {
	v := strings.TrimSpace(value)
	if len(v) < 9 || len(v) > 12 {
		return false
	}
	for _, c := range v {
		if c < '0' || c > '9' {
			return false
		}
	}

	// If it looks like a valid epoch, it's definitely not a phone number.
	if IsEpoch(v) {
		return true
	}

	// Telegram IDs are typically large numbers. We treat any purely-numeric
	// 9-12 digit string without standard phone formatting as a platform ID
	// candidate. The key insight: the PII judge already decided it's a
	// phone number; our job is to un-decide that when the entity came from
	// channel metadata context rather than user-visible content.
	// A 10-digit number matching US phone pattern (NXX-NXX-XXXX where N>1)
	// is more likely a real phone number.
	if len(v) == 10 {
		d0 := v[0]
		d3 := v[3]
		if d0 >= '2' && d3 >= '2' {
			// Looks like a valid US phone: area code starts >=2, exchange starts >=2.
			// Suppress anyway — in the context of channel metadata, these are
			// almost always platform IDs, not phone numbers. The user can
			// remove this suppression rule if they need phone detection in
			// channel metadata.
			return true
		}
	}

	return len(v) >= 9
}

// FilterToolFindings applies tool-specific suppressions.
func FilterToolFindings(toolName string, entities []PIIEntity, supps []ToolSuppression) (kept []PIIEntity, suppressed []SuppressedEntity) {
	suppressSet := make(map[string]string)
	for _, ts := range supps {
		re := compileRegex(ts.ToolPattern)
		if re == nil {
			continue
		}
		if re.MatchString(toolName) {
			for _, fid := range ts.SuppressFindings {
				suppressSet[fid] = ts.Reason
			}
		}
	}

	if len(suppressSet) == 0 {
		return entities, nil
	}

	for _, ent := range entities {
		if reason, ok := suppressSet[ent.FindingID]; ok {
			suppressed = append(suppressed, SuppressedEntity{
				PIIEntity:     ent,
				SuppressionID: "tool:" + toolName,
				Reason:        reason,
			})
			continue
		}
		kept = append(kept, ent)
	}
	return
}
