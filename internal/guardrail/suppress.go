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
	"container/list"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// regexCacheMaxEntries bounds the compiled-regex cache. 1024 is far more
// than any realistic rule-pack (default pack has ~12 patterns) but safely
// protects against pathological inputs where an attacker-controlled path
// causes the cache to grow unbounded. On overflow the least-recently-used
// entry is evicted.
const regexCacheMaxEntries = 1024

var (
	regexCacheMu    sync.Mutex
	regexCache      = make(map[string]*list.Element, regexCacheMaxEntries)
	regexCacheOrder = list.New()
)

type regexCacheEntry struct {
	pattern string
	re      *regexp.Regexp // nil means "pattern is invalid; cache the negative result"
}

// compileRegex returns a compiled regex from cache or compiles and caches it.
// Returns nil if the pattern is invalid. Negative results are also cached
// so a pathological pattern can't burn CPU on every request.
func compileRegex(pattern string) *regexp.Regexp {
	regexCacheMu.Lock()
	if el, ok := regexCache[pattern]; ok {
		regexCacheOrder.MoveToFront(el)
		re := el.Value.(*regexCacheEntry).re
		regexCacheMu.Unlock()
		return re
	}
	regexCacheMu.Unlock()

	re, _ := regexp.Compile(pattern)

	regexCacheMu.Lock()
	defer regexCacheMu.Unlock()
	// Double-check after reacquiring the lock to avoid a race adding the
	// same pattern twice.
	if el, ok := regexCache[pattern]; ok {
		regexCacheOrder.MoveToFront(el)
		return el.Value.(*regexCacheEntry).re
	}
	el := regexCacheOrder.PushFront(&regexCacheEntry{pattern: pattern, re: re})
	regexCache[pattern] = el
	for regexCacheOrder.Len() > regexCacheMaxEntries {
		oldest := regexCacheOrder.Back()
		if oldest == nil {
			break
		}
		regexCacheOrder.Remove(oldest)
		entry := oldest.Value.(*regexCacheEntry)
		delete(regexCache, entry.pattern)
	}
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
		if !findingPatternMatches(s.FindingPattern, ent.FindingID) {
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

// findingPatternMatches reports whether the YAML finding_pattern matches the
// runtime finding ID. The YAML surface is advertised as a pattern, so we
// treat it as an anchored regex: operators can write literal IDs like
// "JUDGE-PII-EMAIL" (which match themselves) or wildcards like
// "JUDGE-PII-.*" (which match every JUDGE-PII finding).
//
// Anchoring with \A...\z prevents "JUDGE-PII-EMAIL" from accidentally
// matching "JUDGE-PII-EMAIL-EXTERNAL" and keeps the common literal case
// behaving exactly as operators expect.
//
// A pattern that fails to compile falls back to exact string equality so
// misconfiguration doesn't silently disable the suppression — compileRegex
// also logs the failure once via the rule-pack Validate path.
func findingPatternMatches(pattern, findingID string) bool {
	if pattern == "" {
		return false
	}
	if pattern == findingID {
		return true
	}
	re := compileRegex(`\A(?:` + pattern + `)\z`)
	if re == nil {
		return pattern == findingID
	}
	return re.MatchString(findingID)
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
// ID (Telegram, Slack, etc.) rather than a phone number.
//
// The default policy is: fail-OPEN for real phones. If the value has the
// structure of a valid NANP (US/Canada) phone number, we return false so
// the PII finding is surfaced. Operators who run integrations where bare
// phone-looking strings are known to be platform IDs (e.g. Telegram user
// IDs in channel metadata) can add their own context-specific suppression
// on top.
//
// Previously this heuristic returned true for any 9-12 digit number,
// which silently suppressed legitimate phone numbers like 844-908-8619.
// The NANP structure check below rules out invalid area/exchange codes
// (N11 service codes, leading-1 blocks, etc.).
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

	if IsEpoch(v) {
		return true
	}

	if len(v) == 10 && looksLikeNANPPhone(v) {
		// Real-looking NANP phone number — do NOT suppress by default.
		return false
	}
	if len(v) == 11 && v[0] == '1' && looksLikeNANPPhone(v[1:]) {
		// 1 + 10-digit NANP number (country code prefix).
		return false
	}

	// 9-digit, 12-digit, or a 10/11-digit value whose NANP structure is
	// invalid: treat as a platform ID.
	return true
}

// looksLikeNANPPhone reports whether a 10-digit string has valid
// North-American Numbering Plan structure: NPA (area code) first digit
// 2-9 and not N11, NXX (exchange) first digit 2-9 and not N11.
func looksLikeNANPPhone(v string) bool {
	if len(v) != 10 {
		return false
	}
	return isNANPBlock(v[0:3]) && isNANPBlock(v[3:6])
}

func isNANPBlock(s string) bool {
	if len(s) != 3 {
		return false
	}
	if s[0] < '2' || s[0] > '9' {
		return false
	}
	// N11 service codes (211, 311, 411, 511, 611, 711, 811, 911) are
	// never valid area/exchange codes.
	if s[1] == '1' && s[2] == '1' {
		return false
	}
	return true
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
