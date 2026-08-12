// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"regexp"
	"slices"
	"strings"
)

const trustedPromptLiteralCategory = "trust-exploit"

type trustedPromptLiteralDetectionOnlyContract struct {
	pattern    string
	title      string
	severity   string
	confidence float64
	tags       []string
}

// trustedPromptLiteralDetectionOnly is deliberately code-owned and separate
// from both rule-pack metadata and the ActionFacts command-owner allowlist.
// Only these exact shipped prompt rules may turn a weak literal match into
// detection-only telemetry. Operator rules that reuse an ID, aliases, and
// mutated catalog entries retain their configured enforcement.
var trustedPromptLiteralDetectionOnly = map[string]trustedPromptLiteralDetectionOnlyContract{
	"TRUST-PROMPT-EXTRACT": {
		pattern: `(?i)(?:show|reveal|print|output|display|repeat|tell\s+me)\s+(?:me\s+)?(?:your\s+)?(?:the\s+)?(?:(?:system|initial|hidden|private|internal)\s+)?(?:prompt|instructions?|rules?|guidelines?)`,
		title:   "System prompt extraction attempt", severity: "MEDIUM", confidence: 0.75,
		tags: []string{"prompt-injection"},
	},
	"TRUST-FICTIONAL": {
		pattern: `(?i)(?:hypothetically|in\s+a\s+fictional\s+(?:scenario|world|story)|for\s+(?:educational|research|academic)\s+purposes?\s+only|this\s+is\s+just\s+a\s+(?:test|experiment|hypothetical))`,
		title:   "Fictional framing / purpose laundering", severity: "MEDIUM", confidence: 0.70,
		tags: []string{"prompt-injection"},
	},
	"TRUST-DELIMITER": {
		pattern: `(?im)(?:\[INST\][\s\S]{0,200}\b(?:override|ignore|disable|bypass|reveal|expose|unfiltered|unrestricted|new\s+(?:instructions?|rules?|system\s+prompt)|follow\s+(?:my|these|the)\s+instructions?|do\s+evil)\b[\s\S]{0,200}\[\/INST\]|<\|im_start\|>[\s\S]{0,200}\b(?:no\s+restrictions?|override|ignore|disable|bypass|reveal|expose|unfiltered|unrestricted|new\s+(?:instructions?|rules?|system\s+prompt)|follow\s+(?:my|these|the)\s+instructions?|do\s+evil)\b[\s\S]{0,200}<\|im_end\|>|(?:system\s+override|end\s+system\s+prompt|<\/system>|<\|im_end\|>|<\|endoftext\|>|<<\s*SYS\s*>>|\[INST\]|\[\/INST\])[\s\S]{0,120}\b(?:override|ignore|disable|bypass|reveal|expose|unfiltered|unrestricted|new\s+(?:instructions?|rules?|system\s+prompt)|follow\s+(?:my|these|the)\s+instructions?|do\s+evil)\b)`,
		title:   "Delimiter hijacking / prompt framing escape", severity: "CRITICAL", confidence: 0.93,
		tags: []string{"prompt-injection"},
	},
}

// protectedPromptExtractionPattern separates a request for the model's own
// protected control text from ordinary developer requests to show project
// instructions, rules, or guidelines. The broad catalog regex still records
// the latter, but they remain LOW detection-only telemetry.
var protectedPromptExtractionPattern = regexp.MustCompile(
	`(?i)\b(?:show|reveal|print|output|display|repeat|tell\s+me)\s+` +
		`(?:me\s+)?(?:` +
		`your\s+(?:(?:system|initial|hidden|private|internal)\s+)?(?:prompt|instructions?|rules?|guidelines?)` +
		`|(?:the\s+)?(?:system|initial|hidden)\s+(?:prompt|instructions?|rules?|guidelines?)` +
		`|(?:the\s+)?(?:private|internal)\s+(?:prompt|instructions?)` +
		`)\b`,
)

var fictionalFramingPattern = regexp.MustCompile(
	`(?i)(?:hypothetically|in\s+a\s+fictional\s+(?:scenario|world|story)|` +
		`for\s+(?:educational|research|academic)\s+purposes?\s+only|` +
		`this\s+is\s+just\s+a\s+(?:test|experiment|hypothetical))`,
)

// fictionalAdversarialControlPattern intentionally recognizes only direct
// assistant-control language. A fictional premise near an ordinary coding,
// writing, or research question is not itself an attack. Harmful-domain
// classification remains owned by the configured judge/AID lanes.
var fictionalAdversarialControlPattern = regexp.MustCompile(
	`(?im)(?:^|[.!?;,:]\s*|^\s*[-*>]\s*)` +
		`(?:(?:please|now|next)\s+)?(?:` +
		`(?:ignore|disregard)\s+(?:all\s+)?(?:(?:previous|prior|above|earlier)\s+` +
		`(?:instructions?|rules?|guidelines?|context)|everything(?:\s+(?:above|before))?)` +
		`|(?:override|bypass|disable|turn\s+off|remove)\s+(?:all\s+|your\s+|the\s+)?` +
		`(?:safety(?:\s+(?:rules?|checks?|filters?|restrictions?))?|guardrails?|filters?|restrictions?|` +
		`system\s+prompt|instructions?|rules?)` +
		`|(?:reveal|expose)\s+(?:your\s+|the\s+)?(?:system|initial|hidden|private|internal)\s+` +
		`(?:prompt|instructions?|rules?|guidelines?|secrets?)` +
		`|you\s+(?:are|will|must|should)\s+(?:now\s+)?(?:unfiltered|unrestricted|uncensored)` +
		`|(?:respond|answer|operate|act)\s+(?:with\s+)?(?:no|without(?:\s+any)?)\s+` +
		`(?:rules?|restrictions?|filters?|safety|ethical\s+constraints?|moral\s+constraints?)` +
		`|do\s+anything(?:\s+now)?` +
		`)\b`,
)

var delimiterControlTokenPattern = regexp.MustCompile(
	`(?i)(?:system\s+override|end\s+system\s+prompt|</system>|<\|im_start\|>|<\|im_end\|>|` +
		`<\|endoftext\|>|<<\s*SYS\s*>>|\[INST\]|\[/INST\])`,
)

// delimiterAttackPayloadPattern is anchored immediately after a model-control
// delimiter. It replaces the old bare-keyword implication (for example,
// "delimiter ... reveal") with explicit control objects and imperative
// grammar. This keeps parser/test prose observable without making it a
// universal CRITICAL action.
var delimiterAttackPayloadPattern = regexp.MustCompile(
	`(?is)^\s*(?:(?:[.:;,-]\s*)|(?:<\|im_start\|>\s*)|` +
		`(?:system(?:(?:\s*:)|(?:\\n)|(?:\\r\\n)|(?:\r?\n))?\s*)){0,4}` +
		`(?:(?:please\s+|now\s+|next\s+)?(?:` +
		`(?:ignore|disregard)\s+(?:all\s+)?(?:(?:previous|prior|above|earlier)\s+` +
		`(?:instructions?|rules?|guidelines?|context)|everything(?:\s+(?:above|before))?)` +
		`|(?:override|bypass|disable|turn\s+off|remove)\s+(?:all\s+|your\s+|the\s+)?` +
		`(?:safety(?:\s+(?:rules?|checks?|filters?|restrictions?))?|guardrails?|filters?|restrictions?|` +
		`system\s+prompt|instructions?|rules?)` +
		`|(?:reveal|expose)\s+(?:your\s+|the\s+)?(?:system|initial|hidden|private|internal)\s+` +
		`(?:prompt|instructions?|rules?|guidelines?|secrets?)` +
		`|follow\s+(?:my|these|the)\s+instructions?` +
		`|do\s+evil` +
		`|you\s+(?:are|will|must|should)\s+(?:now\s+)?(?:unfiltered|unrestricted|uncensored)` +
		`|you\s+(?:have|are\s+under)\s+no\s+restrictions?` +
		`|no\s+restrictions?` +
		`|new\s+(?:instructions?|rules?|system\s+prompt)(?:\s*[:.!]|\s*$)` +
		`))\b`,
)

const trustLiteralContextWindow = 200

func applyTrustLiteralContext(
	generation *compiledRulePackCategories,
	category string,
	rule *PatternRule,
	text string,
	finding RuleFinding,
) RuleFinding {
	if rule == nil {
		return finding
	}
	ruleID := rule.ID
	if trustLiteralContextEnforceable(ruleID, text) {
		return finding
	}
	// The scan engine records only one finding per rule ID. Check the same
	// normalized view it scans before demoting a weak raw match, otherwise an
	// early benign literal could hide a later obfuscated actionable variant.
	normalized := normalizeShell(text)
	if normalized != text && trustLiteralContextEnforceable(ruleID, normalized) {
		return finding
	}
	contract, ok := trustedPromptLiteralDetectionOnly[ruleID]
	if !ok || !trustedPromptLiteralDetectionOnlyRule(
		generation,
		category,
		rule,
		ruleID,
		contract,
	) {
		return finding
	}
	finding.Severity = "LOW"
	finding.Confidence = clampConfidence(finding.Confidence * 0.5)
	finding.enforcement = findingEnforcementDetectionOnly
	return finding
}

func trustedPromptLiteralDetectionOnlyRule(
	generation *compiledRulePackCategories,
	category string,
	rule *PatternRule,
	ruleID string,
	contract trustedPromptLiteralDetectionOnlyContract,
) bool {
	if generation == nil || rule == nil || category != trustedPromptLiteralCategory ||
		!exactTrustedPromptLiteralRule(rule, ruleID, contract) {
		return false
	}

	canonicalID := canonicalPromptLiteralRuleID(ruleID)
	if canonicalID == "" {
		return false
	}
	foundOrigin := false
	for categoryIndex := range generation.categories {
		candidateCategory := &generation.categories[categoryIndex]
		for ruleIndex := range candidateCategory.Rules {
			candidate := &candidateCategory.Rules[ruleIndex]
			if canonicalPromptLiteralRuleID(candidate.ID) != canonicalID {
				continue
			}
			// Canonicalization is used only to widen collision detection. The
			// one accepted owner still needs the exact ID, category, fields, and
			// address from this immutable generation.
			if foundOrigin || candidateCategory.Name != trustedPromptLiteralCategory ||
				candidate != rule || !exactTrustedPromptLiteralRule(candidate, ruleID, contract) {
				return false
			}
			foundOrigin = true
		}
	}
	return foundOrigin
}

func exactTrustedPromptLiteralRule(
	rule *PatternRule,
	ruleID string,
	contract trustedPromptLiteralDetectionOnlyContract,
) bool {
	return rule != nil && rule.ID == ruleID && rule.Pattern != nil &&
		rule.Pattern.String() == contract.pattern && rule.Expression == "" &&
		!rule.ToolCallOnly && rule.Title == contract.title &&
		rule.Severity == contract.severity && rule.Confidence == contract.confidence &&
		slices.Equal(rule.Tags, contract.tags)
}

func canonicalPromptLiteralRuleID(ruleID string) string {
	return strings.ToUpper(strings.TrimSpace(ruleID))
}

func trustLiteralContextEnforceable(ruleID, text string) bool {
	switch ruleID {
	case "TRUST-PROMPT-EXTRACT":
		return protectedPromptExtractionPattern.MatchString(text)
	case "TRUST-FICTIONAL":
		return fictionalFramingHasAdversarialControl(text)
	case "TRUST-DELIMITER":
		return delimiterHasExplicitAttackPayload(text)
	default:
		return true
	}
}

func fictionalFramingHasAdversarialControl(text string) bool {
	for _, loc := range fictionalFramingPattern.FindAllStringIndex(text, -1) {
		start := loc[0] - trustLiteralContextWindow
		if start < 0 {
			start = 0
		}
		end := loc[1] + trustLiteralContextWindow
		if end > len(text) {
			end = len(text)
		}
		if fictionalAdversarialControlPattern.MatchString(text[start:end]) {
			return true
		}
	}
	return false
}

func delimiterHasExplicitAttackPayload(text string) bool {
	for _, loc := range delimiterControlTokenPattern.FindAllStringIndex(text, -1) {
		end := loc[1] + trustLiteralContextWindow
		if end > len(text) {
			end = len(text)
		}
		if delimiterAttackPayloadPattern.MatchString(text[loc[1]:end]) {
			return true
		}
	}
	return false
}
