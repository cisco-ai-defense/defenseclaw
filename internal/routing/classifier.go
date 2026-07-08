// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routing

import "strings"

// Message represents a chat message for classification.
type Message struct {
	Role    string
	Content string
}

// SignalResult holds matched signals from classification.
type SignalResult struct {
	MatchedKeywords   []string
	MatchedEmbeddings []string
	MatchedDomains    []string
}

// Classify evaluates all signals against the messages and returns matched signal names.
func Classify(messages []Message, signals SignalConfig) *SignalResult {
	result := &SignalResult{}
	if len(messages) == 0 {
		return result
	}

	// Extract last user message for classification.
	var lastUserMsg string
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == "user" {
			lastUserMsg = strings.ToLower(messages[i].Content)
			break
		}
	}
	if lastUserMsg == "" {
		return result
	}

	for _, ks := range signals.Keywords {
		if matchKeywordSignal(lastUserMsg, ks) {
			result.MatchedKeywords = append(result.MatchedKeywords, ks.Name)
		}
	}

	return result
}

func matchKeywordSignal(text string, signal KeywordSignal) bool {
	op := strings.ToUpper(signal.Operator)
	if op == "AND" {
		for _, kw := range signal.Keywords {
			if !strings.Contains(text, strings.ToLower(kw)) {
				return false
			}
		}
		return len(signal.Keywords) > 0
	}
	// Default: OR
	for _, kw := range signal.Keywords {
		if strings.Contains(text, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}
