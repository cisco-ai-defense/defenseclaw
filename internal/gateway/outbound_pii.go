// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/paymentcard"
	policyassets "github.com/defenseclaw/defenseclaw/policies"
)

// Personal data leaves the machine when a send tool carries it in the message.
// The enterprise-data rules classify the content of a prompt or a document;
// in a tool call they stay audit telemetry, because a command that mentions a
// card number is not a transfer of one. A send tool is: its arguments are the
// message. A labelled card or passport number in them alerts. It never blocks:
// the call cannot tell a user mailing their own booking to a travel agency
// from an injected instruction doing the same, and the recipient is only an
// address.
//
// The card check is the PII-CARD-LABELED rule of the privacy-high-assurance
// pack and its LabeledRunAt validator, read from the embedded pack, not
// copied. The passport check is the same shape for the one identifier that
// pack has no labelled rule for.

const (
	outboundPIICardRuleID     = "PII-CARD-LABELED"
	outboundPIIPassportRuleID = "PII-PASSPORT-LABELED"
)

var outboundPIIPassport = regexp.MustCompile(
	`(?i:\bpassport(?:[\s_-]*(?:number|no\.?|num|#))?)[\s*_:=#-]{1,12}([A-Z0-9]{6,9})\b`)

var (
	outboundPIICardOnce sync.Once
	outboundPIICardRE   *regexp.Regexp
)

// outboundPIICardPattern returns the PII-CARD-LABELED pattern of the embedded
// privacy-high-assurance pack, or nil when the pack does not carry it.
func outboundPIICardPattern() *regexp.Regexp {
	outboundPIICardOnce.Do(func() {
		files, err := policyassets.ProtectionPackRules("privacy-high-assurance")
		if err != nil {
			return
		}
		for _, file := range files {
			if pattern := outboundPIIRulePattern(file.Data, outboundPIICardRuleID); pattern != "" {
				if re, err := regexp.Compile(pattern); err == nil {
					outboundPIICardRE = re
				}
				return
			}
		}
	})
	return outboundPIICardRE
}

// outboundPIIRulePattern reads the pattern of one rule from rule-file YAML
// (a rules list of items with an id and a pattern). A file that does not parse
// or does not carry the rule gives "".
func outboundPIIRulePattern(data []byte, ruleID string) string {
	var doc struct {
		Rules []struct {
			ID      string `yaml:"id"`
			Pattern string `yaml:"pattern"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return ""
	}
	for _, rule := range doc.Rules {
		if rule.ID == ruleID {
			return rule.Pattern
		}
	}
	return ""
}

// trustedActionSendToolName reports a tool whose name says it hands a message
// to someone: a send verb in the name (send, post, publish, forward, reply,
// share, notify, broadcast, tweet, dm, email, mail) and no read verb before
// it. The name is cut into words (sendEmail, chat_postMessage), and a noun
// alone (message, email, history) decides nothing: message_history is a
// lookup, get_email is a lookup, mail_send is not.
func trustedActionSendToolName(tool string) bool {
	for _, word := range toolLeafWords(tool) {
		switch word {
		case "read", "get", "list", "search", "find", "fetch", "view", "describe", "show", "query",
			"draft", "drafts", "inbox", "unread", "count", "check", "history", "log", "logs", "lookup",
			"status", "summary", "retrieve", "load", "open":
			return false
		case "send", "post", "publish", "forward", "reply", "share", "notify", "broadcast", "tweet", "dm",
			"email", "mail":
			return true
		}
	}
	return false
}

// outboundPIIStrings returns the string values of a tool call's arguments in
// a fixed order (object keys sorted, arrays in order), so the same call is
// judged the same way every time. Nothing is cut: each string is scanned
// whole, and RE2 is linear in its length, so the request body limit is the
// only bound and there is no cap that could hide what comes after it.
func outboundPIIStrings(raw json.RawMessage) []string {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil
	}
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch typed := v.(type) {
		case string:
			out = append(out, typed)
		case []any:
			for _, item := range typed {
				walk(item)
			}
		case map[string]any:
			keys := make([]string, 0, len(typed))
			for key := range typed {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				walk(typed[key])
			}
		}
	}
	walk(value)
	return out
}

// outboundPIIQuotes turns the quote characters of a dict or JSON rendering
// into spaces, so "'Credit Card Number': '4237-4252-7456-2574'" reads as the
// labelled field it is. Byte offsets are unchanged.
var outboundPIIQuotes = strings.NewReplacer("'", " ", `"`, " ", "`", " ", `\`, " ")

// outboundPIIFindings adds an alert-only finding for a labelled card or
// passport number in the message of a send tool.
func outboundPIIFindings(request trustedActionRequest, findings []RuleFinding) []RuleFinding {
	if !request.EnforcementCapable || !trustedActionSendToolName(request.Input.Tool) ||
		len(request.Input.Args) == 0 {
		return findings
	}
	strs := outboundPIIStrings(request.Input.Args)
	if len(strs) == 0 {
		return findings
	}
	add := func(ruleID, title string) {
		for _, existing := range findings {
			if existing.RuleID == ruleID {
				return
			}
		}
		findings = append(findings, RuleFinding{
			RuleID: ruleID, Title: title, Severity: "MEDIUM", Confidence: 0.7,
			Tags:        []string{"pii", "outbound"},
			LineNumber:  1,
			enforcement: findingEnforcementAlertOnly,
		})
	}
	card := outboundPIICardPattern()
	for _, text := range strs {
		text = outboundPIIQuotes.Replace(text)
		if card != nil {
			for _, loc := range card.FindAllStringIndex(text, -1) {
				if paymentcard.LabeledRunAt(text, loc[0], loc[1]) {
					add(outboundPIICardRuleID, "Labelled payment card number in a message the tool sends")
					break
				}
			}
		}
		for _, m := range outboundPIIPassport.FindAllStringSubmatchIndex(text, -1) {
			value := text[m[2]:m[3]]
			digits := 0
			for _, r := range value {
				if r >= '0' && r <= '9' {
					digits++
				}
			}
			if digits >= 5 {
				add(outboundPIIPassportRuleID, "Labelled passport number in a message the tool sends")
				break
			}
		}
	}
	return findings
}
