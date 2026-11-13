// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"regexp"
	"strings"
	"sync"

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
	outboundPIIMaxBytes       = 1 << 16
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
// without a YAML parser: the file shape is fixed (id, then pattern, on the
// following lines of the same list item).
func outboundPIIRulePattern(data []byte, ruleID string) string {
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) != "- id: "+ruleID {
			continue
		}
		for _, next := range lines[i+1:] {
			trimmed := strings.TrimSpace(next)
			if strings.HasPrefix(trimmed, "- id:") {
				return ""
			}
			if strings.HasPrefix(trimmed, "pattern:") {
				value := strings.TrimSpace(strings.TrimPrefix(trimmed, "pattern:"))
				if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
					return strings.ReplaceAll(value[1:len(value)-1], "''", "'")
				}
				return value
			}
		}
	}
	return ""
}

// trustedActionSendToolName reports a tool whose name says it sends a message
// out: send_email, post_message, slack.publish, forward. A name that also
// says read, get, list or search is a lookup.
func trustedActionSendToolName(tool string) bool {
	leaf := strings.ToLower(tool)
	if i := strings.LastIndex(leaf, "__"); i >= 0 {
		leaf = leaf[i+2:]
	} else if i := strings.LastIndexByte(leaf, '.'); i >= 0 {
		leaf = leaf[i+1:]
	}
	send := false
	for _, word := range strings.FieldsFunc(leaf, func(r rune) bool {
		return r == '_' || r == '-' || r == '.' || r == ' ' || r == '/'
	}) {
		switch word {
		case "read", "get", "list", "search", "find", "fetch", "view", "describe", "show", "query",
			"draft", "drafts", "inbox", "unread", "count", "check":
			return false
		case "send", "email", "mail", "forward", "publish", "notify", "post", "reply", "share",
			"message", "dm", "tweet":
			send = true
		}
	}
	return send
}

// outboundPIIText joins the string values of a tool call's arguments.
func outboundPIIText(raw json.RawMessage) string {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return ""
	}
	var parts []string
	size := 0
	var walk func(any)
	walk = func(v any) {
		if size > outboundPIIMaxBytes {
			return
		}
		switch typed := v.(type) {
		case string:
			parts = append(parts, typed)
			size += len(typed)
		case []any:
			for _, item := range typed {
				walk(item)
			}
		case map[string]any:
			for _, item := range typed {
				walk(item)
			}
		}
	}
	walk(value)
	text := strings.Join(parts, "\n")
	if len(text) > outboundPIIMaxBytes {
		text = text[:outboundPIIMaxBytes]
	}
	return text
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
	text := outboundPIIText(request.Input.Args)
	if text == "" {
		return findings
	}
	text = outboundPIIQuotes.Replace(text)
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
	if card := outboundPIICardPattern(); card != nil {
		for _, loc := range card.FindAllStringIndex(text, 8) {
			if paymentcard.LabeledRunAt(text, loc[0], loc[1]) {
				add(outboundPIICardRuleID, "Labelled payment card number in a message the tool sends")
				break
			}
		}
	}
	for _, m := range outboundPIIPassport.FindAllStringSubmatchIndex(text, 8) {
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
	return findings
}
