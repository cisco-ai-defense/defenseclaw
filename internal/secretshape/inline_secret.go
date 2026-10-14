// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package secretshape

import (
	"regexp"
	"strings"
)

// InlineSecret is a secret value found in a text. Label names its kind and
// Offset is its byte offset; the value itself is never kept, so the finding
// is safe to log.
type InlineSecret struct {
	Label  string
	Offset int
}

// inlineCredentialShapes are credentials whose issuer prefix and body shape
// identify them without context. Each body is bounded by its charset, so a
// regular expression that describes the shape (AKIA[0-9A-Z]{16}) or a word
// that merely contains the prefix does not match.
var inlineCredentialShapes = []struct {
	label string
	re    *regexp.Regexp
	body  int // index of the submatch that holds the body
}{
	{"aws-access-key-id", regexp.MustCompile(`\b(?:AKIA|ASIA)([0-9A-Z]{16})\b`), 1},
	{"github-token", regexp.MustCompile(`\bgh[pousr]_([0-9A-Za-z]{36})\b`), 1},
	{"github-fine-grained-token", regexp.MustCompile(`\bgithub_pat_([0-9A-Za-z_]{82})\b`), 1},
	{"slack-token", regexp.MustCompile(`\bxox[abprs]-([0-9A-Za-z-]{10,})`), 1},
	{"anthropic-key", regexp.MustCompile(`\bsk-ant-([0-9A-Za-z_-]{32,})`), 1},
	{"openai-key", regexp.MustCompile(`\bsk-(?:proj-|svcacct-)?([0-9A-Za-z_-]{32,})`), 1},
	{"google-api-key", regexp.MustCompile(`\bAIza([0-9A-Za-z_-]{35})`), 1},
	{"stripe-secret-key", regexp.MustCompile(`\b[rs]k_live_([0-9A-Za-z]{24,})`), 1},
	{"jwt", regexp.MustCompile(`\beyJ([0-9A-Za-z_-]{8,})\.eyJ[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{16,}`), 1},
}

// FindInlineSecret returns the first secret value in text: a complete
// private-key PEM block (ValidPrivateKeyPEMAt) or a credential with a
// well-known issuer shape. A body made of one repeated character is a
// placeholder (AKIAXXXXXXXXXXXXXXXX), not a secret.
func FindInlineSecret(text string) (InlineSecret, bool) {
	best := InlineSecret{Offset: -1}
	for from := 0; ; {
		i := strings.Index(text[from:], "-----BEGIN")
		if i < 0 {
			break
		}
		if ValidPrivateKeyPEMAt(text, from+i) {
			best = InlineSecret{Label: "private-key", Offset: from + i}
			break
		}
		from += i + len("-----BEGIN")
	}
	for _, shape := range inlineCredentialShapes {
		for _, loc := range shape.re.FindAllStringSubmatchIndex(text, -1) {
			if best.Offset >= 0 && loc[0] >= best.Offset {
				break
			}
			body := text[loc[2*shape.body]:loc[2*shape.body+1]]
			if strings.Trim(body, body[:1]) == "" {
				continue
			}
			best = InlineSecret{Label: shape.label, Offset: loc[0]}
			break
		}
	}
	return best, best.Offset >= 0
}
