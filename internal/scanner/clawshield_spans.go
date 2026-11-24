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

package scanner

import (
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/secretshape"
)

// SecretSpan is where a critical credential sits in a file. Start and End
// are the byte offsets of the value itself, without the key name or the
// separator a rule matches before it, so replacing the span keeps the
// surrounding syntax (quotes, "key =" prefixes). Whole marks a finding
// that is the file as a whole (a service account JSON, a connection
// string with its password further on), which cannot be cut out.
type SecretSpan struct {
	RuleID     string
	Start, End int
	Whole      bool
}

// csValueAt narrows a rule's match to its value for the rules whose
// pattern starts with a key name. Group 1 is the value; the patterns are
// anchored at the end of the match text they are applied to.
var csValueAt = map[string]*lazyregexp.Regexp{
	"CS-SEC-AWS-SECRET":  lazyregexp.New(`([A-Za-z0-9/+=]{40})$`),
	"CS-SEC-AWS-SESSION": lazyregexp.New(`(?i)aws_session_token['":\s=]*([A-Za-z0-9/+=]+)$`),
	"CS-SEC-AZ-STORAGE":  lazyregexp.New(`(?i)(?:DefaultEndpointsProtocol|AccountKey)\s*=\s*([A-Za-z0-9+/=]+)$`),
	"CS-SEC-TWILIO-AUTH": lazyregexp.New(`([0-9a-f]{32})$`),
}

// csWholeFile are the critical rules whose match is not the credential
// itself: the file is held back whole.
var csWholeFile = map[string]bool{"CS-SEC-GCP-SA": true, "CS-SEC-AZ-CONN": true}

// SigningKeyRule reports whether a rule finds key material a program uses
// to sign requests (an AWS secret key or session token, a private key):
// a header swap at egress cannot stand in for it.
func SigningKeyRule(id string) bool {
	return id == "CS-SEC-AWS-SECRET" || id == "CS-SEC-AWS-SESSION" || strings.HasPrefix(id, "CS-SEC-KEY-")
}

// ScanContentSpans returns the critical-severity credentials in content
// (the findings DefaultSecretDetector holds a file back for) with the span
// of each value, sorted by Start. Overlapping spans are merged; the merged
// span keeps the first rule's id and is Whole if either part is.
func (s *ClawShieldSecretsScanner) ScanContentSpans(content []byte) []SecretSpan {
	text := string(content)
	var spans []SecretSpan
	for _, rule := range csSecretRules {
		if rule.severity != SeverityCritical {
			continue
		}
		for _, loc := range rule.pattern.FindAllStringIndex(text, -1) {
			start, end := loc[0], loc[1]
			sp := SecretSpan{RuleID: rule.id, Start: start, End: end, Whole: csWholeFile[rule.id]}
			switch {
			case strings.HasPrefix(rule.id, "CS-SEC-KEY-"):
				if !secretshape.ValidPrivateKeyPEMAt(text, start) {
					continue
				}
				// A valid block ends at the first footer after its header
				// (base64 payload lines cannot hold "-----END ").
				footer := strings.Index(text[start:], "-----END ")
				if footer < 0 {
					sp.Whole = true
					break
				}
				tail := strings.Index(text[start+footer+len("-----END "):], "-----")
				if tail < 0 {
					sp.Whole = true
					break
				}
				sp.End = start + footer + len("-----END ") + tail + len("-----")
			case csValueAt[rule.id] != nil:
				if m := csValueAt[rule.id].FindStringSubmatchIndex(text[start:end]); m != nil && m[2] >= 0 {
					sp.Start, sp.End = start+m[2], start+m[3]
				}
			}
			spans = append(spans, sp)
		}
	}
	if len(spans) == 0 {
		return nil
	}
	sort.SliceStable(spans, func(i, j int) bool { return spans[i].Start < spans[j].Start })
	merged := spans[:1]
	for _, sp := range spans[1:] {
		last := &merged[len(merged)-1]
		if sp.Start < last.End {
			if sp.End > last.End {
				last.End = sp.End
			}
			last.Whole = last.Whole || sp.Whole
			continue
		}
		merged = append(merged, sp)
	}
	return merged
}
