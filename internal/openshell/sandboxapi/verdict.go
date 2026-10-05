// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
package sandboxapi

import "strings"

// verdictLeads start the block and confirmation reasons of a sandbox hook
// verdict (gateway.agentBlockSentence, gateway.agentConfirmSentence): the
// wording a host hook uses, then " (rule ID: Title)" when a rule is named.
var verdictLeads = []string{
	"DefenseClaw policy blocked this action",
	"DefenseClaw blocked this action under your organization's policy",
	"DefenseClaw policy needs your confirmation for this action",
	"DefenseClaw needs your confirmation for this action under your organization's policy",
}

// verdictVerbs start the other verdict reasons ("Allowed but flagged by
// DefenseClaw rule ID: Title. ..."), and those of gateways from before
// GAP-1885 ("Blocked by DefenseClaw rule ID: Title. ...").
var verdictVerbs = []string{"Blocked by", "Held for approval by", "Allowed but flagged by", "Flagged by"}

// VerdictRule reads the leading rule out of a sandbox hook verdict's
// reason: its ID and title (title "" when the reason leaves it out). ok is
// false for a reason that is no DefenseClaw verdict reason; id is "" for
// one that names no rule.
func VerdictRule(reason string) (id, title string, ok bool) {
	r := strings.TrimSpace(reason)
	for _, lead := range verdictLeads {
		rest, found := strings.CutPrefix(r, lead)
		if !found {
			continue
		}
		subject, found := strings.CutPrefix(rest, " (")
		end := strings.Index(subject, ").")
		if !found || end < 0 {
			return "", "", true
		}
		subject = subject[:end]
		item, found := strings.CutPrefix(subject, "rule ")
		if !found {
			if item, found = strings.CutPrefix(subject, "rules "); !found {
				return "", "", true
			}
			item, _, _ = strings.Cut(item, ", ")
		}
		id, title, _ = strings.Cut(item, ": ")
		return strings.TrimSpace(id), strings.TrimSpace(title), true
	}
	for _, verb := range verdictVerbs {
		rest, found := strings.CutPrefix(r, verb+" DefenseClaw ")
		if !found {
			continue
		}
		if rest, found = strings.CutPrefix(rest, "rule "); !found {
			return "", "", true
		}
		end := len(rest)
		for _, sep := range []string{":", " (", ". "} {
			if i := strings.Index(rest, sep); i >= 0 && i < end {
				end = i
			}
		}
		id = strings.TrimSuffix(rest[:end], ".")
		if strings.HasPrefix(rest[end:], ":") {
			title = strings.TrimSpace(rest[end+1:])
			for _, sep := range []string{" (also ", ". "} {
				if i := strings.Index(title, sep); i >= 0 {
					title = title[:i]
				}
			}
			title = strings.TrimSuffix(title, ".")
		}
		return id, title, true
	}
	return "", "", false
}

// VerdictRuleLabel is what an activity-feed line names for a verdict
// reason: "SEC-AWS-KEY (AWS access key)", the rule ID alone, "" for a
// DefenseClaw verdict that names no rule, or any other reason as is. The
// feed used to repeat the whole reason, advice to the agent included
// ("✗ prompt blocked by DefenseClaw: Blocked by DefenseClaw rule ..."),
// GAP-1902.
func VerdictRuleLabel(reason string) string {
	id, title, ok := VerdictRule(reason)
	switch {
	case !ok:
		return strings.TrimSpace(reason)
	case id == "" || title == "":
		return id
	}
	return id + " (" + title + ")"
}
