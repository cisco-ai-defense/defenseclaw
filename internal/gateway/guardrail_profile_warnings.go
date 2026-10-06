// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// profileExplainWarnings lists what an administrator should know about the
// decision `guardrail profile explain` reports, and what doctor and status
// repeat: things that are not errors but that the profile decision alone
// does not show.
func profileExplainWarnings(set *guardrailProfileSet, decision profileDecision, subject *profileSubject) []string {
	var warnings []string
	if note := shortNameUserNote(set, decision, subject); note != "" {
		warnings = append(warnings, note)
	}
	return warnings
}

// shortNameUserNote says when a directory account was selected by a users
// entry that is a bare name. A bare name is the account name without its
// domain, so the entry meant for alice@corp.example.com selects a local
// account alice as well, and the reverse (GAP-0182).
func shortNameUserNote(set *guardrailProfileSet, decision profileDecision, subject *profileSubject) string {
	if set == nil || subject == nil || decision.Assignment < 1 || decision.Assignment > len(set.assignments) ||
		subject.Domain == "" || subject.Directory == useridentity.DirectoryLocal {
		return ""
	}
	for _, entry := range set.assignments[decision.Assignment-1].Match.Users {
		entry = strings.TrimSpace(entry)
		if entry == "" || strings.ContainsAny(entry, `@\`) || !userEntryMatches(subject, entry) ||
			strings.EqualFold(entry, subject.UserID) {
			continue
		}
		qualified := firstNonEmpty(subject.UPN, subject.Principal, subject.UserID)
		return fmt.Sprintf("assignment %d selects this account by the short name %q, so it selects a local account of that name too; "+
			"write %s (or the uid) to select only this account", decision.Assignment, entry, qualified)
	}
	return ""
}
