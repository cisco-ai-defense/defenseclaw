// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// The identity refusal (guardrailProfileSet.identityUncertaintyReason) is
// DefenseClaw text made of fixed clauses and one explain command whose only
// variable parts are a verified user ID and two connector or agent tokens.
// The refusal is shown as it is on the call that meets it, but the session
// start gate keeps the text of a start refused for it and wraps it in a
// sentence on every later call of that session; that text went through the
// reason redaction as free-form and reached the user as redacted spans
// (GAP-0718). The clause table and the recognizer below are the one source
// of both directions: a clause is added in identityFactSentences or
// nowhere, and TestIdentityRefusalReadsOnEveryPath renders every identity
// state to check that the recognizer accepts what the producer writes.
const (
	identityRefusalPrefix         = "DefenseClaw refused this request: "
	identityRefusalElevatedPrompt = " from an elevated PowerShell prompt"
	identityRefusalTail           = " to inspect the identity decision"

	// Why a Windows account has no sign-in token groups (profileSubjectFromVerified).
	tokenGroupsCauseNoDesktopSession = "the account has no desktop session, so its sign-in token groups are unknown until it signs in at the desktop again"
	tokenGroupsCauseNoGuardianRecord = "the guardian has no identity record for this account yet; a desktop sign-in (console or Remote Desktop) writes it"
)

// identityFactSentences names each unproven identity fact without naming a
// group, another account or a candidate profile.
var identityFactSentences = map[string]string{
	"account:failed":               "the account holder is ambiguous",
	"account:ambiguous_short_name": "a bare users entry may name accounts in more than one trusted domain; use a qualified name or uid",
	"account:unknown":              "the account holder is unconfirmed",
	"upn:unknown":                  "this account\x27s UPN is unconfirmed",
	"groups:unknown":               "group membership is unconfirmed",
	"agent:unknown":                "ownership of a pre-upgrade agent identity is unconfirmed",
	factAssignmentGroupSID:         "an assignment group SID is unconfirmed",
}

// identityFactClause is the sentence for one unproven fact. A fact outside
// the table is named by its own token.
func identityFactClause(fact string) string {
	if sentence, ok := identityFactSentences[fact]; ok {
		return sentence
	}
	return "identity fact " + fact + " is unconfirmed"
}

// identityKnownClauses is every fixed clause the producer writes.
var identityKnownClauses = func() []string {
	known := []string{tokenGroupsCauseNoDesktopSession, tokenGroupsCauseNoGuardianRecord}
	for _, sentence := range identityFactSentences {
		known = append(known, sentence)
	}
	return known
}()

// A fact outside the table: "<field>:<state>", both lower-case words.
var identityUnnamedFactClause = lazyregexp.New(`^identity fact [a-z_]+:[a-z_]+ is unconfirmed$`)

// identityClauseConsumed returns rest without its first clause when rest
// opens with one the producer writes.
func identityClauseConsumed(rest string) (string, bool) {
	for _, clause := range identityKnownClauses {
		if rest == clause {
			return "", true
		}
		if after, ok := strings.CutPrefix(rest, clause+"; "); ok {
			return after, true
		}
	}
	clause, after, _ := strings.Cut(rest, "; ")
	return after, identityUnnamedFactClause.MatchString(clause)
}

// trustedIdentityRefusalReason reports an identity refusal exactly as
// identityUncertaintyReason writes it: only its fixed clauses and an
// explain command of the known shapes. Any other text after the same
// opening stays free-form and redacted.
func trustedIdentityRefusalReason(reason string) bool {
	if len(reason) > 1200 {
		return false
	}
	body, ok := strings.CutPrefix(reason, identityRefusalPrefix)
	if !ok {
		return false
	}
	if body, ok = strings.CutSuffix(body, identityRefusalTail); !ok {
		return false
	}
	body = strings.TrimSuffix(body, identityRefusalElevatedPrompt)
	if body, ok = strings.CutSuffix(body, "`"); !ok {
		return false
	}
	clauses, command, ok := strings.Cut(body, "; run `")
	if !ok || clauses == "" || !trustedIdentityExplainCommand(command) {
		return false
	}
	for n := 0; clauses != ""; n++ {
		if n > len(identityKnownClauses)+4 {
			return false
		}
		if clauses, ok = identityClauseConsumed(clauses); !ok {
			return false
		}
	}
	return true
}

// identityWindowsAdminCLI is the installed defenseclaw.exe the Windows
// explain command names (managed.WindowsStandaloneAdminCLI); a test replaces
// it to render a registered Program Files of another shape.
var identityWindowsAdminCLI = managed.WindowsStandaloneAdminCLI

// trustedIdentityExplainCommand reports an explain command exactly as
// profileExplainCommand writes it: one of its fixed forms, a verified user
// ID or the placeholder, and the --connector and --agent values that pass
// profileCommandConnector and profileCommandAgent. The Windows form is
// rendered again by the shared PowerShell renderer around the installed
// executable, so whatever quoting the renderer applies to that path is
// accepted and a command that names another executable is not. A value
// outside those predicates, in any position, makes the text free-form.
func trustedIdentityExplainCommand(command string) bool {
	if command == profileExplainList {
		return true
	}
	rest := command
	if head, agent, ok := cutLastWord(rest, " --agent "); ok {
		if !profileCommandAgent(agent) {
			return false
		}
		rest = head
	}
	if head, name, ok := cutLastWord(rest, " --connector "); ok {
		if !profileCommandConnector(name) {
			return false
		}
		rest = head
	}
	base, user, ok := strings.Cut(rest, " --user ")
	if !ok || (user != profileExplainUserPlaceholder && !profileCommandUser(user)) {
		return false
	}
	switch base {
	case profileExplainOSS, profileExplainLinux, profileExplainDarwin,
		managed.WindowsCommandLine(identityWindowsAdminCLI(), "enterprise", "windows", "profile-explain"):
		return true
	}
	return false
}

// cutLastWord splits text at the last sep when what follows is one word.
func cutLastWord(text, sep string) (head, word string, ok bool) {
	i := strings.LastIndex(text, sep)
	if i < 0 {
		return text, "", false
	}
	word = text[i+len(sep):]
	if word == "" || strings.ContainsAny(word, " \t\r\n") {
		return text, "", false
	}
	return text[:i], word, true
}
