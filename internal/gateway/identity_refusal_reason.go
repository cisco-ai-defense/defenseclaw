// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "sync"

// The identity refusal (guardrailProfileSet.identityUncertaintyReason) is
// DefenseClaw text made of fixed clauses and one explain command whose only
// variable parts are a verified user ID and two connector or agent tokens.
// The refusal is shown as it is on the call that meets it, but the session
// start gate keeps the text of a start refused for it and wraps it in a
// sentence on every later call of that session; that text went through the
// reason redaction as free-form and reached the user as redacted spans
// (GAP-0718). The producer now issues each text it writes
// (issueIdentityRefusal) and the display trusts exactly the texts issued.
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

// identityRefusals is the set of refusal texts this process wrote. The
// display trusts a text because the producer issued it, never because of how
// it reads: a recognizer of the final string cannot tell a value the
// producer verified from one that only fits the same shape (a forged user
// ID, a fact word, a path that holds the option delimiter) and drops a valid
// rendering it did not expect.
//
// Two tiers keep it bounded without losing a live verdict. The recent ring
// holds the last texts written, the oldest dropped once it is full. A text
// the session start gate retains for a blocked session is also pinned for as
// long as the gate keeps that verdict (up to its 4,096 sessions and seven
// days), so the refusals of other accounts never turn a live session into
// redacted spans (GAP-0718).
var identityRefusals struct {
	mu     sync.Mutex
	issued map[string]struct{}
	order  [identityRefusalIssuedMax]string
	next   int
	pinned map[string]int
}

// identityRefusalIssuedMax bounds the recent ring. A refusal is the text of
// one account, connector and fact set, so a host has few distinct ones; a
// text pushed out and not pinned reads as free-form (redacted), the safe
// side.
const identityRefusalIssuedMax = 512

// issueIdentityRefusal records a refusal text the producer has just written
// and returns it.
func issueIdentityRefusal(text string) string {
	r := &identityRefusals
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.issued[text]; ok {
		return text
	}
	if r.issued == nil {
		r.issued = make(map[string]struct{}, identityRefusalIssuedMax)
	}
	if old := r.order[r.next]; old != "" {
		delete(r.issued, old)
	}
	r.order[r.next] = text
	r.next = (r.next + 1) % identityRefusalIssuedMax
	r.issued[text] = struct{}{}
	return text
}

// pinIdentityRefusal keeps a refusal text trusted until it is unpinned, for
// a verdict the session start gate retains. It pins only a text the
// producer issued and reports whether it did.
func pinIdentityRefusal(text string) bool {
	r := &identityRefusals
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.issued[text]; !ok && r.pinned[text] == 0 {
		return false
	}
	if r.pinned == nil {
		r.pinned = make(map[string]int)
	}
	r.pinned[text]++
	return true
}

// unpinIdentityRefusal releases one pin of pinIdentityRefusal.
func unpinIdentityRefusal(text string) {
	r := &identityRefusals
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pinned[text] > 1 {
		r.pinned[text]--
		return
	}
	delete(r.pinned, text)
}

// trustedIdentityRefusalReason reports a refusal text exactly as
// identityUncertaintyReason issued it. Any other text, however it reads,
// stays free-form and redacted.
func trustedIdentityRefusalReason(reason string) bool {
	r := &identityRefusals
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.issued[reason]; ok {
		return true
	}
	return r.pinned[reason] > 0
}
