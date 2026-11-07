// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"container/list"
	"sync"
	"time"
)

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
// Three rules keep it bounded without losing a text that is still needed.
//   - The recent list holds the last identityRefusalIssuedMax distinct texts,
//     the least recently issued dropped first; issuing a text again
//     refreshes it.
//   - A text issued while a session start is being judged (openStartWindow)
//     is kept until that start has pinned it, up to identityRefusalHeldMax
//     texts, so no number of other refusals turns the reason of a start into
//     redacted spans before the gate retains it.
//   - A text the session start gate retains for a blocked session is pinned
//     for as long as the gate keeps that verdict (up to its 4,096 sessions
//     and seven days).
//
// A text dropped past all three reads as free-form (redacted), the safe
// side (GAP-0718).
var identityRefusals identityRefusalRegistry

type identityRefusalRegistry struct {
	mu     sync.Mutex
	recent map[string]*list.Element // text -> its element of order
	order  list.List                // of *identityRefusalIssue, newest first
	seq    uint64
	open   map[uint64]identityRefusalWindow // first seq of a window -> window
	pinned map[string]int
}

type identityRefusalIssue struct {
	text string
	seq  uint64
}

type identityRefusalWindow struct {
	opened time.Time
	starts int
}

const (
	// identityRefusalIssuedMax bounds the recent list. A refusal is the text
	// of one account, connector and fact set, so a host has few distinct
	// ones.
	identityRefusalIssuedMax = 512
	// identityRefusalHeldMax bounds the texts kept for starts being judged.
	identityRefusalHeldMax = 16384
	// identityRefusalWindowMax is how long a start window holds texts. A
	// start ends at its hook answer or its in-place check timeout, well
	// inside it; past it the texts age out like any other.
	identityRefusalWindowMax = 2 * time.Minute
)

// issueIdentityRefusal records a refusal text the producer has just written
// and returns it.
func issueIdentityRefusal(text string) string {
	r := &identityRefusals
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	if elem, ok := r.recent[text]; ok {
		elem.Value.(*identityRefusalIssue).seq = r.seq
		r.order.MoveToFront(elem)
		return text
	}
	if r.recent == nil {
		r.recent = make(map[string]*list.Element, identityRefusalIssuedMax)
	}
	r.recent[text] = r.order.PushFront(&identityRefusalIssue{text: text, seq: r.seq})
	r.trimLocked(time.Now())
	return text
}

// trimLocked drops the least recently issued texts past the bound, except
// the ones issued since the oldest live start window opened.
func (r *identityRefusalRegistry) trimLocked(now time.Time) {
	holdFrom := uint64(0)
	for first, window := range r.open {
		if now.Sub(window.opened) > identityRefusalWindowMax {
			delete(r.open, first)
		} else if holdFrom == 0 || first < holdFrom {
			holdFrom = first
		}
	}
	for r.order.Len() > identityRefusalIssuedMax {
		oldest := r.order.Back()
		issue := oldest.Value.(*identityRefusalIssue)
		if holdFrom != 0 && issue.seq >= holdFrom && r.order.Len() <= identityRefusalHeldMax {
			return
		}
		r.order.Remove(oldest)
		delete(r.recent, issue.text)
	}
}

// openStartWindow marks a session start being judged: every text issued from
// now until closeStartWindow stays trusted, so the reason the start ends with
// can still be pinned. It returns the window to close.
func openStartWindow() uint64 {
	r := &identityRefusals
	r.mu.Lock()
	defer r.mu.Unlock()
	first := r.seq + 1
	if r.open == nil {
		r.open = make(map[uint64]identityRefusalWindow)
	}
	window := r.open[first]
	if window.starts == 0 {
		window.opened = time.Now()
	}
	window.starts++
	r.open[first] = window
	return first
}

// closeStartWindow ends a window of openStartWindow once its start has
// pinned the reason it retains (or has none to pin).
func closeStartWindow(first uint64) {
	r := &identityRefusals
	r.mu.Lock()
	defer r.mu.Unlock()
	window, ok := r.open[first]
	if !ok {
		return
	}
	if window.starts--; window.starts > 0 {
		r.open[first] = window
	} else {
		delete(r.open, first)
	}
	r.trimLocked(time.Now())
}

// pinIdentityRefusal keeps a refusal text trusted until it is unpinned, for
// a verdict the session start gate retains. It pins only a text the
// producer issued and reports whether it did.
func pinIdentityRefusal(text string) bool {
	r := &identityRefusals
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.recent[text]; !ok && r.pinned[text] == 0 {
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
	if _, ok := r.recent[reason]; ok {
		return true
	}
	return r.pinned[reason] > 0
}
