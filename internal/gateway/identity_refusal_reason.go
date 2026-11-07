// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"container/list"
	"hash/maphash"
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

	// identityRefusalConnectorHint follows the explain command when a
	// connector the administrator configured stands in it as a placeholder:
	// the name itself is configuration text and never rides in the reason.
	identityRefusalConnectorHint = " (replace " + profileConnectorPlaceholder + " with the name of the connector from the configuration)"
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
//     refreshes it. It serves the call that meets the refusal.
//   - A session start being judged owns a watch (watchIdentityRefusals) that
//     records every text issued while it lasts, as a fingerprint, so the
//     reason the start ends with can still be pinned however many other
//     refusals were issued meanwhile. The watch is the start's own: it has
//     its own lifetime, is never shared with another start, and is not
//     bounded by a count that another start's traffic could fill (a
//     fingerprint is issued once per distinct text and only for as long as
//     the start lasts, at most identityRefusalWatchMax).
//   - A text the session start gate retains for a blocked session is pinned
//     for as long as the gate keeps that verdict (up to its 4,096 sessions
//     and seven days).
//
// A text dropped past all three reads as free-form (redacted), the safe
// side (GAP-0718).
var identityRefusals identityRefusalRegistry

type identityRefusalRegistry struct {
	mu      sync.Mutex
	recent  map[string]*list.Element // text -> its element of order
	order   list.List                // of string, newest first
	watches map[*identityRefusalWatch]struct{}
	pinned  map[string]int
}

// identityRefusalWatch is one session start's record of the refusals issued
// while it is judged. It is guarded by the registry's mutex.
type identityRefusalWatch struct {
	deadline time.Time
	seen     map[uint64]struct{} // fingerprints of the texts issued
}

const (
	// identityRefusalIssuedMax bounds the recent list. A refusal is the text
	// of one account, connector and fact set, so a host has few distinct
	// ones.
	identityRefusalIssuedMax = 512
	// identityRefusalWatchMax is how long a start's watch records. A start
	// ends at its hook answer or its in-place check timeout, well inside it;
	// a start that never finishes stops recording at it and the texts age
	// out like any other.
	identityRefusalWatchMax = 2 * time.Minute
)

// identityRefusalSeed keys the fingerprints, so no text can be crafted to
// collide with an issued one.
var identityRefusalSeed = maphash.MakeSeed()

func identityRefusalFingerprint(text string) uint64 {
	return maphash.String(identityRefusalSeed, text)
}

// issueIdentityRefusal records a refusal text the producer has just written
// and returns it.
func issueIdentityRefusal(text string) string {
	r := &identityRefusals
	r.mu.Lock()
	defer r.mu.Unlock()
	if elem, ok := r.recent[text]; ok {
		r.order.MoveToFront(elem)
	} else {
		if r.recent == nil {
			r.recent = make(map[string]*list.Element, identityRefusalIssuedMax)
		}
		r.recent[text] = r.order.PushFront(text)
		for r.order.Len() > identityRefusalIssuedMax {
			oldest := r.order.Back()
			r.order.Remove(oldest)
			delete(r.recent, oldest.Value.(string))
		}
	}
	if len(r.watches) > 0 {
		now, fingerprint := time.Now(), identityRefusalFingerprint(text)
		for watch := range r.watches {
			if now.After(watch.deadline) {
				delete(r.watches, watch)
				continue
			}
			watch.seen[fingerprint] = struct{}{}
		}
	}
	return text
}

// watchIdentityRefusals starts the record of a session start being judged:
// every text issued from now until close stays pinnable by that start. The
// caller closes it.
func watchIdentityRefusals() *identityRefusalWatch {
	r := &identityRefusals
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for other := range r.watches {
		if now.After(other.deadline) {
			delete(r.watches, other)
		}
	}
	watch := &identityRefusalWatch{deadline: now.Add(identityRefusalWatchMax), seen: make(map[uint64]struct{})}
	if r.watches == nil {
		r.watches = make(map[*identityRefusalWatch]struct{})
	}
	r.watches[watch] = struct{}{}
	return watch
}

// adopt records the refusal of the decision this start's own request was
// resolved to, which the producer issued before the start began: that
// text is the one the start is expected to end with. text is the Refused
// field of a profileDecision, written only by identityUncertaintyReason.
func (w *identityRefusalWatch) adopt(text string) {
	if w == nil || text == "" {
		return
	}
	r := &identityRefusals
	r.mu.Lock()
	defer r.mu.Unlock()
	if w.seen != nil {
		w.seen[identityRefusalFingerprint(text)] = struct{}{}
	}
}

// pin keeps a refusal text trusted until it is unpinned, for a verdict the
// session start gate retains. It pins only a text the producer issued
// (recent, pinned already, or recorded by this start's watch) and reports
// whether it did.
func (w *identityRefusalWatch) pin(text string) bool {
	r := &identityRefusals
	r.mu.Lock()
	defer r.mu.Unlock()
	_, issued := r.recent[text]
	if !issued && r.pinned[text] == 0 {
		if w == nil {
			return false
		}
		if _, issued = w.seen[identityRefusalFingerprint(text)]; !issued { // a closed watch has no seen
			return false
		}
	}
	if r.pinned == nil {
		r.pinned = make(map[string]int)
	}
	r.pinned[text]++
	return true
}

// close ends the watch once its start has pinned the reason it retains (or
// has none to pin).
func (w *identityRefusalWatch) close() {
	if w == nil {
		return
	}
	r := &identityRefusals
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.watches, w)
	w.seen = nil
}

// unpinIdentityRefusal releases one pin of pin.
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
