// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CanonicalNameForID is NameForID for the account name records carry
// (defenseclaw.user.name) and users selectors match. On Windows, while the
// user who signed in with a UPN (ENT-BOB@DCLAB.TEST, as typed) has a
// session, LookupAccountSid can answer that UPN for the account, in the case
// it was typed, rather than its sAMAccountName. One person then shows up
// under two account names, records whose name field takes no @ drop the name
// (GAP-0382), and a users entry naming ent-bob or DCLAB\ent-bob selected him
// only when he signed in as DCLAB\ent-bob (GAP-0533). Such an answer is
// mapped back to the bare sAMAccountName (canonicalSIDAccountName). An
// account whose own name holds a literal @ keeps it.
func CanonicalNameForID(id string) string {
	name := NameForID(id)
	if KindForID(id) != KindWindowsSID || !strings.Contains(name, "@") {
		return name
	}
	return canonicalSIDNames.get(strings.TrimSpace(id), name)
}

// CanonicalWindowsAccountName is CanonicalNameForID for an account name and
// domain a caller already had from LookupAccountSid for sid: the enrollment
// enumerator, the sandbox gate and profile-explain name the account the
// way the hook path does.
func CanonicalWindowsAccountName(sid, account, domain string) string {
	if KindForID(sid) != KindWindowsSID || !strings.Contains(account, "@") {
		return account
	}
	return canonicalSIDNames.getIn(strings.TrimSpace(sid), account, domain)
}

// SettledWindowsAccountName is CanonicalWindowsAccountName for the writer of a
// trusted machine record (the SYSTEM enumerator's identity record): the
// account's sAMAccountName when the directory's translation spelt it, else ""
// (a name with no @, no translation, or one that did not answer in time). The
// enumerator's LSA also names an account that signed in with a UPN by that
// UPN, so the record held DCLAB\ENT-CAROL@DCLAB.TEST and the gateway, whose
// service account cannot translate, had nothing settled to read: the typed
// spelling stayed the name (GAP-0382). A record never carries the typed
// spelling, which would read as settled.
func SettledWindowsAccountName(sid, account, domain string) string {
	if KindForID(sid) != KindWindowsSID || !strings.Contains(account, "@") {
		return ""
	}
	name, settled := canonicalSIDNames.lookupIn(strings.TrimSpace(sid), account, domain)
	if !settled {
		return ""
	}
	return name
}

// SetKnownAccountNameLookup installs lookup, the DOMAIN\name a trusted
// machine record holds for a Windows SID ("" for none): on a managed Windows
// gateway, the identity record the SYSTEM enumerator writes. nil removes it.
func SetKnownAccountNameLookup(lookup func(sid string) string) {
	if lookup == nil {
		knownAccountNames.Store(nil)
		return
	}
	knownAccountNames.Store(&lookup)
}

var knownAccountNames atomic.Pointer[func(string) string]

func knownAccountName(sid string) string {
	if lookup := knownAccountNames.Load(); lookup != nil {
		return (*lookup)(sid)
	}
	return ""
}

// canonicalSIDAccountName maps lsaName, the name the LSA gave sid in domain,
// to the account's sAMAccountName when lsaName is the sign-in UPN of that
// same account. settled reports that the name is spelt as the directory
// holds it. sidOf names the SID an account name resolves to
// (LookupAccountName); samForUPN translates a UPN to DOMAIN\sAMAccountName
// (TranslateNameW, "" when it is not one); known names the account of a SID
// as a trusted record holds it (knownAccountName). samForUPN and known may
// be nil.
//
// The answers, in order:
//   - the translation, with the sAMAccountName in its directory case, also
//     for a UPN whose prefix is not the sAMAccountName;
//   - the account the SYSTEM enumerator recorded for sid, when both it and
//     the sign-in name resolve to sid. The enumerator's LSA names the
//     account by its sAMAccountName, in its directory case, while the
//     gateway's restricted service account gets no answer from the
//     translation, which binds to the directory as the caller;
//   - the LSA on its own: when both DOMAIN\<the part before the @> and the
//     sign-in name resolve to sid, that part is the sAMAccountName of this
//     account (GAP-0533). It is spelt as its user typed it at sign-in
//     (ENT-CAROL for ent-carol), so the answer is not settled: the records
//     of the two sign-in forms named one account two ways (GAP-0382).
func canonicalSIDAccountName(sid, domain, lsaName string, samForUPN, known, sidOf func(string) string) (string, bool) {
	name := strings.TrimSpace(lsaName)
	if !strings.Contains(name, "@") || NormalizeUPN(name) == "" || sidOf == nil {
		return name, false
	}
	sameSID := func(account string) bool { return strings.EqualFold(strings.TrimSpace(sidOf(account)), sid) }
	if samForUPN != nil {
		sam := strings.TrimSpace(samForUPN(name))
		if account, _ := SplitQualifiedName(sam); sam != "" && account != "" && sameSID(sam) {
			return account, true
		}
	}
	domain = strings.TrimSpace(domain)
	if known != nil {
		if account, qualified := recordedAccountName(known(sid), domain); account != "" && sameSID(qualified) && sameSID(name) {
			return account, true
		}
	}
	if bare, _ := SplitQualifiedName(name); bare != "" && !strings.ContainsAny(bare, `\@`) {
		if domain != "" && sameSID(domain+`\`+bare) && sameSID(name) {
			return bare, false
		}
	}
	return name, false
}

// recordedAccountName splits a recorded DOMAIN\name (or a bare name, in
// domain) into the bare account and the qualified name it is looked up by.
// A name with an @ in its account part is not a sAMAccountName here.
func recordedAccountName(recorded, domain string) (account, qualified string) {
	recorded = strings.TrimSpace(recorded)
	account, recordedDomain := recorded, domain
	if i := strings.IndexByte(recorded, '\\'); i >= 0 {
		account, recordedDomain = recorded[i+1:], recorded[:i]
	}
	account, recordedDomain = strings.TrimSpace(account), strings.TrimSpace(recordedDomain)
	if account == "" || recordedDomain == "" || strings.ContainsAny(account, `\@`) {
		return "", ""
	}
	return account, recordedDomain + `\` + account
}

// canonicalSIDNameWait bounds how long a request waits for the directory to
// translate a UPN-form account name; a slower answer is used by the next
// request, and this one keeps the LSA's name.
const canonicalSIDNameWait = 2 * time.Second

// canonicalSIDNameLimit bounds the cache; it is cleared when full.
const canonicalSIDNameLimit = 1024

// canonicalSIDNameRetry is how long an answer not spelt by the directory or
// the enumerator's record is trusted: a domain controller that was
// unreachable at sign-in, or a record the enumerator had not written yet,
// must not leave the UPN or its typed spelling the account's name until the
// gateway restarts.
const canonicalSIDNameRetry = 2 * time.Minute

var canonicalSIDNames = &canonicalNameCache{
	resolve: func(sid, name, domain string) (string, bool) {
		if domain == "" {
			domain = platformDomainForSID(sid)
		}
		return canonicalSIDAccountName(sid, domain, name, platformSAMNameForUPN, knownAccountName, platformSIDForAccountName)
	},
	wait: canonicalSIDNameWait,
	now:  time.Now,
}

// canonicalNameCache remembers each (SID, LSA name) answer, so a hook pays
// for the directory translation once per account and spelling.
type canonicalNameCache struct {
	resolve func(sid, name, domain string) (string, bool)
	wait    time.Duration
	now     func() time.Time

	mu      sync.Mutex
	entries map[string]canonicalNameEntry
}

// canonicalNameEntry is one answer; expires is zero for a settled name,
// which does not change while the account exists.
type canonicalNameEntry struct {
	name    string
	expires time.Time
}

func (c *canonicalNameCache) get(sid, name string) string { return c.getIn(sid, name, "") }

func (c *canonicalNameCache) getIn(sid, name, domain string) string {
	canonical, _ := c.lookupIn(sid, name, domain)
	return canonical
}

// lookupIn is getIn with whether the answer is settled; one that did not
// come within the wait is name, unsettled.
func (c *canonicalNameCache) lookupIn(sid, name, domain string) (string, bool) {
	key := sid + "\x00" + name
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	c.mu.Lock()
	if entry, ok := c.entries[key]; ok && (entry.expires.IsZero() || now().Before(entry.expires)) {
		c.mu.Unlock()
		return entry.name, entry.expires.IsZero()
	}
	c.mu.Unlock()
	type result struct {
		name    string
		settled bool
	}
	answer := make(chan result, 1)
	go func() {
		canonical, settled := c.resolve(sid, name, strings.TrimSpace(domain))
		entry := canonicalNameEntry{name: canonical}
		if !settled {
			entry.expires = now().Add(canonicalSIDNameRetry)
		}
		c.mu.Lock()
		if c.entries == nil || len(c.entries) >= canonicalSIDNameLimit {
			c.entries = map[string]canonicalNameEntry{}
		}
		c.entries[key] = entry
		c.mu.Unlock()
		answer <- result{canonical, settled}
	}()
	select {
	case got := <-answer:
		return got.name, got.settled
	case <-time.After(c.wait):
		return name, false
	}
}
