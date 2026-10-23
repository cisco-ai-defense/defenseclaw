// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import (
	"strings"
	"sync"
	"time"
)

// Windows directory facts, verified.
//
// The gateway and the SYSTEM enumerator resolve them for a SID the kernel or
// a per-user credential already verified, from OS state only:
//
//   - LookupAccountSid names the account and its domain; the domain equals
//     the computer name for a local account.
//   - The identity store, HKLM\SOFTWARE\Microsoft\IdentityStore\Cache\<SID>\
//     IdentityCache\<SID>, holds the UPN of a cloud sign-in (UserName) and
//     the provider that issued it (ProviderName, "AzureAD" for Entra ID).
//   - CloudDomainJoin\JoinInfo\<thumbprint> (TenantId) and TenantInfo say the
//     device is Entra joined, and the LSA primary-domain policy says it is
//     AD joined; both together is a hybrid join.
//   - An AD account's UPN comes from TranslateNameW, which may contact a
//     domain controller, so it runs in the background (adUPNCache) and the
//     caller says how long it may wait for it.
//
// The parsing is here, behind windowsDirectoryReader, so it is tested on
// every platform; directory_windows.go supplies the real reader.

const (
	identityStoreCacheKey = `SOFTWARE\Microsoft\IdentityStore\Cache`
	cloudJoinInfoKey      = `SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo`
	cloudTenantInfoKey    = `SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo`
	entraProviderName     = "AzureAD"
	entraUserSIDPrefix    = "S-1-12-1-"
)

// windowsDirectoryReader is the OS state the Windows resolver reads.
type windowsDirectoryReader interface {
	// StringValue reads one REG_SZ value under HKLM.
	StringValue(path, name string) (string, bool)
	// SubKeys lists the subkeys of an HKLM key.
	SubKeys(path string) []string
	// LookupAccount resolves a SID to its account and domain names.
	LookupAccount(sid string) (account, domain string, ok bool)
	// SIDForName resolves a user account name (DOMAIN\name or a UPN) to its
	// SID (LookupAccountName), or "".
	SIDForName(name string) string
	// ComputerName is the NetBIOS computer name.
	ComputerName() string
	// DomainJoin reports the NetBIOS and DNS names of the primary AD domain
	// from LSA policy. The computer DNS suffix can differ from this domain.
	DomainJoin() (domain, dnsDomain string, joined bool)
}

// windowsJoinState is the machine's join state: the Entra tenant and the AD
// domain it is joined to, either or both.
type windowsJoinState struct {
	TenantID  string
	ADDomain  string
	DNSDomain string
}

func readWindowsJoinState(r windowsDirectoryReader) windowsJoinState {
	var state windowsJoinState
	for _, thumbprint := range r.SubKeys(cloudJoinInfoKey) {
		if tenant, ok := r.StringValue(cloudJoinInfoKey+`\`+thumbprint, "TenantId"); ok && validTenantID(tenant) {
			state.TenantID = strings.ToLower(strings.TrimSpace(tenant))
			break
		}
	}
	if state.TenantID == "" {
		// Older builds record only TenantInfo\<tenant id>.
		for _, tenant := range r.SubKeys(cloudTenantInfoKey) {
			if validTenantID(tenant) {
				state.TenantID = strings.ToLower(strings.TrimSpace(tenant))
				break
			}
		}
	}
	domain, dnsDomain, adJoined := r.DomainJoin()
	if adJoined {
		state.ADDomain = strings.TrimSpace(domain)
		state.DNSDomain = strings.TrimSpace(dnsDomain)
	}
	return state
}

// identityStoreUPN reads the cloud sign-in UPN and provider recorded for sid.
func identityStoreUPN(r windowsDirectoryReader, sid string) (upn, provider string) {
	key := identityStoreCacheKey + `\` + sid + `\IdentityCache\` + sid
	name, _ := r.StringValue(key, "UserName")
	provider, _ = r.StringValue(key, "ProviderName")
	return NormalizeUPN(name), strings.TrimSpace(provider)
}

// resolveWindowsDirectoryFacts resolves the verified directory facts of sid.
// adUPN, when non-nil, returns the TranslateNameW answer for a SID and
// DOMAIN\account name; it bounds its own wait.
func resolveWindowsDirectoryFacts(
	r windowsDirectoryReader,
	sid string,
	adUPN func(sid, samName string) string,
	now time.Time,
) DirectoryFacts {
	sid = strings.ToUpper(strings.TrimSpace(sid))
	facts := DirectoryFacts{Source: SourceWindowsLSA, Assurance: AssuranceVerified, ResolvedAt: now}
	if !strings.HasPrefix(sid, "S-1-") {
		return DirectoryFacts{}
	}
	join := readWindowsJoinState(r)
	account, domain, ok := r.LookupAccount(sid)
	account = strings.TrimSpace(account)
	if ok {
		facts.AccountDomain = domain
		// While its user signed in with a UPN, the LSA can name an AD
		// account by that UPN; the account's facts (its principal, the UPN
		// lookup) are those of its sAMAccountName whatever the sign-in form
		// (GAP-0533).
		account, _ = canonicalSIDAccountName(sid, domain, account, nil, nil, r.SIDForName)
	}
	upn, provider := identityStoreUPN(r, sid)
	switch {
	case strings.HasPrefix(sid, entraUserSIDPrefix):
		// An Entra ID account (S-1-12-1-...) has no domain account; its UPN
		// is in the identity store.
		facts.Directory = DirectoryEntraID
		if facts.AccountDomain == "" {
			facts.AccountDomain = "AzureAD"
		}
		facts.TenantID = join.TenantID
		if upn != "" {
			facts.UPN = upn
			facts.Source = SourceWindowsIdentityStore
		}
	case ok && strings.EqualFold(domain, r.ComputerName()):
		facts.Directory = DirectoryLocal
	case ok && strings.HasPrefix(sid, "S-1-5-") && !strings.HasPrefix(sid, "S-1-5-21-"):
		// Built-in and service SIDs use pseudo-domains such as NT AUTHORITY.
		facts.Directory = DirectoryLocal
	case ok && domain != "" && strings.HasPrefix(sid, "S-1-5-21-"):
		// The domain is reported in lower case, by its DNS name when it is
		// the machine's own domain, as SSSD and winbind report it on
		// Linux; LookupAccountSid gives only the NetBIOS name.
		facts.Directory = DirectoryActiveDirectory
		facts.Domain = strings.ToLower(domain)
		if upn != "" && strings.EqualFold(provider, entraProviderName) {
			// A hybrid user signed in to Entra: the identity store has the
			// cloud UPN, which is the synced AD UPN.
			facts.UPN = upn
			facts.TenantID = join.TenantID
			facts.Source = SourceWindowsIdentityStore
		} else if adUPN != nil && account != "" {
			facts.UPN = NormalizeUPN(adUPN(sid, domain+`\`+account))
		}
		if join.DNSDomain != "" && strings.EqualFold(domain, join.ADDomain) {
			// LSA identifies the joined AD domain, even when the computer
			// has a disjoint primary DNS suffix.
			facts.Realm = strings.ToUpper(join.DNSDomain)
			facts.Domain = strings.ToLower(join.DNSDomain)
		}
	default:
		return DirectoryFacts{}
	}
	facts.Principal = facts.UPN
	// An @ may be part of the SAM name, so never turn it into a
	// verified principal without the directory translation.
	if facts.Principal == "" && facts.Realm != "" && account != "" && !strings.ContainsRune(account, '@') {
		facts.Principal = AccountPrincipal(account, facts.Realm)
	}
	if facts.Domain == "" && facts.UPN != "" {
		facts.Domain = strings.ToLower(facts.UPN[strings.LastIndexByte(facts.UPN, '@')+1:])
	}
	return facts
}

// validTenantID accepts the GUID-shaped tenant ids the join state records.
func validTenantID(id string) bool {
	id = strings.TrimSpace(id)
	if len(id) < 8 || len(id) > 128 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == '-') {
			return false
		}
	}
	return true
}

const (
	// adUPNTTL stays below the 15-minute directory refresh interval so a
	// UPN-only rename is checked on each refresh even when SID and SAM name
	// remain unchanged.
	adUPNTTL = 5 * time.Minute
	// adUPNFailureTTL is how long a failed lookup (no domain controller
	// reachable) is reused. It is short so a laptop that starts the gateway
	// off the corporate network gets its UPN minutes after it is back, not a
	// day later; the last good answer is kept meanwhile.
	adUPNFailureTTL = 2 * time.Minute
)

// adUPNCache resolves a SID and DOMAIN\account to a UPN with translate, one
// lookup per identity at a time, in the background. A reused account name
// must not inherit the previous SID's verified UPN.
//
// Translations are numbered as they start. An eviction (past 4096 cached
// identities) lets a newer translation of an identity start while an older
// one still runs, and they can finish in any order. The entry holds the
// answer of the newest translation that answered: a newer answer replaces
// an older one, and an older or evicted translation never puts its answer
// back. Only the newest translation started confirms its answer
// (unconfirmed).
type adUPNCache struct {
	translate func(samName string) string
	now       func() time.Time

	mu      sync.Mutex
	entries map[string]adUPNEntry
	// started numbers translations in the order they start. inflight holds,
	// per identity with a translation running, the newest translation
	// started, the newest one that answered, and how many run. Evictions
	// clear entries but not inflight, so every completion knows whether a
	// newer translation started or already answered; the last completion
	// deletes the key, so the map only holds identities being translated.
	started  uint64
	inflight map[string]adUPNFlight
}

type adUPNFlight struct {
	newest, answered uint64
	running          int
}

type adUPNEntry struct {
	upn string
	// kept: upn is an earlier answer that the newest translation, which
	// failed, did not confirm. superseded: upn is the answer of a
	// translation a newer one overtook. Only unconfirmed reads them.
	kept, superseded bool
	expires          time.Time
	done             chan struct{} // open while the newest lookup runs
}

func newADUPNCache(translate func(string) string) *adUPNCache {
	return &adUPNCache{
		translate: translate, now: time.Now,
		entries: map[string]adUPNEntry{}, inflight: map[string]adUPNFlight{},
	}
}

// lookup returns the UPN of samName: the cached answer, or the one a lookup
// started now (or already running) produces within wait. A lookup that takes
// longer returns the previous answer, if any, and finishes in the background.
func (c *adUPNCache) lookup(sid, samName string, wait time.Duration) string {
	key := strings.ToUpper(strings.TrimSpace(sid)) + "\x00" + strings.ToLower(samName)
	c.mu.Lock()
	entry := c.entries[key]
	if entry.done == nil && !c.now().Before(entry.expires) {
		if len(c.entries) > 4096 {
			c.entries = map[string]adUPNEntry{}
			entry = adUPNEntry{}
		}
		c.started++
		flight := c.inflight[key]
		flight.newest, flight.running = c.started, flight.running+1
		c.inflight[key] = flight
		entry.done = make(chan struct{})
		c.entries[key] = entry
		go c.run(key, samName, entry.upn, entry.done, c.started)
	}
	c.mu.Unlock()
	if entry.done == nil || wait <= 0 {
		return entry.upn
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-entry.done:
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.entries[key].upn
	case <-timer.C:
		return entry.upn
	}
}

// run is translation seq of one identity; previous is the answer the entry
// held when it started.
func (c *adUPNCache) run(key, samName, previous string, done chan struct{}, seq uint64) {
	answer := c.translate(samName)
	c.mu.Lock()
	flight := c.inflight[key]
	overtaken, answeredLater := flight.newest > seq, flight.answered > seq
	if answer != "" && !answeredLater {
		flight.answered = seq
	}
	if flight.running--; flight.running > 0 {
		c.inflight[key] = flight
	} else {
		delete(c.inflight, key)
	}
	entry, present := c.entries[key]
	switch {
	case overtaken && (answer == "" || answeredLater):
		// A newer translation started. This one's failure keeps nothing,
		// and its answer never replaces a newer one, also when an eviction
		// has dropped that one meanwhile.
	case overtaken:
		// The newest answer so far, but a newer translation runs or failed:
		// lookup gives it (GAP-0129), never confirmed. The entry keeps that
		// translation's done channel and, after its failure, its retry time.
		expires := c.now().Add(adUPNTTL)
		if present {
			expires = entry.expires
		}
		c.entries[key] = adUPNEntry{upn: answer, superseded: true, expires: expires, done: entry.done}
	case answer != "":
		c.entries[key] = adUPNEntry{upn: answer, expires: c.now().Add(adUPNTTL)}
	default:
		// The newest translation failed: the last good answer stays, the
		// one the entry holds now (an overtaken translation may have
		// answered meanwhile) or else the one it started from.
		if present && entry.upn != "" {
			previous = entry.upn
		}
		c.entries[key] = adUPNEntry{upn: previous, kept: previous != "", expires: c.now().Add(adUPNFailureTTL)}
	}
	c.mu.Unlock()
	close(done)
}

// unconfirmed reports whether upn, an answer lookup gave for the identity,
// is not what its newest translation verified: the last good UPN kept
// through a failed lookup, the answer of a translation a newer one overtook,
// or an answer the cache no longer holds. It changes no answer lookup
// gives; agent identity rows use it to leave such a UPN out (GAP-0129 keeps
// it for profile matching).
func (c *adUPNCache) unconfirmed(sid, samName, upn string) bool {
	key := strings.ToUpper(strings.TrimSpace(sid)) + "\x00" + strings.ToLower(samName)
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entries[key]
	return entry.kept || entry.superseded || entry.upn != upn
}

// Limit Windows account lookups that remain in the OS after their caller's
// budget expires. A domain controller can leave LookupAccountSid stalled; the
// caller must still finish its identity-spool cycle.
var windowsGroupLookupSlots = make(chan struct{}, 8)

func windowsGroupNamesWithLookup(
	sids []string, limit int, budget time.Duration,
	lookup func(string) (account, domain string, ok bool),
) []string {
	deadline := time.Now().Add(budget)
	out := make([]string, 0, len(sids))
	for i, sid := range sids {
		name := ""
		if i < limit && time.Now().Before(deadline) {
			select {
			case windowsGroupLookupSlots <- struct{}{}:
				result := make(chan string, 1)
				go func(sid string) {
					account, domain, ok := lookup(sid)
					<-windowsGroupLookupSlots
					if !ok || account == "" {
						result <- ""
					} else if domain == "" {
						result <- account
					} else {
						result <- domain + `\` + account
					}
				}(sid)
				timer := time.NewTimer(time.Until(deadline))
				select {
				case name = <-result:
				case <-timer.C:
				}
				timer.Stop()
			default:
			}
		}
		if name == "" {
			name = sid
		}
		out = append(out, name)
	}
	return out
}
