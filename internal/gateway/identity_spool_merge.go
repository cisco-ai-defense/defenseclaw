// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/inventory/ideplugins"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// identitySpoolMaxAge bounds how old a guardian identity record may be. The
// guardian rewrites records every identity cache lifetime; a record several
// lifetimes old belongs to a guardian that stopped, and its UPN may be stale.
// The guardian keeps the record of an account it did not list for as long
// (enterprisehooks.IdentitySpoolMaxAge).
const identitySpoolMaxAge = identityDirectoryMaxAge

// identitySpoolDir is the guardian identity spool the gateway reads, or ""
// when it runs without a guardian (any profile but standalone).
var identitySpoolDir atomic.Value // string

func setIdentitySpoolDir(dir string) { identitySpoolDir.Store(dir) }

func currentIdentitySpoolDir() string {
	dir, _ := identitySpoolDir.Load().(string)
	return dir
}

// awaitingSpool marks facts a gateway that takes account groups from the
// guardian's identity spool (Windows) resolved before the enumerator wrote the
// account's record: they have no groups, which means "not known yet", not "in
// no group". The cache refreshes such facts after identityDirectoryIncompleteTTL
// instead of holding them for the full TTL, so an account's first sign-in
// does not leave it on the default profile for 15 minutes (GAP-0121).
func awaitingSpool(facts useridentity.DirectoryFacts) bool {
	return currentIdentitySpoolDir() != "" && len(facts.Groups) == 0
}

// awaitingSpoolUPN marks guardian-backed facts that are not complete yet, on
// a gateway that takes them from the guardian's identity spool. On Linux,
// SSSD names the account before the guardian can read InfoPipe, so the facts
// lack the UPN (GAP-0334). On a managed Mac, Open Directory supplies groups
// even when the guardian record is absent, and names an Active Directory
// account of a bound Mac without its directory, domain or UPN until the
// guardian's record is merged in; the users entries written as a UPN or
// DOMAIN\name match through them (GAP-0575). Refresh these answers after the
// short incomplete lifetime so a restored guardian record does not leave a
// users-by-UPN assignment on the default profile for the full directory TTL.
// An account the guardian never names keeps refreshing at that pace, which
// costs a directory cache read. Facts its current record was merged into
// await nothing: a local Mac account, or an SSSD account whose directory
// gives no UPN, has none (GAP-0522). Nor does an account the gateway's own
// Open Directory answer proves local (macOSOwnDirectory: of the local node,
// not a mobile copy of a directory account and not linked to Platform SSO):
// it has no UPN to wait for, as agentIdentityAccountUPN already holds. Waiting for one left every UPN or
// DOMAIN\name assignment a maybe for such an account, so a local account
// was refused once any such assignment existed (GAP-0532).
func awaitingSpoolUPN(facts useridentity.DirectoryFacts) bool {
	if currentIdentitySpoolDir() == "" || facts.GuardianRecord {
		return false
	}
	switch facts.Source {
	case useridentity.SourceSSSD:
		return facts.UPN == ""
	case useridentity.SourceMacOSOpenDirectory:
		return facts.Directory == "" || facts.UPNPending || facts.UPN == "" && facts.Directory != useridentity.DirectoryLocal
	}
	return false
}

// spoolRecordNote is the explain note for an account the enumerator has no
// current identity record for. On Windows a group assignment can match only
// through that record, so the answer, usually match=default, is not final.
//
// selected reports that an assignment already chose the profile (a users, SID
// or agent assignment does not need the token groups): the strict default then
// protects nothing here, so the note must not claim it does (GAP-0507).
func spoolRecordNote(id string, now time.Time, selected bool) string {
	if id == "" || currentIdentitySpoolDir() == "" {
		return ""
	}
	if record, ok := readIdentitySpoolFacts(id, now); ok {
		if record.Facts.GroupsPartial {
			return spoolSignedOutNote(selected)
		}
		return ""
	}
	return "the guardian has no identity record for this account yet: its group membership is unknown until the enumerator " +
		"writes one (at the account's first sign-in or its next cycle), so a group assignment cannot match it now and the " +
		"profile above is not final" + spoolRecordSignInHint
}

// spoolSignedOutNote is the note for an account whose desktop session ended:
// group assignments cannot match until it signs in again. The strict default
// is named as the safety net only while no assignment has chosen the profile.
func spoolSignedOutNote(selected bool) string {
	note := "the guardian has no current token groups for this account (it has no active desktop session): " +
		"group assignments cannot match until it signs in again"
	if selected {
		return note + "; the profile above was chosen by an assignment that needs no token groups"
	}
	return note + "; a strict default profile protects this gap"
}

// spoolRecordSignInHint names the sign-in that writes the record on Windows:
// only a desktop session (console or Remote Desktop) does (GAP-0388).
var spoolRecordSignInHint = func() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	return "; on Windows only a desktop sign-in (console or Remote Desktop) writes it, not an SSH, scheduled-task or " +
		"runas session"
}()

// readIdentitySpoolFacts returns the guardian's record for key (a uid or
// SID), when one exists, is trusted and is current.
func readIdentitySpoolFacts(key string, now time.Time) (enterprisehooks.IdentitySpoolRecord, bool) {
	record, state := readIdentitySpoolState(key, now)
	return record, state == identitySpoolCurrent
}

// identitySpoolState is what the gateway finds for an account's guardian
// identity record.
type identitySpoolState int

const (
	// identitySpoolCurrent is a trusted record inside its trust window.
	identitySpoolCurrent identitySpoolState = iota
	// identitySpoolAbsent is no record at all. On Windows the enumerator
	// removed it (the account left its group cache or the enrollment, or a
	// publication it could not complete disproved it, GAP-0329) or never
	// wrote one. On Linux and macOS it is not a withdrawal: the guardian
	// has not written the record yet, or removed one the gateway no longer
	// needs; it withdraws an identity explicitly
	// (identitySpoolWithdrawnAt).
	identitySpoolAbsent
	// identitySpoolUnreadable is a record the gateway cannot use now: a
	// read, parse or trust failure (a sharing violation while the
	// enumerator replaces the file), or a timestamp outside its trust
	// window. It withdraws nothing the record proved before.
	identitySpoolUnreadable
)

// readIdentitySpoolState reads the guardian's record for key and says
// whether it is current, absent or unreadable.
func readIdentitySpoolState(key string, now time.Time) (enterprisehooks.IdentitySpoolRecord, identitySpoolState) {
	dir := currentIdentitySpoolDir()
	if dir == "" {
		return enterprisehooks.IdentitySpoolRecord{}, identitySpoolAbsent
	}
	record, err := enterprisehooks.ReadIdentitySpoolRecord(dir, key, validateManagedGuardianAuthorization)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return enterprisehooks.IdentitySpoolRecord{}, identitySpoolAbsent
	case err != nil || record.UpdatedAt.After(now) || now.Sub(record.UpdatedAt) > identitySpoolMaxAge:
		return enterprisehooks.IdentitySpoolRecord{}, identitySpoolUnreadable
	}
	return record, identitySpoolCurrent
}

// identitySpoolWithdrawnAt is when the Linux or macOS guardian last withdrew
// the identity it had published for the uid key: the uid now names another
// account, the same name in another domain or directory, or a recreated
// account (enterprisehooks.IdentitySpoolWithdrawalSuffix). Zero for none,
// for one the gateway cannot trust, and for one older than
// identitySpoolMaxAge, by when every fact merged from the record it
// withdraws has aged out anyway.
func identitySpoolWithdrawnAt(key string, now time.Time) time.Time {
	dir := currentIdentitySpoolDir()
	if dir == "" {
		return time.Time{}
	}
	at, err := enterprisehooks.ReadIdentitySpoolWithdrawal(dir, key, validateManagedGuardianAuthorization)
	if err != nil || now.Sub(at) > identitySpoolMaxAge {
		return time.Time{}
	}
	return at
}

// identitySpoolSeenAt is the newest guardian record or withdrawal of key a
// lookup starting at now reads (useridentity.DirectoryFacts.SpoolSeenAt).
// It is read before the record itself, so a record the guardian writes
// during the lookup only makes it older: the next request then looks at that
// record once more.
func identitySpoolSeenAt(key string, now time.Time) time.Time {
	seen := identitySpoolWithdrawnAt(key, now)
	if record, ok := readIdentitySpoolFacts(key, now); ok && record.UpdatedAt.After(seen) {
		seen = record.UpdatedAt
	}
	return seen
}

// identitySpoolConnectorEmail is the connector address the enumerator
// published in the current identity record of sid, or "".
func identitySpoolConnectorEmail(sid, connector string) string {
	record, ok := readIdentitySpoolFacts(sid, time.Now())
	if !ok {
		return ""
	}
	return record.ConnectorEmails[connector]
}

// identitySpoolIDEMaxAge bounds how old a published IDE inventory may be: an
// enumerator that stopped publishing leaves the profile to the gateway's own
// scan.
const identitySpoolIDEMaxAge = 24 * time.Hour

// identitySpoolIDEInstalls is the IDE inventory the enumerator published for
// sid, whose profile is home, when its redirected AppData is out of the
// gateway service's reach: a trusted record of that profile, at most
// identitySpoolIDEMaxAge old.
func identitySpoolIDEInstalls(sid, home string) ([]ideplugins.Install, bool) {
	dir := currentIdentitySpoolDir()
	if dir == "" {
		return nil, false
	}
	record, err := enterprisehooks.ReadIDEAppDataSpool(enterprisehooks.IDEAppDataSpoolDir(filepath.Dir(dir)), sid, validateManagedGuardianAuthorization)
	now := time.Now()
	if err != nil || !strings.EqualFold(filepath.Clean(record.Home), filepath.Clean(home)) ||
		record.UpdatedAt.After(now.Add(time.Minute)) || now.Sub(record.UpdatedAt) > identitySpoolIDEMaxAge {
		return nil, false
	}
	return record.Installs, true
}

// identitySpoolAccountName is the DOMAIN\name the SYSTEM enumerator recorded
// for sid in its current identity record, or "". It only spells a name the
// LSA already confirmed for sid (useridentity.SetKnownAccountNameLookup).
func identitySpoolAccountName(sid string) string {
	record, ok := readIdentitySpoolFacts(strings.ToUpper(strings.TrimSpace(sid)), time.Now())
	if !ok {
		return ""
	}
	return strings.TrimSpace(record.User)
}

// readIdentitySpoolFactsForAccount rejects a reused uid's old record. A
// missing name is also unverified; Windows uses the stable SID path above.
// accountSID is the SID the gateway resolved for the uid now ("" for none):
// a record that names another SID is an account recreated under the same
// uid and name, whose UPN is not this one's. The account's own UPN is then
// unknown until the guardian writes its record, so the error makes the
// lookup a failed one (identityFactsUnconfirmedError): a request that a users
// entry written as a UPN could match is refused, naming the upn, and the
// lookup is retried every identityDirectoryRetry, instead of the plain
// default as a verified answer.
func readIdentitySpoolFactsForAccount(key, accountName, accountSID string, now time.Time) (enterprisehooks.IdentitySpoolRecord, bool, error) {
	record, ok := readIdentitySpoolFacts(key, now)
	if !ok || record.User == "" || accountName == "" || !strings.EqualFold(record.User, accountName) {
		return enterprisehooks.IdentitySpoolRecord{}, false, nil
	}
	if record.AccountSID != "" && accountSID != "" && !strings.EqualFold(record.AccountSID, accountSID) {
		return enterprisehooks.IdentitySpoolRecord{}, false, &identityFactsUnconfirmedError{err: fmt.Errorf("the hook guardian's identity "+
			"record for uid %s is of another account under the same uid and name (another SID): this account's UPN is unknown until the "+
			"guardian's next pass writes its record; the lookup is retried every %s", key, identityDirectoryRetry)}
	}
	return record, true, nil
}

// mergeSpoolFacts overlays the guardian's root-resolved record on the facts
// the gateway resolved itself for the same verified account. The spool wins
// for the UPN and principal, which only root can read, and for the realm and
// directory type it resolved with them; the gateway's own answer wins for
// groups, which it resolved just now. When the guardian's InfoPipe lookup by
// uid holds the account in another SSSD domain than the gateway's own facts
// name (record.SSSDDomain), the gateway's domain, realm, principal and
// directory type are another account's, and the spool's replace them even
// where it has none.
func mergeSpoolFacts(own useridentity.DirectoryFacts, record enterprisehooks.IdentitySpoolRecord) useridentity.DirectoryFacts {
	spool := record.Facts
	merged := own
	if record.SSSDDomain != "" && own.Domain != "" && !strings.EqualFold(own.Domain, record.SSSDDomain) &&
		!strings.EqualFold(own.Domain, spool.Domain) {
		merged.Domain, merged.Realm, merged.Principal, merged.Directory, merged.AccountDomain = "", "", "", "", ""
	}
	if spool.UPN != "" {
		merged.UPN = spool.UPN
		// Agent identity rows only; profile matching ignores the mark.
		merged.UPNKept = record.UPNKept()
	}
	if spool.Principal != "" {
		// One principal form per account, whichever guardian build wrote
		// the record (GAP-0259).
		merged.Principal = spool.Principal
		if upn := useridentity.NormalizeUPN(spool.Principal); upn != "" {
			merged.Principal = upn
		}
	}
	if spool.Realm != "" {
		merged.Realm = spool.Realm
	}
	if spool.Domain != "" && merged.Domain == "" {
		merged.Domain = spool.Domain
	}
	if record.AccountDomain != "" && merged.AccountDomain == "" && !strings.ContainsAny(record.AccountDomain, `\/@ `) {
		merged.AccountDomain = record.AccountDomain
	}
	if spool.Directory != "" {
		merged.Directory = spool.Directory
	}
	if spool.TenantID != "" {
		merged.TenantID = spool.TenantID
	}
	if len(merged.Groups) == 0 {
		merged.Groups = spool.Groups
		merged.GroupsPartial = spool.GroupsPartial
	}
	if spool.Source != "" && (spool.UPN != "" || merged.Source == "") {
		merged.Source = spool.Source
	}
	if merged.ResolvedAt.IsZero() {
		merged.ResolvedAt = spool.ResolvedAt
	}
	merged.Assurance = useridentity.AssuranceVerified
	merged.GuardianRecord = true
	return merged
}

// forgetOnSpoolGroupChange drops key's cached facts when the guardian's
// identity record lists another group set than the one they were built
// from. On Windows the groups come from the account's sign-in token: after a
// user signed out and in again the enumerator recorded the new groups at
// once and `profile-explain` showed them, while hooks kept the cached old
// ones for up to 15 more minutes (GAP-1027). A new sign-in now applies at the
// next request, and explain and the hooks agree. A removed record also drops
// cached token groups before the next request makes a policy decision.
func forgetOnSpoolGroupChange(cache *identityDirectoryCache, key string, now time.Time) {
	forgetOnSpoolChange(cache, key, now, true)
}

// forgetOnSpoolChange drops key's cached facts when the guardian's record
// contradicts them or the guardian withdrew them. A record that is there but
// cannot be read now withdraws nothing: the facts it proved stay, bounded by
// their lifetime and the record's trust window (identitySpoolTrustedUntil),
// as cached facts stay through a directory outage. Dropping them on such a
// miss let the next request resolve without the record and select the
// outage default, which can be weaker than the assignment the facts select.
//
// On Windows (checkGroups) the record is the only source of an account's
// token groups, so a record that is gone ends the cached groups: the
// enumerator removes it when the account left its group cache or the
// enrollment, or when it could not publish groups that changed (GAP-0329).
// The next lookup has no groups and takes the outage path: a request whose
// assignments need the groups is refused, naming them; others get the
// proven or default profile (default_lookup_failed).
//
// On Linux and macOS the gateway resolves the account's groups and SID
// through NSS itself and takes only the UPN and its realm from the record.
// A missing record is no withdrawal there: before the guardian's first
// record, an NSS-verified account's facts were dropped at every request,
// and a slow directory then refused its requests or sent it to a possibly
// weaker default_lookup_failed profile; a record without a SID dropped them at
// every request too (loop round 3). The guardian withdraws an identity
// explicitly instead (identitySpoolWithdrawnAt), and a withdrawal written
// after the facts were resolved drops them. A current record drops them
// when it names another SID or another UPN than they do; a fact either one
// lacks contradicts nothing. A record that adds to them (a UPN) refreshes
// them in place (refreshSoon): they stay if the refresh fails. Each record
// and withdrawal is acted on once: the facts note the newest one their
// lookup read (useridentity.DirectoryFacts.SpoolSeenAt).
func forgetOnSpoolChange(cache *identityDirectoryCache, key string, now time.Time, checkGroups bool) {
	if cache == nil || key == "" || currentIdentitySpoolDir() == "" {
		return
	}
	cached, _, ok := cache.peek(key)
	if !ok {
		return
	}
	record, state := readIdentitySpoolState(key, now)
	if checkGroups {
		switch {
		case state == identitySpoolUnreadable:
		case state == identitySpoolAbsent:
			if len(cached.Groups) > 0 {
				cache.forget(key)
			}
		case cached.GroupsPartial != record.Facts.GroupsPartial || !sameGroupSet(cached.Groups, record.Facts.Groups):
			cache.forget(key)
		}
		return
	}
	if withdrawn := identitySpoolWithdrawnAt(key, now); withdrawn.After(cached.SpoolSeenAt) {
		cache.forget(key)
		return
	}
	if state != identitySpoolCurrent || !record.UpdatedAt.After(cached.SpoolSeenAt) {
		return
	}
	switch {
	case spoolRecordContradicts(cached, record):
		cache.forget(key)
	case spoolRecordAddsFacts(cached, record):
		cache.refreshSoon(key)
	}
}

// spoolRecordContradicts reports whether a guardian record names another
// directory identity than the cached facts: another SID than the one SSSD
// gave for the uid, or another UPN. A fact that either side lacks
// contradicts nothing.
func spoolRecordContradicts(cached useridentity.DirectoryFacts, record enterprisehooks.IdentitySpoolRecord) bool {
	differ := func(a, b string) bool {
		a, b = strings.TrimSpace(a), strings.TrimSpace(b)
		return a != "" && b != "" && !strings.EqualFold(a, b)
	}
	return differ(cached.AccountSID, record.AccountSID) || differ(cached.UPN, record.Facts.UPN)
}

// spoolRecordAddsFacts reports whether merging record would change the
// identity facts the cached ones name.
func spoolRecordAddsFacts(cached useridentity.DirectoryFacts, record enterprisehooks.IdentitySpoolRecord) bool {
	merged := mergeSpoolFacts(cached, record)
	return merged.UPN != cached.UPN || merged.Principal != cached.Principal || merged.Realm != cached.Realm ||
		merged.Domain != cached.Domain || merged.AccountDomain != cached.AccountDomain || merged.Directory != cached.Directory ||
		merged.TenantID != cached.TenantID
}

// sameGroupSet compares two group lists as sets, ignoring case and order.
func sameGroupSet(a, b []string) bool {
	set := make(map[string]bool, len(a))
	for _, group := range a {
		set[strings.ToLower(strings.TrimSpace(group))] = true
	}
	other := make(map[string]bool, len(b))
	for _, group := range b {
		group = strings.ToLower(strings.TrimSpace(group))
		if !set[group] {
			return false
		}
		other[group] = true
	}
	return len(other) == len(set)
}

// UPN assignments the identity records cannot back.
//
// On standalone Linux the UPN of an SSSD account comes only from the
// guardian's record, which reads it from InfoPipe. When InfoPipe stops
// reporting userPrincipalName (the [ifp] user_attributes of sssd.conf lost
// it), a users entry written as a UPN selects nobody: the guardian keeps a UPN
// it verified before (enterprisehooks.KeepVerifiedInfoPipeUPN), but an account
// it never had one for is recorded with the derived account@REALM, and the
// entry falls to the default profile with no other sign (GAP-1114).
// upnAssignmentWarnings says so in explain, status, verify and the gateway
// log, naming the likely cause, whenever the assignments write a users entry
// as a UPN.

// upnAssignmentRecordsMax bounds the records one check reads.
const upnAssignmentRecordsMax = 512

// upnAssignmentNamed bounds the uids and entries one warning names.
const upnAssignmentNamed = 8

const upnAssignmentRemedy = "check that user_attributes in the [ifp] section of sssd.conf lists +userPrincipalName " +
	"(and ldap_user_extra_attrs maps it for an LDAP domain), then restart sssd"

func upnAssignmentWarnings(assignments []config.ProfileAssignment, records []enterprisehooks.IdentitySpoolRecord, now time.Time) []string {
	type upnEntry struct {
		assignment int
		entry      string
	}
	var entries []upnEntry
	for i, assignment := range assignments {
		for _, entry := range assignment.Match.Users {
			if entry = strings.TrimSpace(entry); strings.Contains(entry, "@") && !strings.Contains(entry, `\`) {
				entries = append(entries, upnEntry{i + 1, entry})
			}
		}
	}
	if len(entries) == 0 {
		return nil
	}
	var kept, derived []string
	var current []enterprisehooks.IdentitySpoolRecord
	for _, record := range records {
		if record.UpdatedAt.After(now) || now.Sub(record.UpdatedAt) > identitySpoolMaxAge {
			continue
		}
		current = append(current, record)
		switch record.UPNSource {
		case enterprisehooks.UPNSourceInfoPipeKept:
			kept = append(kept, record.Key)
		case enterprisehooks.UPNSourceDerived:
			derived = append(derived, record.Key)
		}
	}
	uids := func(keys []string) string {
		named := keys
		if len(named) > upnAssignmentNamed {
			named = named[:upnAssignmentNamed]
		}
		list := "uid " + strings.Join(named, ", uid ")
		if more := len(keys) - len(named); more > 0 {
			list += fmt.Sprintf(" and %d more", more)
		}
		return list
	}
	var warnings []string
	if len(kept) > 0 {
		warnings = append(warnings, fmt.Sprintf("SSSD InfoPipe answers without userPrincipalName for %d account(s) (%s), so the guardian "+
			"keeps the UPN it read before; an account without one gets none, and a users entry written as its UPN selects nobody: %s",
			len(kept), uids(kept), upnAssignmentRemedy))
	}
	if len(derived) == 0 {
		return warnings
	}
	var unmatched []string
	for _, e := range entries {
		matched := false
		for _, record := range current {
			if useridentity.PrincipalsEqual(record.Facts.UPN, e.entry) || useridentity.PrincipalsEqual(record.Facts.Principal, e.entry) ||
				useridentity.EqualFold(record.User, e.entry) {
				matched = true
				break
			}
		}
		if !matched {
			unmatched = append(unmatched, fmt.Sprintf("assignment %d: user %q", e.assignment, e.entry))
		}
	}
	if len(unmatched) == 0 {
		return warnings
	}
	count := len(unmatched)
	if count > upnAssignmentNamed {
		unmatched = append(unmatched[:upnAssignmentNamed:upnAssignmentNamed], fmt.Sprintf("%d more", count-upnAssignmentNamed))
	}
	return append(warnings, fmt.Sprintf("%d users entry(ies) written as a UPN (%s) match no account of this host's identity records, "+
		"and SSSD InfoPipe reports no userPrincipalName for %d account(s) (%s): an account such an entry means gets the default "+
		"profile; %s", count, strings.Join(unmatched, ", "), len(derived), uids(derived), upnAssignmentRemedy))
}

// spoolUPNAssignmentWarnings runs upnAssignmentWarnings over the guardian
// records of a standalone Linux gateway.
func spoolUPNAssignmentWarnings(assignments []config.ProfileAssignment, now time.Time) []string {
	dir := currentIdentitySpoolDir()
	if runtime.GOOS != "linux" || dir == "" || len(assignments) == 0 {
		return nil
	}
	return upnAssignmentWarnings(assignments, enterprisehooks.ReadIdentitySpoolRecords(dir, validateManagedGuardianAuthorization,
		upnAssignmentRecordsMax), now)
}

// A bound Mac whose domain controller does not answer.
//
// Open Directory then answers at once and without an error, but lists an
// Active Directory account without its domain groups: its primary group
// (Domain Users) is left as a bare number and its other domain groups are
// gone. The account's facts looked resolved, so a user a groups assignment
// selects silently got the default profile, nothing warned, and it stayed
// there after the domain controller was back until the Open Directory caches
// were flushed (GAP-1106). An account the guardian records as Active
// Directory whose primary group has no name is therefore a failed lookup: the
// gateway keeps the facts it cached (for up to an hour), status and verify
// warn directory_lookups_failing, and the reason names the flush.

//
// A mobile account keeps the name of its primary group through an outage,
// though, and lost only its other domain groups: the user got the default
// profile as "default", explain called its assignment group renamed or
// deleted, a new sandbox run was refused as a policy change, and the facts
// held for the full 15 minutes after the domain controller answered again
// (GAP-0496, GAP-0517). Open Directory itself lists the domain's node Offline
// then (odutil show nodenames), so an Active Directory account's lookup also
// fails while it does: requests keep the facts cached before the outage (for
// up to an hour; then a request whose assignments need the directory facts
// is refused, naming the missing fact, and others get default_lookup_failed,
// provisional for sandboxes), and
// a lookup is retried every 15 s. Right after the outage Open Directory may
// still list the account without its groups for a minute or two, so facts
// resolved within openDirectorySettleWindow of the node last seen offline are
// refreshed every 15 s (openDirectorySettling) instead of held for 15 minutes.
//
// Open Directory does not always list the node Offline: on a Mac whose
// domain controller was blocked for an hour the node stayed Online, and
// about 20 minutes in the accounts lost their other domain groups with
// their primary group still named, so they got the default profile as a
// verified "default" (GAP-0092). The root guardian checks the domain
// controllers itself and lists the domains whose domain controllers stopped
// answering (enterprisehooks.DirectoryUnreachableFile); an Active Directory
// account of such a domain is a failed lookup too (unreachable).

// openDirectorySettleWindow is how long after the node was last seen offline
// an answer is refreshed at the retry pace.
const openDirectorySettleWindow = 5 * time.Minute

// openDirectoryOfflineAt is when a lookup last found the directory away
// (Unix nanoseconds), 0 when never: the Active Directory node of a Mac
// offline or its domain controllers not answering, or SSSD offline for the
// domain of a Linux account (sssdGroupsUnavailable).
var openDirectoryOfflineAt atomic.Int64

// openDirectorySettling marks Open Directory and SSSD facts resolved shortly
// after the directory was last seen away.
func openDirectorySettling(facts useridentity.DirectoryFacts) bool {
	at := openDirectoryOfflineAt.Load()
	if at == 0 || facts.ResolvedAt.IsZero() {
		return false
	}
	switch facts.Source {
	case useridentity.SourceMacOSOpenDirectory, useridentity.SourceSSSD, useridentity.SourceSSSDInfoPipe:
	default:
		return false
	}
	since := facts.ResolvedAt.Sub(time.Unix(0, at))
	return since >= 0 && since < openDirectorySettleWindow
}

// openDirectoryGroupsUnavailable is the lookup error for an Active Directory
// account whose domain groups Open Directory cannot list now, or nil: the
// domain's node is offline (offline), or its primary group primaryGID has no
// name (named). directory says the account is an Active Directory one: the
// guardian's record says so (record), or, without a record, the account is
// not one of the local node (a mobile account is not, GAP-0496). A failure is
// noted for openDirectorySettling; without a current record on a managed Mac
// it also ends the facts cached before it (identityFactsUnconfirmedError).
//
// The unnamed primary group is read with or without the guardian's record.
// The record is trusted for an hour (identitySpoolMaxAge), so a Mac whose
// domain controller stayed away longer lost it exactly when Open Directory's
// own caches ran out (about 45 minutes in): the account then showed its
// primary group as a bare number, the lookup stopped failing, and the account
// moved to the default profile as plain "default", not default_lookup_failed,
// while a new sandbox run was refused as a policy change (GAP-0496, GAP-0517).
//
// unreachable reports whether the guardian lists the domain (lower case; ""
// for an account without a record, whose domain is unknown: any domain) as
// having no domain controller that answers.
func openDirectoryGroupsUnavailable(record *enterprisehooks.IdentitySpoolRecord, localNode bool, primaryGID string, named func(gid string) bool,
	offline func() bool, unreachable func(domain string) bool, now time.Time) error {
	if record != nil && record.Facts.Directory != useridentity.DirectoryActiveDirectory || record == nil && localNode {
		return nil
	}
	domain := ""
	if record != nil {
		domain = strings.ToLower(strings.TrimSpace(record.Facts.Domain))
	}
	var err error
	switch {
	case offline != nil && offline():
		err = fmt.Errorf("the Mac's Open Directory lists its Active Directory node offline (odutil show nodenames): the domain "+
			"controller does not answer, so this account's domain groups are unknown; the lookup is retried every %s", identityDirectoryRetry)
	case unreachable != nil && unreachable(domain):
		label := domain
		if label == "" {
			label = "the account's Active Directory domain"
		}
		err = fmt.Errorf("the hook guardian finds no domain controller of %s that answers (it checks every 15 seconds while one is "+
			"away), so this account's domain groups are unknown; the lookup is retried every %s", label, identityDirectoryRetry)
	case primaryGID != "" && !named(primaryGID):
		err = fmt.Errorf("the Mac's Open Directory lists this directory account without its domain groups (its primary group %s has "+
			"no name): the domain controller does not answer, or the Mac still answers from the caches it filled while it did not; "+
			"once the domain controller answers, run sudo dscacheutil -flushcache; sudo dsmemberutil flushcache", primaryGID)
	default:
		return nil
	}
	openDirectoryOfflineAt.Store(now.UnixNano())
	if record == nil && currentIdentitySpoolDir() != "" {
		// The guardian has not confirmed the account for identitySpoolMaxAge:
		// its own lookups fail while the domain controller does not answer,
		// and its record ages out. Open Directory answered from its caches
		// until now, so the facts cached from those answers are no older
		// than a few minutes, and keeping them for another hour left the
		// account on its group profile almost two hours into an outage, or
		// (with explain refreshing them) on plain "default". They go now:
		// requests whose assignments need the directory facts are refused,
		// naming the missing fact; others get the proven or default profile
		// (default_lookup_failed, provisional for sandboxes) (GAP-0496,
		// GAP-0517).
		return &identityFactsUnconfirmedError{err: fmt.Errorf("the facts cached before are no longer used: the hook guardian has not "+
			"confirmed this account for %s, and %w", identitySpoolMaxAge, err)}
	}
	return err
}

// An SSSD account of a Linux host whose directory does not answer.
//
// SSSD then answers from its cache, without an error: for an account whose
// memberships it looked up before, the memberships it cached; for one it
// never looked them up for (a first sign-in during the outage, or a cleared
// cache), the primary group alone. The gateway took that answer as verified
// facts: the account got the default profile as plain "default", status and
// verify did not warn, a new sandbox started without the provisional note,
// and the facts were kept for 15 minutes after SSSD was back online
// (GAP-0191). The root guardian asks SSSD whether it is online for each
// enrolled account's SSSD domain and lists the offline ones in the identity
// spool (enterprisehooks.DirectoryUnreachableFile). An SSSD account of such
// a domain that SSSD lists with its primary group only
// (useridentity.DirectoryFacts.OnlyPrimaryGroup) is a failed lookup: requests
// whose assignments need its groups are refused, naming them, and others get
// default_lookup_failed (provisional sandboxes); status and verify warn
// directory_lookups_failing, and the lookup is retried every 15 seconds.
// When SSSD is online again the guardian flushes SSSD's caches and removes
// the domain from the list, so the next lookup gets the account's groups.
