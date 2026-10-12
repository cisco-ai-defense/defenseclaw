// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
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
// costs a directory cache read.
func awaitingSpoolUPN(facts useridentity.DirectoryFacts) bool {
	if currentIdentitySpoolDir() == "" {
		return false
	}
	switch facts.Source {
	case useridentity.SourceSSSD:
		return facts.UPN == ""
	case useridentity.SourceMacOSOpenDirectory:
		return facts.UPN == "" || facts.Directory == ""
	}
	return false
}

// spoolRecordNote is the explain note for an account the enumerator has no
// current identity record for. On Windows a group assignment can match only
// through that record, so the answer, usually match=default, is not final.
func spoolRecordNote(id string, now time.Time) string {
	if id == "" || currentIdentitySpoolDir() == "" {
		return ""
	}
	if record, ok := readIdentitySpoolFacts(id, now); ok {
		if record.Facts.GroupsPartial {
			return "the guardian has no current token groups for this account (it has no active desktop session): " +
				"group assignments cannot match until it signs in again; a strict default profile protects this gap"
		}
		return ""
	}
	return "the guardian has no identity record for this account yet: its group membership is unknown until the enumerator " +
		"writes one (at the account's first sign-in or its next cycle), so a group assignment cannot match it now and the " +
		"profile above is not final" + spoolRecordSignInHint
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
	dir := currentIdentitySpoolDir()
	if dir == "" {
		return enterprisehooks.IdentitySpoolRecord{}, false
	}
	record, err := enterprisehooks.ReadIdentitySpoolRecord(dir, key, validateManagedGuardianAuthorization)
	if err != nil || record.UpdatedAt.After(now) || now.Sub(record.UpdatedAt) > identitySpoolMaxAge {
		return enterprisehooks.IdentitySpoolRecord{}, false
	}
	return record, true
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
func readIdentitySpoolFactsForAccount(key, accountName string, now time.Time) (enterprisehooks.IdentitySpoolRecord, bool) {
	record, ok := readIdentitySpoolFacts(key, now)
	if !ok || record.User == "" || accountName == "" || !strings.EqualFold(record.User, accountName) {
		return enterprisehooks.IdentitySpoolRecord{}, false
	}
	return record, true
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
	return merged
}

// spoolGroupsCheckInterval is how often a request re-reads an account's
// guardian identity record to see whether its group set changed.
const spoolGroupsCheckInterval = 5 * time.Second

var spoolGroupChecks struct {
	sync.Mutex
	at map[string]time.Time
}

// forgetOnSpoolGroupChange drops key's cached facts when the guardian's
// identity record lists another group set than the one they were built
// from. On Windows the groups come from the account's sign-in token: after a
// user signed out and in again the enumerator recorded the new groups at
// once and `profile-explain` showed them, while hooks kept the cached old
// ones for up to 15 more minutes (GAP-1027). A new sign-in now applies at the
// next request, and explain and the hooks agree. The record is read at most
// every spoolGroupsCheckInterval per account.
func forgetOnSpoolGroupChange(cache *identityDirectoryCache, key string, now time.Time) {
	if cache == nil || key == "" || currentIdentitySpoolDir() == "" {
		return
	}
	cached, _, ok := cache.peek(key)
	if !ok {
		return
	}
	spoolGroupChecks.Lock()
	if last, seen := spoolGroupChecks.at[key]; seen && now.Sub(last) >= 0 && now.Sub(last) < spoolGroupsCheckInterval {
		spoolGroupChecks.Unlock()
		return
	}
	if spoolGroupChecks.at == nil || len(spoolGroupChecks.at) >= identityDirectoryMax {
		spoolGroupChecks.at = map[string]time.Time{}
	}
	spoolGroupChecks.at[key] = now
	spoolGroupChecks.Unlock()
	record, ok := readIdentitySpoolFacts(key, now)
	if !ok {
		return
	}
	if cached.GroupsPartial != record.Facts.GroupsPartial || !sameGroupSet(cached.Groups, record.Facts.Groups) {
		cache.forget(key)
	}
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
// up to an hour, then default_lookup_failed, provisional for sandboxes), and
// a lookup is retried every 15 s. Right after the outage Open Directory may
// still list the account without its groups for a minute or two, so facts
// resolved within openDirectorySettleWindow of the node last seen offline are
// refreshed every 15 s (openDirectorySettling) instead of held for 15 minutes.

// openDirectorySettleWindow is how long after the node was last seen offline
// an answer is refreshed at the retry pace.
const openDirectorySettleWindow = 5 * time.Minute

// openDirectoryOfflineAt is when a lookup last found the Active Directory
// node offline (Unix nanoseconds), 0 when never.
var openDirectoryOfflineAt atomic.Int64

// openDirectorySettling marks Open Directory facts resolved shortly after the
// Active Directory node was last seen offline.
func openDirectorySettling(facts useridentity.DirectoryFacts) bool {
	at := openDirectoryOfflineAt.Load()
	if at == 0 || facts.Source != useridentity.SourceMacOSOpenDirectory || facts.ResolvedAt.IsZero() {
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
func openDirectoryGroupsUnavailable(record *enterprisehooks.IdentitySpoolRecord, localNode bool, primaryGID string, named func(gid string) bool,
	offline func() bool, now time.Time) error {
	if record != nil && record.Facts.Directory != useridentity.DirectoryActiveDirectory || record == nil && localNode {
		return nil
	}
	var err error
	switch {
	case offline != nil && offline():
		err = fmt.Errorf("the Mac's Open Directory lists its Active Directory node offline (odutil show nodenames): the domain "+
			"controller does not answer, so this account's domain groups are unknown; the lookup is retried every %s", identityDirectoryRetry)
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
		// directory-dependent assignments use default_lookup_failed and
		// sandboxes start provisional (GAP-0496, GAP-0517).
		return &identityFactsUnconfirmedError{err: fmt.Errorf("the facts cached before are no longer used: the hook guardian has not "+
			"confirmed this account for %s, and %w", identitySpoolMaxAge, err)}
	}
	return err
}
