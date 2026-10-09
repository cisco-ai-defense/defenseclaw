// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"runtime"
	"strings"
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

// awaitingSpoolUPN marks guardian-backed facts that lack a UPN. On Linux,
// SSSD names the account before the guardian can read InfoPipe; on a managed
// Mac, Open Directory supplies groups even when the guardian record is absent.
// Refresh these answers after the short incomplete lifetime so a restored
// guardian record does not leave a users-by-UPN assignment on the default
// profile for the full directory TTL.
func awaitingSpoolUPN(facts useridentity.DirectoryFacts) bool {
	return currentIdentitySpoolDir() != "" && facts.UPN == "" &&
		(facts.Source == useridentity.SourceSSSD || facts.Source == useridentity.SourceMacOSOpenDirectory)
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

// openDirectoryGroupsUnavailable is the lookup error for the account of
// record whose primary group primaryGID Open Directory may not name, or nil.
// named is asked only for an Active Directory account.
func openDirectoryGroupsUnavailable(record enterprisehooks.IdentitySpoolRecord, primaryGID string, named func(gid string) bool) error {
	if record.Facts.Directory != useridentity.DirectoryActiveDirectory || primaryGID == "" || named(primaryGID) {
		return nil
	}
	return fmt.Errorf("the Mac's Open Directory lists this Active Directory account without its domain groups (its primary group %s has "+
		"no name): the domain controller does not answer, or the Mac still answers from the caches it filled while it did not; "+
		"once the domain controller answers, run sudo dscacheutil -flushcache; sudo dsmemberutil flushcache", primaryGID)
}
