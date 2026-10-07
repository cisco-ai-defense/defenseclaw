// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"sync/atomic"
	"time"

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

// awaitingSpoolUPN marks the facts of an SSSD account on a gateway that takes
// the UPN from the guardian's identity spool (standalone Linux) while they
// carry none: the guardian reads InfoPipe after the reconcile that enrolls the
// account, which is often after the account's first request. Held for the
// full TTL, those facts recorded the principal as sAMAccountName@REALM for up
// to 15 minutes and then as the UPN (GAP-0334); refreshed after the short
// incomplete lifetime, the UPN appears within about two minutes of the
// guardian's record. An account InfoPipe never names keeps refreshing at
// that pace, which costs an SSSD cache read.
func awaitingSpoolUPN(facts useridentity.DirectoryFacts) bool {
	return currentIdentitySpoolDir() != "" && facts.Source == useridentity.SourceSSSD && facts.UPN == ""
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
			return "the guardian identity record lists the groups of this account's last signed-in session (it has no active " +
				"session now): a group it has gained since counts only after it signs in again, so the profile above is not final"
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
	if err != nil || now.Sub(record.UpdatedAt) > identitySpoolMaxAge {
		return enterprisehooks.IdentitySpoolRecord{}, false
	}
	return record, true
}

// mergeSpoolFacts overlays the guardian's root-resolved facts on the facts
// the gateway resolved itself for the same verified account. The spool wins
// for the UPN and principal, which only root can read, and for the realm and
// directory type it resolved with them; the gateway's own answer wins for
// groups, which it resolved just now.
func mergeSpoolFacts(own, spool useridentity.DirectoryFacts) useridentity.DirectoryFacts {
	merged := own
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
