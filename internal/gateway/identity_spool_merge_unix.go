// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

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
