// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
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
// for what only root can read (UPN, principal, realm, directory type); the
// gateway's own answer wins for groups, which it resolved just now.
func mergeSpoolFacts(own, spool useridentity.DirectoryFacts) useridentity.DirectoryFacts {
	merged := own
	if spool.UPN != "" {
		merged.UPN = spool.UPN
	}
	if spool.Principal != "" {
		merged.Principal = spool.Principal
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
