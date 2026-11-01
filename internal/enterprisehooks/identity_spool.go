// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// The identity spool.
//
// Some verified directory facts can only be read with privilege: SSSD
// InfoPipe answers root only, the gateway's sandbox hides /proc and user
// homes, and on Windows the token-group cache is SYSTEM-only. The root
// guardian (Linux, macOS) or SYSTEM enumerator (Windows) resolves them for
// each enrolled account and writes one record per account, <uid>.json or
// <SID>.json, in the identity directory under the guardian authorization
// directory: owned by root or SYSTEM and readable by the gateway's group,
// exactly like the AI discovery user-scan spool. The gateway merges a record
// into the facts it resolves itself for the same verified uid or SID.

// IdentitySpoolDirName is the spool directory under the guardian
// authorization directory.
const IdentitySpoolDirName = "identity"

// IdentitySpoolRecordVersion is the record schema version.
const IdentitySpoolRecordVersion = 1

// IdentitySpoolMaxAge is how long the gateway trusts a record (four times the
// 15 minute identity cache lifetime) and how long the guardian keeps the
// record of an account it no longer lists.
const IdentitySpoolMaxAge = time.Hour

// IdentitySpoolKeptUPNMaxAge is how long the guardian keeps a UPN that SSSD
// InfoPipe stopped reporting (KeepVerifiedInfoPipeUPN). Kept without a
// bound, a UPN removed in the directory selected that account's UPN
// profile indefinitely (GAP-1235); a day gives the administrator the status
// and verify warnings of an [ifp] section that lost userPrincipalName
// (GAP-1114) before the accounts fall to the profile their other facts
// select.
const IdentitySpoolKeptUPNMaxAge = 24 * time.Hour

// maxIdentitySpoolRecordBytes bounds one record.
const maxIdentitySpoolRecordBytes = 256 << 10

// UPN sources recorded in IdentitySpoolRecord.UPNSource.
const (
	UPNSourceInfoPipe = "infopipe"
	// UPNSourceInfoPipeKept is a UPN an earlier pass read from InfoPipe,
	// kept because the latest InfoPipe answer for the same account listed no
	// userPrincipalName (KeepVerifiedInfoPipeUPN).
	UPNSourceInfoPipeKept  = "infopipe_kept"
	UPNSourceDerived       = "derived"
	UPNSourceIdentityStore = "identity_store"
	UPNSourceTranslateName = "translate_name"
)

// IdentitySpoolRecord is one account's spool file.
type IdentitySpoolRecord struct {
	Version int `json:"version"`
	// Key is the uid (Linux, macOS) or SID (Windows) the record is for; it
	// must match the file name.
	Key       string    `json:"key"`
	User      string    `json:"user,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
	// UPNSource says where Facts.UPN, or the derived Facts.Principal, came
	// from: infopipe, identity_store, translate_name, or derived (the
	// sAMAccountName@REALM fallback; Facts.UPN is then empty).
	UPNSource string `json:"upn_source,omitempty"`
	// UPNKeptSince is when the guardian first kept an InfoPipe UPN that
	// InfoPipe no longer reported (UPNSource infopipe_kept): the UPN goes
	// once it is IdentitySpoolKeptUPNMaxAge old. On Windows it is when the
	// guardian first kept the last known UPN of a pass that did not verify
	// one (MarkWindowsKeptUPN); the UPN stays for profile matching
	// (GAP-0129, GAP-0284) and UPNSource keeps naming the lookup that
	// verified it. The gateway leaves a kept UPN out of agent identity rows.
	UPNKeptSince time.Time `json:"upn_kept_since,omitzero"`
	// AccountSID is the SID SSSD holds for the uid (Linux), the account's
	// immutable directory identifier; empty for an account without one. An
	// account recreated under the same uid, name and SSSD domain has another
	// SID, so the facts an earlier record carries are another account's:
	// the guardian keeps none of them for it (KeepVerifiedInfoPipeUPN,
	// identitySpoolSameIdentity) and the gateway does not use the record.
	// It is written in the record's extension (identitySpoolRecordExtension),
	// not in the record object, which the 1.0.3 and older gateways decode
	// with unknown fields refused.
	AccountSID string `json:"-"`
	// LegacyOwnerToken is the root guardian's home or SID proof for the
	// pre-1.0.4 agents migration map. The gateway service cannot stat a
	// private home under ProtectHome=yes. It lives in the extension so an
	// older gateway can still read the first record object on rollback.
	LegacyOwnerToken string `json:"-"`
	// AccountsStamp is the LocalAccountsStamp the guardian read before the
	// pass that wrote LegacyOwnerToken (Linux): the gateway takes the home
	// proof for the uid's holder only while it is the current stamp, so a
	// clock step or a change during the pass does not make it current or
	// stale by wall-clock time (GAP-2025). In the extension; records 1.0.4
	// wrote carry none.
	AccountsStamp string `json:"-"`
	// SSSDDomain is the SSSD domain that holds the uid by InfoPipe
	// Users.FindByID (Linux): the gateway drops a domain, realm and
	// principal of its own that name another domain (mergeSpoolFacts).
	SSSDDomain string `json:"sssd_domain,omitempty"`
	// AccountIncarnation is the unixidentity.AccountIncarnation of the
	// account the record was resolved for (Linux): the SID SSSD holds for
	// its uid, or the NSS service that answers the uid. A uid handed from
	// one account to another of the same name keeps its key and name, so
	// the gateway lays a record only over the facts of the account whose
	// incarnation it names (review of GAP-0551). Records an older guardian
	// wrote carry none, and are not laid over any account's facts until the
	// guardian writes them again (at its first pass after it starts).
	AccountIncarnation string `json:"account_incarnation,omitempty"`
	// AccountDomain is the account's DOMAIN\user namespace (its NetBIOS
	// domain, macOS), which DirectoryFacts never serializes: profile
	// matching alone reads it (GAP-0635).
	AccountDomain string                      `json:"account_domain,omitempty"`
	Facts         useridentity.DirectoryFacts `json:"facts"`
	// ConnectorEmails maps "claudecode" and "codex" to the account address
	// the SYSTEM enumerator read from that connector's file in the
	// account's own profile, while ai_discovery.include_user_email is on
	// (Windows). The gateway service cannot read Claude Code's file, which
	// lives in the profile root (GAP-1025).
	ConnectorEmails map[string]string `json:"connector_emails,omitempty"`
}

// identitySpoolRecordExtension holds the facts a record carries that the
// gateways and guardians of 1.0.3 and older do not know. They decode the
// record object with unknown fields refused, so a new field in it made a
// gateway still running beside an upgraded guardian (during the package
// upgrade, or after a rollback) drop every record that had one, and an
// account assigned by the UPN only the record holds fell to the default
// profile. The extension is a second JSON object after the record object
// in the same file, written in the same atomic replace: those builds read
// the first object only and stop there. It is decoded without refusing
// unknown fields, so a later build can add facts to it the same way.
type identitySpoolRecordExtension struct {
	AccountSID       string `json:"account_sid,omitempty"`
	LegacyOwnerToken string `json:"legacy_owner_token,omitempty"`
	AccountsStamp    string `json:"accounts_stamp,omitempty"`
}

// identitySpoolClockSlack is how far in the future a record may be dated
// before the wall clock counts as stepped back.
const identitySpoolClockSlack = time.Minute

// IdentitySpoolStale reports whether the records in dir look older than
// fresh to a reader of the wall clock: any record is older than fresh, or
// dated more than a minute in the future. The gateway trusts a
// record by its wall-clock age, so after a clock step (an NTP correction, a
// resume from suspend) every record looked over an hour old, or the records
// written under a slow clock did once it was corrected, and the accounts
// assigned by UPN fell to the default profile until the guardian's next
// interval (GAP-0921). oldest is the time of the oldest record, zero for
// none, and key its uid or SID; when only a record dated in the future makes
// the spool stale, they are that record's time and key instead, so the
// account named is the one at fault (GAP-1116).
func IdentitySpoolStale(dir string, now time.Time, fresh time.Duration) (oldest time.Time, key string, stale bool) {
	if dir == "" {
		return time.Time{}, "", false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return time.Time{}, "", false
	}
	var futureAt time.Time
	futureKey := ""
	for _, entry := range entries {
		name, ok := strings.CutSuffix(entry.Name(), ".json")
		// Only the accounts' records count: the guardian's other files
		// (DirectoryUnreachableFile) are rewritten or removed on their own.
		if entry.IsDir() || !ok || !validIdentitySpoolKey(name) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		written := info.ModTime()
		if oldest.IsZero() || written.Before(oldest) {
			oldest, key = written, name
		}
		if written.Sub(now) > identitySpoolClockSlack && (futureKey == "" || written.After(futureAt)) {
			futureAt, futureKey = written, name
		}
	}
	switch {
	case oldest.IsZero():
		return time.Time{}, "", false
	case now.Sub(oldest) > fresh:
		return oldest, key, true
	case futureKey != "":
		return futureAt, futureKey, true
	}
	return oldest, key, false
}

// IdentitySpoolDir is the spool directory for a guardian authorization
// directory.
func IdentitySpoolDir(authorizationDir string) string {
	if strings.TrimSpace(authorizationDir) == "" {
		return ""
	}
	return filepath.Join(authorizationDir, IdentitySpoolDirName)
}

// ReadIdentitySpoolRecord reads the record for key from dir. trust validates
// the file (root- or SYSTEM-owned, not writable by others) before it is
// opened. A missing record is os.ErrNotExist.
func ReadIdentitySpoolRecord(dir, key string, trust func(path, label string) error) (IdentitySpoolRecord, error) {
	return readIdentitySpoolFile(dir, key, ".json", "identity spool record", trust)
}

// IdentitySpoolWithdrawalSuffix names the file, <uid>.withdrawn, in which the
// Linux or macOS guardian withdraws the identity it published for a uid
// that now names another account: another name, the same name in another
// domain or directory, or a recreated account (WriteIdentitySpool). A
// missing record is no withdrawal: it is also missing before the guardian
// first writes it, and the gateway keeps the facts it verified itself
// through that. A withdrawal is written like a record, root-owned and
// readable by the gateway's group, and holds only the uid and its time; the
// gateway drops the facts it cached for the uid before that time. It stays
// for IdentitySpoolMaxAge, as long as the gateway trusts the record it
// withdraws, and other files ignore it (IdentitySpoolStale,
// ReadIdentitySpoolRecords).
const IdentitySpoolWithdrawalSuffix = ".withdrawn"

// ReadIdentitySpoolWithdrawal returns when the guardian last withdrew the
// identity it published for key, validated by trust as a record is;
// os.ErrNotExist when it withdrew none.
func ReadIdentitySpoolWithdrawal(dir, key string, trust func(path, label string) error) (time.Time, error) {
	record, err := readIdentitySpoolFile(dir, key, IdentitySpoolWithdrawalSuffix, "identity spool withdrawal", trust)
	return record.UpdatedAt, err
}

// readIdentitySpoolFile reads dir/<key><suffix>, a record or a withdrawal.
func readIdentitySpoolFile(dir, key, suffix, label string, trust func(path, label string) error) (IdentitySpoolRecord, error) {
	var record IdentitySpoolRecord
	key = strings.TrimSpace(key)
	if dir == "" || !validIdentitySpoolKey(key) {
		return record, os.ErrNotExist
	}
	path := filepath.Join(dir, key+suffix)
	info, err := os.Lstat(path)
	if err != nil {
		return record, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxIdentitySpoolRecordBytes {
		return record, fmt.Errorf("%s is not a regular file within the size limit", label)
	}
	if trust != nil {
		if err := trust(path, label); err != nil {
			return record, err
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return record, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxIdentitySpoolRecordBytes+1))
	if err != nil {
		return record, err
	}
	return ParseIdentitySpoolRecord(data, key)
}

// ParseIdentitySpoolRecord decodes a record, and its extension when one
// follows it, and checks it names key.
func ParseIdentitySpoolRecord(data []byte, key string) (IdentitySpoolRecord, error) {
	var record IdentitySpoolRecord
	if len(data) > maxIdentitySpoolRecordBytes {
		return record, errors.New("identity spool record exceeds the size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, fmt.Errorf("parse identity spool record: %w", err)
	}
	if rest := bytes.TrimSpace(data[decoder.InputOffset():]); len(rest) > 0 {
		var extension identitySpoolRecordExtension
		extensionDecoder := json.NewDecoder(bytes.NewReader(rest))
		if err := extensionDecoder.Decode(&extension); err != nil {
			return record, fmt.Errorf("parse identity spool record extension: %w", err)
		}
		if extensionDecoder.More() {
			return record, errors.New("identity spool record has data after its extension")
		}
		record.AccountSID = strings.TrimSpace(extension.AccountSID)
		record.LegacyOwnerToken = strings.TrimSpace(extension.LegacyOwnerToken)
		record.AccountsStamp = strings.TrimSpace(extension.AccountsStamp)
	}
	if record.Version != IdentitySpoolRecordVersion {
		return record, fmt.Errorf("unsupported identity spool record version %d", record.Version)
	}
	if !strings.EqualFold(record.Key, key) {
		return record, errors.New("identity spool record names another account")
	}
	for connector, email := range record.ConnectorEmails {
		if (connector != "claudecode" && connector != "codex") || !useridentity.ValidEmail(email) {
			return record, errors.New("identity spool record names an invalid connector address")
		}
	}
	record.Facts.Assurance = useridentity.AssuranceVerified
	return record, nil
}

// KeepLastKnownUPN carries the UPN of the account's previous record into a
// fresh record that resolved none, with the principal it gave. Windows
// resolves a UPN only while the user is signed in, so without it a signed-out
// account's record fell back to account@REALM and the account showed two
// principals (GAP-0284). The SID or uid is the record key, so the previous
// record is the same account.
func KeepLastKnownUPN(record, previous IdentitySpoolRecord) IdentitySpoolRecord {
	if record.Facts.UPN != "" || previous.Facts.UPN == "" || !strings.EqualFold(record.Key, previous.Key) {
		return record
	}
	record.Facts.UPN = previous.Facts.UPN
	record.Facts.Principal = previous.Facts.UPN
	record.UPNSource = previous.UPNSource
	if record.Facts.Domain == "" {
		record.Facts.Domain = previous.Facts.Domain
	}
	return record
}

// MarkWindowsKeptUPN sets UPNKeptSince on a Windows record whose UPN is not
// the answer of this pass (kept): the last known UPN KeepLastKnownUPN
// carried, the last good answer the AD UPN cache gave through a failed
// TranslateNameW, or a token-group-only record's earlier UPN. It dates the
// first pass that kept the same UPN, and clears the mark on a record whose
// UPN this pass verified. It changes no UPN, principal or source, so
// profile matching is what it was; the mark only keeps the UPN out of
// agent identity rows, which list current facts (UPNKept).
func MarkWindowsKeptUPN(record, previous IdentitySpoolRecord, kept bool) IdentitySpoolRecord {
	record.UPNKeptSince = time.Time{}
	if !kept || record.Facts.UPN == "" {
		return record
	}
	record.UPNKeptSince = record.UpdatedAt
	if strings.EqualFold(record.Key, previous.Key) && strings.EqualFold(record.Facts.UPN, previous.Facts.UPN) &&
		!previous.UPNKeptSince.IsZero() && !previous.UPNKeptSince.After(record.UpdatedAt) {
		record.UPNKeptSince = previous.UPNKeptSince
	}
	return record
}

// UPNKept reports whether the record's UPN is one the guardian kept rather
// than verified in the pass that wrote it: InfoPipe's infopipe_kept, or a
// Windows UPN MarkWindowsKeptUPN dated.
func (r IdentitySpoolRecord) UPNKept() bool {
	return r.Facts.UPN != "" && (r.UPNSource == UPNSourceInfoPipeKept || !r.UPNKeptSince.IsZero())
}

// IdentitySpoolRecordStillProves reports whether previous, the record an
// account has, still proves what current, the record a pass resolved for
// the same account and could not publish, says, so a failed publication
// need not withdraw it. The group SIDs (a Windows record's token groups;
// the names a pass could not resolve this time are not compared) and
// whether they are known (GroupsPartial) must be the same. A name, UPN,
// principal, domain, realm, directory, tenant or SID that both name must
// agree; one the pass did not resolve this time contradicts nothing.
// Connector addresses and timestamps decide no profile and are not
// compared.
func IdentitySpoolRecordStillProves(previous, current IdentitySpoolRecord) bool {
	if !strings.EqualFold(previous.Key, current.Key) || previous.Facts.GroupsPartial != current.Facts.GroupsPartial {
		return false
	}
	if !current.Facts.GroupsPartial && !sameGroupSIDs(previous.Facts.Groups, current.Facts.Groups) {
		return false
	}
	for _, pair := range [][2]string{
		{previous.User, current.User},
		{previous.Facts.UPN, current.Facts.UPN},
		{previous.Facts.Principal, current.Facts.Principal},
		{previous.Facts.Domain, current.Facts.Domain},
		{previous.Facts.Realm, current.Facts.Realm},
		{string(previous.Facts.Directory), string(current.Facts.Directory)},
		{previous.Facts.TenantID, current.Facts.TenantID},
		{previous.AccountSID, current.AccountSID},
	} {
		if a, b := strings.TrimSpace(pair[0]), strings.TrimSpace(pair[1]); a != "" && b != "" && !strings.EqualFold(a, b) {
			return false
		}
	}
	return true
}

// sameGroupSIDs reports whether two group lists hold the same SIDs (S-1-...),
// whatever their names and order.
func sameGroupSIDs(a, b []string) bool {
	sids := func(groups []string) map[string]bool {
		out := map[string]bool{}
		for _, group := range groups {
			if group = strings.ToUpper(strings.TrimSpace(group)); strings.HasPrefix(group, "S-1-") {
				out[group] = true
			}
		}
		return out
	}
	return maps.Equal(sids(a), sids(b))
}

// IdentitySpoolWithdrawnByFailedWrite reports whether a Windows pass that
// could not publish record must withdraw the account's previous record:
// only one it read (previousErr nil) and disproved
// (IdentitySpoolRecordStillProves). A record it could not read is unknown,
// not disproved: removing it dropped groups that may not have changed, and
// the gateway then took a possibly weaker default. It stays, as the release
// writer left every record whose replacement failed (loop round 3). With no
// record there is nothing to withdraw.
func IdentitySpoolWithdrawnByFailedWrite(previous IdentitySpoolRecord, previousErr error, record IdentitySpoolRecord) bool {
	return previousErr == nil && !IdentitySpoolRecordStillProves(previous, record)
}

// IdentitySpoolTokenGroupRecord is the record a Windows pass publishes for an
// account whose directory lookups did not answer in time (past
// windowsIdentityAccountWait, still running from an earlier pass, or cut by
// the end of the cycle): the token groups the enumerator holds for the
// account this cycle (groupSIDs; known only while signedIn), which need no
// lookup, over the facts of its previous record. Kept as it was, the
// previous record went on naming an earlier sign-in's groups, so a user who
// had gained a strict group kept the weaker profile of the old ones until a
// lookup answered in time or the record aged out (loop round 3). The
// groups are their SIDs, which the gateway matches assignments by, each
// followed by the name the previous record gave it. publish is false when
// the previous record already says this (the same SIDs, or groups unknown
// in both), and when it could not be read: an unknown record is neither
// replaced nor withdrawn here. An account without a record gets one only
// for a signed-in session, the only one with groups to publish.
func IdentitySpoolTokenGroupRecord(previous IdentitySpoolRecord, previousErr error, key string, groupSIDs []string, signedIn bool,
	now time.Time) (record IdentitySpoolRecord, publish bool) {
	switch {
	case previousErr == nil:
		if previous.Facts.GroupsPartial == !signedIn && (!signedIn || sameGroupSIDs(previous.Facts.Groups, groupSIDs)) {
			return previous, false
		}
	case errors.Is(previousErr, os.ErrNotExist) && signedIn:
		previous = IdentitySpoolRecord{Facts: useridentity.DirectoryFacts{ResolvedAt: now}}
	default:
		return previous, false
	}
	record = previous
	record.Key, record.UpdatedAt = key, now
	record.Facts.GroupsPartial = !signedIn
	record.Facts.Groups = nil
	if signedIn {
		record.Facts.Groups = groupsWithNames(groupSIDs, previous.Facts.Groups)
	}
	return record, true
}

// groupsWithNames lists sids, each followed by the name previous (a record's
// groups: each SID followed by its name where one resolved) gave it.
func groupsWithNames(sids, previous []string) []string {
	names := map[string]string{}
	sid := ""
	for _, group := range previous {
		group = strings.TrimSpace(group)
		if strings.HasPrefix(strings.ToUpper(group), "S-1-") {
			sid = strings.ToUpper(group)
			continue
		}
		if sid != "" && group != "" && names[sid] == "" {
			names[sid] = group
		}
		sid = ""
	}
	out := make([]string, 0, 2*len(sids))
	for _, groupSID := range sids {
		out = append(out, groupSID)
		if name := names[strings.ToUpper(strings.TrimSpace(groupSID))]; name != "" {
			out = append(out, name)
		}
	}
	return out
}

// KeepVerifiedInfoPipeUPN carries the UPN an earlier pass read from SSSD
// InfoPipe into a fresh record whose InfoPipe answer listed no
// userPrincipalName. An answer without the attribute is not a verified
// change: it is what InfoPipe says once the [ifp] user_attributes of
// sssd.conf lose userPrincipalName (a hand edit, or a repair that rewrites
// the file). Rewriting the record as derived sent every account a users
// assignment selects by UPN to the default profile within one guardian pass
// (GAP-1114). It keeps the UPN only for the same account in the same SSSD
// domain, under the same name, and only for the same account incarnation.
// A uid, name and domain can all be reused by an account recreated in the
// directory, so the account must be shown to be the same one: by its SID
// (AccountSID) and its account incarnation when both records name them, or
// otherwise by the directory itself (bind) answering this pass that it gives
// the UPN to this account now (UPNBindingBound). A previous record a build
// before 1.0.4 wrote has no SID or incarnation. A lookup that did not answer
// (UPNBindingUnknown) proves nothing, so the UPN goes and the account takes
// the unproven-identity path until a pass proves it (GAP-0384); two
// different SIDs or incarnations are another account. It marks a kept UPN
// infopipe_kept so status and verify can say why. It
// keeps it for IdentitySpoolKeptUPNMaxAge from the first pass that kept it
// (UPNKeptSince): a UPN removed in the directory stayed trusted for as long
// as the guardian ran (GAP-1235). A kept record an older build wrote
// without UPNKeptSince starts the bound at this pass.
func KeepVerifiedInfoPipeUPN(record, previous IdentitySpoolRecord, bind func(upn string) UPNBinding) (IdentitySpoolRecord, bool) {
	if record.Facts.UPN != "" || previous.Facts.UPN == "" ||
		(previous.UPNSource != UPNSourceInfoPipe && previous.UPNSource != UPNSourceInfoPipeKept) ||
		!strings.EqualFold(record.Key, previous.Key) || record.User == "" || !strings.EqualFold(record.User, previous.User) ||
		record.SSSDDomain == "" || !strings.EqualFold(record.SSSDDomain, previous.SSSDDomain) {
		return record, false
	}
	sameIncarnation := record.AccountSID != "" && strings.EqualFold(record.AccountSID, previous.AccountSID) &&
		previous.AccountIncarnation != "" && record.AccountIncarnation == previous.AccountIncarnation
	if !sameIncarnation {
		if record.AccountSID != "" && previous.AccountSID != "" && !strings.EqualFold(record.AccountSID, previous.AccountSID) {
			return record, false
		}
		if bind == nil || bind(previous.Facts.UPN) != UPNBindingBound {
			return record, false
		}
	}
	since := previous.UPNKeptSince
	if previous.UPNSource != UPNSourceInfoPipeKept || since.IsZero() || since.After(record.UpdatedAt) {
		since = record.UpdatedAt
	}
	if record.UpdatedAt.Sub(since) >= IdentitySpoolKeptUPNMaxAge {
		return record, false
	}
	record.Facts.UPN = previous.Facts.UPN
	record.Facts.Principal = previous.Facts.UPN
	record.Facts.Source = previous.Facts.Source
	record.UPNSource = UPNSourceInfoPipeKept
	record.UPNKeptSince = since
	return record, true
}

// UPNBinding is what the directory answers about a UPN an earlier pass
// verified for an account (KeepVerifiedInfoPipeUPN).
type UPNBinding int

const (
	// UPNBindingUnknown: the lookup failed or timed out, or was not asked.
	UPNBindingUnknown UPNBinding = iota
	// UPNBindingBound: the directory gives the UPN to the account now.
	UPNBindingBound
	// UPNBindingOther: the directory gives the UPN to another account, or
	// to none.
	UPNBindingOther
)

// ReadIdentitySpoolRecords reads at most limit records of dir, in file name
// order, skipping any that do not parse or that trust refuses.
func ReadIdentitySpoolRecords(dir string, trust func(path, label string) error, limit int) []IdentitySpoolRecord {
	if limit <= 0 {
		return nil
	}
	var records []IdentitySpoolRecord
	WalkIdentitySpoolRecords(dir, trust, func(record IdentitySpoolRecord) bool {
		records = append(records, record)
		return len(records) < limit
	})
	return records
}

// WalkIdentitySpoolRecords calls fn with each record in dir that reads
// (ReadIdentitySpoolRecord, validated by trust), in file-name order, until
// fn returns false. It holds one record at a time, so a caller that must
// see every record has no cap to stop at (GAP-0964).
func WalkIdentitySpoolRecords(dir string, trust func(path, label string) error, fn func(IdentitySpoolRecord) bool) {
	if dir == "" {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		key, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || entry.IsDir() || !validIdentitySpoolKey(key) {
			continue
		}
		if record, err := ReadIdentitySpoolRecord(dir, key, trust); err == nil && !fn(record) {
			return
		}
	}
}

// MarshalIdentitySpoolRecord serializes a record: the record object, and
// its extension on the next line when it has one.
func MarshalIdentitySpoolRecord(record IdentitySpoolRecord) ([]byte, error) {
	record.Version = IdentitySpoolRecordVersion
	data, err := json.Marshal(record)
	if err != nil || record.AccountSID == "" && record.LegacyOwnerToken == "" {
		return data, err
	}
	extension, err := json.Marshal(identitySpoolRecordExtension{AccountSID: record.AccountSID, LegacyOwnerToken: record.LegacyOwnerToken,
		AccountsStamp: record.AccountsStamp})
	if err != nil {
		return nil, err
	}
	return append(append(data, '\n'), extension...), nil
}

// validIdentitySpoolKey accepts a decimal uid or a SID.
func validIdentitySpoolKey(key string) bool {
	if key == "" || len(key) > 184 {
		return false
	}
	if strings.HasPrefix(strings.ToUpper(key), "S-1-") {
		for i := 4; i < len(key); i++ {
			if c := key[i]; !(c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
		return true
	}
	for i := 0; i < len(key); i++ {
		if key[i] < '0' || key[i] > '9' {
			return false
		}
	}
	return true
}

// writeIdentitySpoolFile replaces dir/name atomically with its final mode
// and ownership set before the rename.
func writeIdentitySpoolFile(dir, name string, record IdentitySpoolRecord, setOwnership func(string) error) error {
	data, err := MarshalIdentitySpoolRecord(record)
	if err != nil {
		return err
	}
	return writeSpoolBytes(dir, name, ".identity-*", data, setOwnership)
}

// writeSpoolBytes replaces dir/name with data atomically, with its final
// mode and ownership set before the rename.
func writeSpoolBytes(dir, name, pattern string, data []byte, setOwnership func(string) error) error {
	tmp, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(0o640)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil && setOwnership != nil {
		err = setOwnership(tmpName)
	}
	if err == nil {
		err = os.Rename(tmpName, filepath.Join(dir, name))
	}
	return err
}
