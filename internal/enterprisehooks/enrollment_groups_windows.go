// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// enterprise.enrollment.include_groups and exclude_groups on Windows.
//
// A signed-in user's session token lists the user's local and Active
// Directory groups, and only those Microsoft Entra ID groups that a built-in
// local group (Administrators, Users, Remote Desktop Users, ...) lists:
// Windows leaves every other Entra group out of the token. The enumerator
// reads the token of each active session and caches its group SIDs, so a signed-out user is decided from
// the membership seen at their last sign-in. Local groups are also read from
// the local account database, which lists the direct members of a local
// group at any time; it decides local accounts completely (a local account
// cannot join a directory group) and directory users who are direct members.
// A directory user whose membership is not known this way (they have not
// signed in since DefenseClaw was installed) is left pending: no new rows,
// existing rows kept, never revoked, until they next sign in. The same
// holds for a user signed in now whose token groups cannot be read, and, while
// a session's user cannot be identified, for every user the cache alone
// decides: the groups cached at an earlier sign-in may be out of date, so a
// decision that rests on them changes nothing that cycle. Well-known
// groups other than Everyone (Authenticated Users, INTERACTIVE, NETWORK,
// Local account, ...) are assigned at sign-in and appear in no account
// database, so they are decided from a token only; Everyone is in every
// token.
//
// Entries name a group by SID (S-1-5-32-544, S-1-12-1-...) or by name
// (Administrators, BUILTIN\Administrators, CONTOSO\Developers). A name is
// resolved to a SID every cycle and the resolution is cached; Entra ID group
// names cannot be resolved on the device, so Entra ID groups are listed by
// SID. A name that resolved before but does not resolve this cycle (the
// directory is unreachable, or its lookup has not answered) keeps its cached
// SID, but that SID is unverified: the group may have been deleted and
// recreated under the same name with a new SID, which a user's token then
// holds instead, and a holder of the old SID may not be in the group now. So
// that SID decides no one, whether or not a user holds it: every user the
// entry would decide is pending (no new rows, existing rows kept, and a
// signed-in user without rows is reported) until the name resolves again.
// A user another exclude_groups entry excludes is still excluded, and while
// only an include_groups name is unverified, a user another entry admits is
// still admitted. An obsolete SID neither admits, excludes nor revokes
// anyone. One answer needs no SID: a local account of this computer is in
// no group of another domain, and a name written DOMAIN\group whose domain
// is not this computer's, cached as a directory group, names such a group
// whatever SID it has now. A local account is therefore still certainly not
// a member of it, as when the name resolves, and an exclude_groups entry of
// that kind leaves local accounts enrolled. A name that does not resolve and was never
// cached (a misspelling, a group of another platform such as wheel, or a
// directory group while the directory is unreachable) cannot be evaluated:
// as an exclude_groups entry it excludes no one, as on Linux and macOS, so
// it never withholds enrollment; as an include_groups entry it leaves the
// users it does not otherwise admit pending, so it never revokes anyone.

// WindowsEnrollmentGroupsCacheFileName is the enumerator's membership cache,
// kept next to the manifest with the manifest's SYSTEM and Administrators
// only protection.
const WindowsEnrollmentGroupsCacheFileName = ".enrollment-groups.json"

const windowsEnrollmentGroupsCacheMaxBytes = 4 << 20

// WindowsEnrollmentGroupCache records, per user SID, the group SIDs of the
// user's last signed-in session token, and each configured group name's SID.
type WindowsEnrollmentGroupCache struct {
	Version int                 `json:"version"`
	Users   map[string][]string `json:"users,omitempty"`
	Names   map[string]string   `json:"names,omitempty"`
	// SignedIn names the users whose groups came from an active session
	// token this cycle; the others keep their last session groups. It is not
	// saved.
	SignedIn map[string]bool `json:"-"`
}

// WindowsEnrollmentGroupsCachePath is the membership cache for manifestPath.
func WindowsEnrollmentGroupsCachePath(manifestPath string) string {
	return filepath.Join(filepath.Dir(filepath.Clean(manifestPath)), WindowsEnrollmentGroupsCacheFileName)
}

// NewWindowsEnrollmentGroupCache returns an empty cache.
func NewWindowsEnrollmentGroupCache() *WindowsEnrollmentGroupCache {
	return &WindowsEnrollmentGroupCache{Version: 1, Users: map[string][]string{}, Names: map[string]string{}}
}

// MarshalWindowsEnrollmentGroupCache serializes the cache deterministically.
func MarshalWindowsEnrollmentGroupCache(cache *WindowsEnrollmentGroupCache) ([]byte, error) {
	if cache == nil {
		cache = NewWindowsEnrollmentGroupCache()
	}
	out := WindowsEnrollmentGroupCache{Version: 1, Users: map[string][]string{}, Names: map[string]string{}}
	for sid, groups := range cache.Users {
		if canon := canonicalManifestTargetSID(sid); canon != "" {
			out.Users[canon] = canonicalWindowsGroupSIDs(groups)
		}
	}
	for name, sid := range cache.Names {
		if canon := canonicalWindowsGroupSID(sid); canon != "" && strings.TrimSpace(name) != "" {
			out.Names[strings.ToLower(strings.TrimSpace(name))] = canon
		}
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// ParseWindowsEnrollmentGroupCache decodes a cache; a malformed cache is an
// error so the caller starts from an empty one.
func ParseWindowsEnrollmentGroupCache(data []byte) (*WindowsEnrollmentGroupCache, error) {
	if len(data) > windowsEnrollmentGroupsCacheMaxBytes {
		return nil, errors.New("enterprise hooks: enrollment group cache is too large")
	}
	var cache WindowsEnrollmentGroupCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, fmt.Errorf("enterprise hooks: parse enrollment group cache: %w", err)
	}
	if cache.Version != 1 {
		return nil, fmt.Errorf("enterprise hooks: enrollment group cache version %d is not supported", cache.Version)
	}
	normalized := NewWindowsEnrollmentGroupCache()
	for sid, groups := range cache.Users {
		if canon := canonicalManifestTargetSID(sid); canon != "" {
			normalized.Users[canon] = canonicalWindowsGroupSIDs(groups)
		}
	}
	for name, sid := range cache.Names {
		if canon := canonicalWindowsGroupSID(sid); canon != "" && strings.TrimSpace(name) != "" {
			normalized.Names[strings.ToLower(strings.TrimSpace(name))] = canon
		}
	}
	return normalized, nil
}

// LoadWindowsEnrollmentGroupCache reads the cache at path. A missing cache
// is empty; one that is not an exact SYSTEM and Administrators only file,
// or does not parse, is refused.
func LoadWindowsEnrollmentGroupCache(path string) (*WindowsEnrollmentGroupCache, error) {
	data, err := readWindowsProtectedRecord(path, windowsEnrollmentGroupsCacheMaxBytes)
	if errors.Is(err, os.ErrNotExist) {
		return NewWindowsEnrollmentGroupCache(), nil
	}
	if err != nil {
		return nil, err
	}
	return ParseWindowsEnrollmentGroupCache(data)
}

// SaveWindowsEnrollmentGroupCache publishes the cache at path.
func SaveWindowsEnrollmentGroupCache(path string, cache *WindowsEnrollmentGroupCache) (bool, error) {
	data, err := MarshalWindowsEnrollmentGroupCache(cache)
	if err != nil {
		return false, err
	}
	return WriteWindowsProtectedRecordAtomic(path, data)
}

func canonicalWindowsGroupSID(raw string) string {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(strings.ToUpper(raw), "S-1-") {
		return ""
	}
	sid, err := windows.StringToSid(raw)
	if err != nil || !sid.IsValid() {
		return ""
	}
	return strings.ToUpper(sid.String())
}

func canonicalWindowsGroupSIDs(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		if canon := canonicalWindowsGroupSID(value); canon != "" {
			if _, dup := seen[canon]; !dup {
				seen[canon] = struct{}{}
				out = append(out, canon)
			}
		}
	}
	sort.Strings(out)
	return out
}

// RefreshWindowsManifestIdentityGroups keeps group facts for administrator
// enrolled users without changing their targets manifest. The cache is
// filtered to the current manifest before it is published to the gateway.
// An incomplete session read still applies the sessions it read and returns
// its error; a user whose token groups were not read keeps the cached groups
// and is not marked signed in, so the gateway gets no groups for them.
func RefreshWindowsManifestIdentityGroups(manifest Manifest, cache *WindowsEnrollmentGroupCache) (*WindowsEnrollmentGroupCache, error) {
	if cache == nil {
		cache = NewWindowsEnrollmentGroupCache()
	}
	allowed := map[string]bool{}
	for _, target := range manifest.Targets {
		if target.IsEnabled() {
			if sid := canonicalManifestTargetSID(target.SID); sid != "" {
				allowed[sid] = true
			}
		}
	}
	fresh := NewWindowsEnrollmentGroupCache()
	fresh.SignedIn = map[string]bool{}
	for sid := range allowed {
		fresh.Users[sid] = []string{}
	}
	for sid, groups := range cache.Users {
		if canon := canonicalManifestTargetSID(sid); allowed[canon] {
			fresh.Users[canon] = canonicalWindowsGroupSIDs(groups)
		}
	}
	sessions, err := windowsActiveSessionGroups()
	for sid, groups := range sessions {
		if canon := canonicalManifestTargetSID(sid); allowed[canon] {
			fresh.Users[canon] = canonicalWindowsGroupSIDs(groups)
			fresh.SignedIn[canon] = true
		}
	}
	return fresh, err
}

// windowsGroupMembership is one user's membership of one configured group.
type windowsGroupMembership int

const (
	windowsGroupMembershipUnknown windowsGroupMembership = iota
	windowsGroupMember
	windowsGroupNotMember
	// windowsGroupUnresolved: the entry names a group that did not resolve
	// to a SID and has no cached SID, so it cannot be evaluated for anyone.
	windowsGroupUnresolved
	// windowsGroupUnverified: the entry's name did not resolve this cycle,
	// and the SID cached when it last did decides no one (membership).
	windowsGroupUnverified
)

// windowsGroupKind classifies a group SID by where its membership can be
// read.
type windowsGroupKind int

const (
	// windowsGroupKindLocal: a BUILTIN alias or a group of this computer's
	// account domain; the local account database lists its direct members.
	windowsGroupKindLocal windowsGroupKind = iota
	// windowsGroupKindDirectory: an Active Directory group (S-1-5-21-...
	// outside this computer's account domain) or a Microsoft Entra ID
	// group (S-1-12-1-...).
	windowsGroupKindDirectory
	// windowsGroupKindEveryone: S-1-1-0, present in every token.
	windowsGroupKindEveryone
	// windowsGroupKindTokenOnly: any other well-known group (Authenticated
	// Users, INTERACTIVE, NETWORK, Local account, ...). Windows adds these to
	// a token at sign-in; no account database lists their members.
	windowsGroupKindTokenOnly
)

const windowsEveryoneSID = "S-1-1-0"

// windowsEnrollmentGroupEntry is one configured group, resolved.
type windowsEnrollmentGroupEntry struct {
	raw string
	sid string // "" when the name did not resolve and is not cached
	// unverified: the name did not resolve this cycle and sid is the SID
	// cached when it last did. The group may since have been deleted or
	// recreated under the same name with another SID, so neither holding
	// nor lacking sid shows a user's membership (membership).
	unverified bool
	// foreignDomain: an unverified entry whose name places the group in
	// another domain than this computer's (DOMAIN\group, cached as a
	// directory group). No local account is a member of it, whatever its
	// SID is now (windowsGroupNameOfAnotherDomain).
	foreignDomain bool
	// members lists the direct members of a local group from the local
	// account database; nil for a directory group or when unreadable.
	members map[string]bool
}

// windowsEnrollmentGroups applies include_groups and exclude_groups for one
// enumeration cycle.
type windowsEnrollmentGroups struct {
	include, exclude []windowsEnrollmentGroupEntry
	// sessions maps the SID of each user with an active session to the
	// group SIDs of that session's token.
	sessions map[string][]string
	cache    *WindowsEnrollmentGroupCache
	// machineSID is this computer's account domain SID: users below it
	// are local accounts.
	machineSID string
	// unread names the users signed in now whose token groups this cycle
	// could not read. unreadAnyone: a session's user could not be
	// identified, or the sessions could not be listed, so any user without a
	// session read this cycle may be signed in. The cached groups of those
	// users may be out of date.
	unread       map[string]bool
	unreadAnyone bool
}

// Seams: session tokens, name resolution, local group members and the
// machine SID. Tests replace them.
var (
	windowsActiveSessionGroups       = readWindowsActiveSessionGroups
	windowsSignedInSessionUsers      = readWindowsSignedInSessionUsers
	windowsResolveGroupName          = resolveWindowsGroupName
	windowsLocalGroupDirectMembers   = readWindowsLocalGroupDirectMembers
	windowsMachineAccountDomainSID   = readWindowsMachineAccountDomainSID
	windowsComputerName              = windows.ComputerName
	windowsGroupNameLookupTimeout    = 3 * time.Second
	windowsGroupNameLookupCycleLimit = 15 * time.Second
)

// newWindowsEnrollmentGroups resolves the configured groups. cache is
// updated in place: the resolved names, and the token groups of every user
// signed in now whose token was read. sessionErr is the error of the
// session read that gave sessions (windowsActiveSessionGroups): the users
// it leaves unread are decided as windowsSessionGroupsInDoubt says.
func newWindowsEnrollmentGroups(
	include, exclude []string,
	sessions map[string][]string,
	sessionErr error,
	cache *WindowsEnrollmentGroupCache,
	logf EnumerationLogger,
) *windowsEnrollmentGroups {
	if cache == nil {
		cache = NewWindowsEnrollmentGroupCache()
	}
	if cache.Users == nil {
		cache.Users = map[string][]string{}
	}
	if cache.Names == nil {
		cache.Names = map[string]string{}
	}
	signedIn := make(map[string][]string, len(sessions))
	cache.SignedIn = make(map[string]bool, len(sessions))
	for sid, groups := range sessions {
		canon := canonicalManifestTargetSID(sid)
		signedIn[canon] = canonicalWindowsGroupSIDs(groups)
		cache.Users[canon] = signedIn[canon]
		cache.SignedIn[canon] = true
	}
	groups := &windowsEnrollmentGroups{sessions: signedIn, cache: cache}
	unread, anyone := windowsSessionGroupsInDoubt(sessionErr)
	groups.unreadAnyone = anyone
	groups.unread = make(map[string]bool, len(unread))
	for sid := range unread {
		if canon := canonicalManifestTargetSID(sid); canon != "" {
			groups.unread[canon] = true
		}
	}
	if len(include) == 0 && len(exclude) == 0 {
		return groups
	}
	if machineSID, err := windowsMachineAccountDomainSID(); err == nil {
		groups.machineSID = strings.ToUpper(strings.TrimSpace(machineSID))
	} else {
		logfSafely(logf, "enrollment", fmt.Sprintf("this computer's account domain SID is unreadable; local accounts are decided from their sign-in tokens only: %v", err))
	}
	var spent time.Duration
	resolve := func(list, raw string) windowsEnrollmentGroupEntry {
		entry := windowsEnrollmentGroupEntry{raw: strings.TrimSpace(raw)}
		if canon := canonicalWindowsGroupSID(entry.raw); canon != "" {
			entry.sid = canon
		} else {
			key := strings.ToLower(entry.raw)
			started := time.Now()
			sid, err := boundedWindowsGroupNameLookup(entry.raw, windowsGroupNameLookupCycleLimit-spent)
			spent += time.Since(started)
			switch {
			case err == nil:
				entry.sid = sid
				cache.Names[key] = sid
			case cache.Names[key] != "":
				entry.sid, entry.unverified = cache.Names[key], true
				entry.foreignDomain = groups.groupKind(entry.sid) == windowsGroupKindDirectory && windowsGroupNameOfAnotherDomain(entry.raw)
				logfSafely(logf, "enrollment", fmt.Sprintf("enterprise.enrollment.%s %q did not resolve (%v); the users it would decide are pending this cycle, whether or not they hold its cached SID %s, since the group may have been deleted or recreated under a new SID (name the group by SID)", list, entry.raw, err, entry.sid))
			case list == "exclude_groups":
				logfSafely(logf, "enrollment", fmt.Sprintf("enterprise.enrollment.exclude_groups %q does not resolve to a group on this computer (%v); it excludes no one this cycle (name the group by SID)", entry.raw, err))
			default:
				logfSafely(logf, "enrollment", fmt.Sprintf("enterprise.enrollment.include_groups %q does not resolve to a group on this computer (%v); users no other entry admits are pending this cycle (name the group by SID)", entry.raw, err))
			}
		}
		if entry.sid != "" && !entry.unverified && groups.localGroupSID(entry.sid) {
			if members, err := windowsLocalGroupDirectMembers(entry.sid); err == nil {
				entry.members = map[string]bool{}
				for _, member := range members {
					if canon := canonicalWindowsGroupSID(member); canon != "" {
						entry.members[canon] = true
					}
				}
			} else {
				logfSafely(logf, "enrollment", fmt.Sprintf("members of local group %q are unreadable: %v", entry.raw, err))
			}
		}
		return entry
	}
	for _, raw := range include {
		groups.include = append(groups.include, resolve("include_groups", raw))
	}
	for _, raw := range exclude {
		groups.exclude = append(groups.exclude, resolve("exclude_groups", raw))
	}
	return groups
}

// boundedWindowsGroupNameLookup resolves name, waiting at most remaining
// and windowsGroupNameLookupTimeout. A name whose lookup of an earlier cycle
// has not returned fails at once without a new one
// (windowsGroupNameLookupGate), so one name the directory never answers for
// neither uses up every cycle's budget nor piles up native calls.
func boundedWindowsGroupNameLookup(name string, remaining time.Duration) (string, error) {
	if remaining <= 0 {
		return "", errors.New("group name lookup budget for this cycle is exhausted")
	}
	if remaining > windowsGroupNameLookupTimeout {
		remaining = windowsGroupNameLookupTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), remaining)
	defer cancel()
	lookup := windowsResolveGroupName
	sid, err := identityLookupGated(ctx, &windowsGroupNameLookupGate, strings.ToLower(strings.TrimSpace(name)), func(context.Context) (string, error) {
		return lookup(name)
	})
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "", errors.New("group name lookup timed out")
	case err != nil:
		return "", err
	}
	if sid = canonicalWindowsGroupSID(sid); sid == "" {
		return "", errors.New("group name lookup returned no SID")
	}
	return sid, nil
}

// windowsGroupNameLookupGate holds the group name lookups, by lower-case
// name.
var windowsGroupNameLookupGate identityLookupGate

// windowsGroupNameOfAnotherDomain reports whether name is written
// DOMAIN\group with a domain that is not this computer: not ".", BUILTIN,
// an NT authority, or the computer's own name (its first DNS label). An
// unqualified name can resolve to a local group of the same name, and a
// computer whose name is unreadable counts as possibly local, so neither
// qualifies.
func windowsGroupNameOfAnotherDomain(name string) bool {
	domain, group, ok := strings.Cut(strings.TrimSpace(name), `\`)
	domain, group = strings.ToUpper(strings.TrimSpace(domain)), strings.TrimSpace(group)
	if !ok || domain == "" || group == "" || strings.Contains(group, `\`) {
		return false
	}
	switch domain {
	case ".", "BUILTIN", "LOCALHOST":
		return false
	}
	if strings.HasPrefix(domain, "NT ") {
		return false // NT AUTHORITY, NT SERVICE, NT VIRTUAL MACHINE: well-known groups
	}
	computer, err := windowsComputerName()
	if err != nil || strings.TrimSpace(computer) == "" {
		return false
	}
	label, _, _ := strings.Cut(domain, ".")
	return !strings.EqualFold(label, strings.TrimSpace(computer))
}

// active reports whether groups filter anything.
func (g *windowsEnrollmentGroups) active() bool {
	return g != nil && len(g.include)+len(g.exclude) > 0
}

// localAccount reports whether userSID is an account of this computer's
// local account database.
func (g *windowsEnrollmentGroups) localAccount(userSID string) bool {
	return g.machineSID != "" && strings.HasPrefix(strings.ToUpper(userSID), g.machineSID+"-")
}

// localGroupSID reports whether sid names a local group: a BUILTIN alias or
// a group of this computer's account domain.
func (g *windowsEnrollmentGroups) localGroupSID(sid string) bool {
	sid = strings.ToUpper(sid)
	return strings.HasPrefix(sid, "S-1-5-32-") || g.localAccount(sid)
}

// groupKind classifies a group SID by where its membership is recorded.
// Without this computer's account domain SID a group of it reads as a
// directory group, whose membership is then taken from tokens only.
func (g *windowsEnrollmentGroups) groupKind(sid string) windowsGroupKind {
	sid = strings.ToUpper(strings.TrimSpace(sid))
	switch {
	case sid == windowsEveryoneSID:
		return windowsGroupKindEveryone
	case g.localGroupSID(sid):
		return windowsGroupKindLocal
	case strings.HasPrefix(sid, "S-1-5-21-"), strings.HasPrefix(sid, "S-1-12-1-"):
		return windowsGroupKindDirectory
	default:
		return windowsGroupKindTokenOnly
	}
}

// membership is userSID's membership of entry. inDoubt says the answer
// comes only from the groups cached at an earlier sign-in while the user may
// be signed in now with a token this cycle could not read. An entry whose
// name did not resolve this cycle is windowsGroupUnverified for everyone:
// its cached SID may name a group since deleted or recreated under the same
// name with another SID, so a member answer could admit a user through an
// include_groups group that no longer holds them or exclude one an
// exclude_groups group no longer holds, and a non-member answer could lose
// an exclusion or revoke a member.
func (g *windowsEnrollmentGroups) membership(userSID string, entry windowsEnrollmentGroupEntry) (windowsGroupMembership, bool) {
	if entry.sid == "" {
		return windowsGroupUnresolved, false
	}
	if entry.unverified {
		if entry.foreignDomain && g.localAccount(userSID) {
			// A local account is in no group of another domain, whichever
			// group the name names now: certain, without the cached SID.
			return windowsGroupNotMember, false
		}
		return windowsGroupUnverified, false
	}
	inList := func(groups []string) windowsGroupMembership {
		for _, group := range groups {
			if strings.EqualFold(group, entry.sid) {
				return windowsGroupMember
			}
		}
		return windowsGroupNotMember
	}
	// A session token lists every group of the user, nested and
	// well-known ones included; the cache holds the last one seen.
	if groups, signedIn := g.sessions[userSID]; signedIn {
		return inList(groups), false
	}
	groups, cached := g.cache.Users[userSID]
	if !cached {
		return g.recordedMembership(userSID, entry), false
	}
	if !g.unread[userSID] && !g.unreadAnyone {
		return inList(groups), false
	}
	// The user may be signed in with a token this cycle could not read: the
	// account database's answer stands, and one only the cache gives is in
	// doubt.
	if recorded := g.recordedMembership(userSID, entry); recorded != windowsGroupMembershipUnknown {
		return recorded, false
	}
	return inList(groups), true
}

// recordedMembership is userSID's membership of entry as far as it is known
// without a token: from the group's kind and the local account database.
func (g *windowsEnrollmentGroups) recordedMembership(userSID string, entry windowsEnrollmentGroupEntry) windowsGroupMembership {
	local := g.localAccount(userSID)
	switch g.groupKind(entry.sid) {
	case windowsGroupKindEveryone:
		return windowsGroupMember
	case windowsGroupKindTokenOnly:
		return windowsGroupMembershipUnknown
	case windowsGroupKindDirectory:
		if local {
			return windowsGroupNotMember // a local account is never in a directory group
		}
		return windowsGroupMembershipUnknown
	}
	// A local group: the local account database lists its direct members.
	if entry.members == nil {
		return windowsGroupMembershipUnknown
	}
	if entry.members[strings.ToUpper(userSID)] {
		return windowsGroupMember
	}
	nestedTokenOnly := false
	for member := range entry.members {
		switch g.groupKind(member) {
		case windowsGroupKindEveryone:
			return windowsGroupMember
		case windowsGroupKindTokenOnly:
			// Members through Authenticated Users or INTERACTIVE, say,
			// are known only from the user's token.
			nestedTokenOnly = true
		}
	}
	if local && !nestedTokenOnly {
		return windowsGroupNotMember
	}
	// A directory user may also be a member through a directory group.
	return windowsGroupMembershipUnknown
}

// decide applies the group filters to one profile: exclusion wins, and an
// unknown membership leaves the profile undecided (pending), never
// excluded. An exclude_groups entry that does not resolve excludes no one;
// an include_groups entry that does not resolve leaves undecided the users
// no other entry admits. A decision that rests on cached groups in doubt
// (evaluate) is pending too, and so is one that an entry whose name did not
// resolve this cycle would make.
func (g *windowsEnrollmentGroups) decide(userSID string) (windowsEnrollmentDecision, string) {
	decision, reason, inDoubt := g.evaluate(userSID)
	if inDoubt {
		return windowsEnrollmentUndecided, g.inDoubtReason(userSID)
	}
	return decision, reason
}

// evaluate is decide before the doubt is applied: inDoubt says the decision
// rests on a membership only the cache gives while the user may be signed in
// with a token this cycle could not read.
func (g *windowsEnrollmentGroups) evaluate(userSID string) (decision windowsEnrollmentDecision, reason string, inDoubt bool) {
	if !g.active() {
		return windowsEnrollmentEnrolled, "", false
	}
	userSID = strings.ToUpper(strings.TrimSpace(userSID))
	var unknown, unverified []string
	// excludeDoubt: an exclude_groups non-membership came from the cache in
	// doubt; doubtfulExclusion: so did the only exclusion found.
	excludeDoubt, doubtfulExclusion := false, ""
	for _, entry := range g.exclude {
		membership, doubt := g.membership(userSID, entry)
		switch membership {
		case windowsGroupMember:
			if !doubt {
				return windowsEnrollmentExcluded, fmt.Sprintf("member of %q (enterprise.enrollment.exclude_groups)", entry.raw), false
			}
			if doubtfulExclusion == "" {
				doubtfulExclusion = entry.raw
			}
		case windowsGroupMembershipUnknown:
			unknown = append(unknown, entry.raw)
		case windowsGroupUnverified:
			unverified = append(unverified, entry.raw)
		case windowsGroupNotMember:
			excludeDoubt = excludeDoubt || doubt
		}
	}
	if doubtfulExclusion != "" {
		return windowsEnrollmentExcluded, fmt.Sprintf("member of %q (enterprise.enrollment.exclude_groups)", doubtfulExclusion), true
	}
	if len(unverified) > 0 {
		return windowsEnrollmentUndecided, windowsGroupsUnverifiedReason("exclude_groups", unverified), false
	}
	if len(unknown) > 0 {
		return windowsEnrollmentUndecided, windowsGroupsPendingReason("exclude_groups", unknown), false
	}
	if len(g.include) == 0 {
		return windowsEnrollmentEnrolled, "", excludeDoubt
	}
	var unresolved []string
	// includeDoubt: an include_groups non-membership came from the cache in
	// doubt; doubtfulMember: so did every membership found. A membership not
	// in doubt admits the user, whichever entry gives it.
	includeDoubt, doubtfulMember := false, false
	for _, entry := range g.include {
		membership, doubt := g.membership(userSID, entry)
		switch membership {
		case windowsGroupMember:
			if !doubt {
				return windowsEnrollmentEnrolled, "", excludeDoubt
			}
			doubtfulMember = true
		case windowsGroupUnverified:
			unverified = append(unverified, entry.raw)
		case windowsGroupMembershipUnknown:
			unknown = append(unknown, entry.raw)
		case windowsGroupUnresolved:
			unresolved = append(unresolved, entry.raw)
		case windowsGroupNotMember:
			includeDoubt = includeDoubt || doubt
		}
	}
	switch {
	case doubtfulMember:
		return windowsEnrollmentEnrolled, "", true
	case len(unverified) > 0:
		return windowsEnrollmentUndecided, windowsGroupsUnverifiedReason("include_groups", unverified), false
	case len(unresolved) > 0:
		return windowsEnrollmentUndecided, windowsGroupsUnresolvedReason(unresolved), false
	case len(unknown) > 0:
		return windowsEnrollmentUndecided, windowsGroupsPendingReason("include_groups", unknown), false
	}
	return windowsEnrollmentExcluded, "not a member of any enterprise.enrollment.include_groups group", excludeDoubt || includeDoubt
}

// inDoubtReason is the pending reason of a decision evaluate put in doubt.
func (g *windowsEnrollmentGroups) inDoubtReason(userSID string) string {
	userSID = strings.ToUpper(strings.TrimSpace(userSID))
	var causes []string
	_, fresh := g.sessions[userSID]
	_, cached := g.cache.Users[userSID]
	switch {
	case g.unread[userSID]:
		causes = append(causes, "the groups of this user's active session could not be read this cycle, so the membership cached at an earlier sign-in may be out of date")
	case g.unreadAnyone && !fresh && cached:
		causes = append(causes, "an active session's user could not be identified this cycle and may be this user, so the membership cached at an earlier sign-in may be out of date")
	}
	if names := g.unverifiedNames(); len(names) > 0 {
		causes = append(causes, fmt.Sprintf(
			"enterprise.enrollment group %q did not resolve this cycle, so its cached SID may name a group since deleted or recreated under that name (name the group by SID)",
			strings.Join(names, ", ")))
	}
	if len(causes) == 0 {
		causes = append(causes, "the group membership this decision rests on may be out of date")
	}
	return strings.Join(causes, "; ") + "; pending: existing rows kept, no new rows"
}

// unverifiedNames lists the entries whose cached SID this cycle could not
// confirm.
func (g *windowsEnrollmentGroups) unverifiedNames() []string {
	var names []string
	for _, entry := range append(append([]windowsEnrollmentGroupEntry(nil), g.exclude...), g.include...) {
		if entry.unverified {
			names = append(names, entry.raw)
		}
	}
	return names
}

func windowsGroupsPendingReason(list string, groups []string) string {
	return fmt.Sprintf(
		"membership of enterprise.enrollment.%s %q is unknown until the user signs in; pending: existing rows kept, no new rows",
		list, strings.Join(groups, ", "),
	)
}

func windowsGroupsUnresolvedReason(groups []string) string {
	return fmt.Sprintf(
		"enterprise.enrollment.include_groups %q does not resolve to a group on this computer, so membership of it is unknown; pending until it resolves: existing rows kept, no new rows (name the group by SID)",
		strings.Join(groups, ", "),
	)
}

// windowsGroupsUnverifiedReason is the pending reason of a user an entry
// whose name did not resolve this cycle would decide.
func windowsGroupsUnverifiedReason(list string, groups []string) string {
	return fmt.Sprintf(
		"enterprise.enrollment.%s %q did not resolve this cycle, so the SID it last resolved to may name a group since deleted or recreated under that name; pending until it resolves: existing rows kept, no new rows (name the group by SID)",
		list, strings.Join(groups, ", "),
	)
}

// pruneCache drops cached users who no longer have a profile.
func (g *windowsEnrollmentGroups) pruneCache(profiles map[string]struct{}) {
	for sid := range g.cache.Users {
		if _, ok := profiles[sid]; !ok {
			delete(g.cache.Users, sid)
		}
	}
}

// readWindowsActiveSessionGroups maps the SID of each user with an active
// session to the group SIDs of that session's token (logon SIDs excluded;
// deny-only groups count, since the user is a member). When a session's
// user cannot be identified, or an identified user's token groups cannot be
// read, it returns the users it did read with a
// *windowsSessionGroupsIncomplete error that names what it missed: such a
// user is signed in now with groups this read did not see, so the groups
// cached at their earlier sign-in may be out of date. A user with two active
// sessions is read only when both tokens are.
func readWindowsActiveSessionGroups() (map[string][]string, error) {
	out := map[string][]string{}
	unread := map[string]bool{}
	var problems []string
	err := visitWindowsSessionTokens(func(state uint32) bool { return state == windows.WTSActive }, func(sid string, token windows.Token) {
		groups, err := windowsSessionAPI.tokenGroups(token)
		if err != nil {
			unread[sid] = true
			problems = append(problems, fmt.Sprintf("token groups of %s: %v", sid, err))
			return
		}
		out[sid] = append(out[sid], groups...)
	})
	if err != nil && !errors.Is(err, errWindowsSessionsUnidentified) {
		return nil, err
	}
	for sid, groups := range out {
		out[sid] = canonicalWindowsGroupSIDs(groups)
	}
	for sid := range unread {
		delete(out, sid)
	}
	if err == nil && len(unread) == 0 {
		return out, nil
	}
	if err != nil {
		problems = append(problems, err.Error())
	}
	return out, &windowsSessionGroupsIncomplete{unread: unread, unidentified: err != nil, detail: strings.Join(problems, "; ")}
}

// windowsSessionGroupsIncomplete is the error of an active-session read
// that missed some active sessions' groups.
type windowsSessionGroupsIncomplete struct {
	// unread names the users with an active session whose token groups
	// could not be read.
	unread map[string]bool
	// unidentified: an active session's user could not be identified, so
	// any user may be signed in with groups the read did not see.
	unidentified bool
	detail       string
}

func (e *windowsSessionGroupsIncomplete) Error() string {
	return "the groups of some active Windows sessions could not be read: " + e.detail
}

// Is matches errWindowsSessionsUnidentified when a session's user could not
// be identified.
func (e *windowsSessionGroupsIncomplete) Is(target error) bool {
	return e.unidentified && target == errWindowsSessionsUnidentified
}

// windowsSessionGroupsInDoubt says whose cached groups the error of an
// active-session read puts in doubt: the users it names unread, and anyone
// it did not read (anyone) when a session's user was not identified or the
// sessions could not be listed.
func windowsSessionGroupsInDoubt(err error) (unread map[string]bool, anyone bool) {
	if err == nil {
		return nil, false
	}
	var incomplete *windowsSessionGroupsIncomplete
	if errors.As(err, &incomplete) {
		return incomplete.unread, incomplete.unidentified
	}
	return nil, true
}

// readWindowsSignedInSessionUsers lists the SIDs of the users who have a
// session now, active or disconnected. A disconnected session keeps running
// the user's processes, so it can still start the user's agents. When a
// session's user cannot be identified it returns the users it did identify
// and an errWindowsSessionsUnidentified error: that session may be any
// user's, so no one may be judged signed out on this answer.
func readWindowsSignedInSessionUsers() (map[string]bool, error) {
	out := map[string]bool{}
	err := visitWindowsSessionTokens(func(state uint32) bool {
		return state == windows.WTSActive || state == windows.WTSDisconnected
	}, func(sid string, _ windows.Token) {
		out[sid] = true
	})
	return out, err
}

// errWindowsSessionsUnidentified is a session whose user could not be read.
var errWindowsSessionsUnidentified = errors.New("the user of a Windows session could not be identified")

// windowsSession is one terminal services session.
type windowsSession struct {
	id, state uint32
}

// windowsSessionAPI lists the sessions and reads a session's user token,
// the token's user SID and its group SIDs; tests replace it.
var windowsSessionAPI = struct {
	list        func() ([]windowsSession, error)
	userToken   func(session uint32) (windows.Token, error)
	tokenUser   func(token windows.Token) (string, error)
	tokenGroups func(token windows.Token) ([]string, error)
	close       func(token windows.Token)
}{
	list: listWindowsSessions,
	userToken: func(session uint32) (windows.Token, error) {
		var token windows.Token
		err := windows.WTSQueryUserToken(session, &token)
		return token, err
	},
	tokenUser: func(token windows.Token) (string, error) {
		user, err := token.GetTokenUser()
		if err != nil {
			return "", err
		}
		return user.User.Sid.String(), nil
	},
	tokenGroups: readWindowsTokenGroups,
	close:       func(token windows.Token) { _ = token.Close() },
}

// readWindowsTokenGroups lists the group SIDs of token, logon SIDs excluded.
func readWindowsTokenGroups(token windows.Token) ([]string, error) {
	groups, err := token.GetTokenGroups()
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, group := range groups.AllGroups() {
		if group.Sid == nil || group.Attributes&windows.SE_GROUP_LOGON_ID == windows.SE_GROUP_LOGON_ID {
			continue
		}
		out = append(out, group.Sid.String())
	}
	return out, nil
}

// listWindowsSessions lists this computer's terminal services sessions.
func listWindowsSessions() ([]windowsSession, error) {
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil {
		return nil, err
	}
	if sessions != nil {
		defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	}
	if count == 0 || sessions == nil {
		return nil, nil
	}
	out := make([]windowsSession, 0, count)
	for _, session := range unsafe.Slice(sessions, count) {
		out = append(out, windowsSession{id: session.SessionID, state: session.State})
	}
	return out, nil
}

// visitWindowsSessionTokens calls visit with the canonical user SID and the
// user token of each session whose state accept admits. The token is closed
// after visit. Session 0 (services) and a session without a signed-in user
// (ERROR_NO_TOKEN) have no user to visit. Any other session whose token or
// user cannot be read is not visited either, but the walk then returns an
// errWindowsSessionsUnidentified error after visiting the rest, so a caller
// can tell a complete answer from one that may be missing a user.
func visitWindowsSessionTokens(accept func(state uint32) bool, visit func(sid string, token windows.Token)) error {
	sessions, err := windowsSessionAPI.list()
	if err != nil {
		return fmt.Errorf("enumerate Windows sessions: %w", err)
	}
	var unidentified []string
	for _, session := range sessions {
		if session.id == 0 || !accept(session.state) {
			continue
		}
		token, err := windowsSessionAPI.userToken(session.id)
		if errors.Is(err, windows.ERROR_NO_TOKEN) {
			continue
		}
		if err != nil {
			unidentified = append(unidentified, fmt.Sprintf("session %d: %v", session.id, err))
			continue
		}
		user, err := windowsSessionAPI.tokenUser(token)
		if err != nil {
			unidentified = append(unidentified, fmt.Sprintf("session %d: token user: %v", session.id, err))
		} else if sid := canonicalManifestTargetSID(user); sid != "" {
			visit(sid, token)
		}
		windowsSessionAPI.close(token)
	}
	if len(unidentified) > 0 {
		return fmt.Errorf("%w: %s", errWindowsSessionsUnidentified, strings.Join(unidentified, "; "))
	}
	return nil
}

// resolveWindowsGroupName resolves a configured group name to its SID.
func resolveWindowsGroupName(name string) (string, error) {
	sid, _, accType, err := windows.LookupSID("", name)
	if err != nil {
		return "", err
	}
	switch accType {
	case windows.SidTypeGroup, windows.SidTypeAlias, windows.SidTypeWellKnownGroup:
		return sid.String(), nil
	default:
		return "", fmt.Errorf("%q is not a group (SID type %d)", name, accType)
	}
}

// readWindowsMachineAccountDomainSID returns this computer's account domain
// SID (the prefix of every local account's SID).
func readWindowsMachineAccountDomainSID() (string, error) {
	computer, err := windows.ComputerName()
	if err != nil {
		return "", err
	}
	sid, _, accType, err := windows.LookupSID("", computer+`\`)
	if err != nil {
		sid, _, accType, err = windows.LookupSID("", computer)
	}
	if err != nil {
		return "", err
	}
	if accType != windows.SidTypeDomain {
		return "", fmt.Errorf("%s resolved to SID type %d, not the local account domain", computer, accType)
	}
	return sid.String(), nil
}

var procNetLocalGroupGetMembers = windows.NewLazySystemDLL("netapi32.dll").NewProc("NetLocalGroupGetMembers")

const (
	windowsNetMaxPreferredLength = 0xFFFFFFFF
	windowsNetErrorMoreData      = 234
)

// readWindowsLocalGroupDirectMembers lists the SIDs of a local group's
// direct members from the local account database (no directory query).
func readWindowsLocalGroupDirectMembers(groupSID string) ([]string, error) {
	sid, err := windows.StringToSid(groupSID)
	if err != nil {
		return nil, err
	}
	name, _, accType, err := sid.LookupAccount("")
	if err != nil {
		return nil, err
	}
	if accType != windows.SidTypeAlias {
		return nil, fmt.Errorf("%s is not a local group", groupSID)
	}
	groupName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	var members []string
	var resume uintptr
	for {
		var buffer *byte
		var read, total uint32
		status, _, _ := procNetLocalGroupGetMembers.Call(
			0,
			uintptr(unsafe.Pointer(groupName)),
			0,
			uintptr(unsafe.Pointer(&buffer)),
			windowsNetMaxPreferredLength,
			uintptr(unsafe.Pointer(&read)),
			uintptr(unsafe.Pointer(&total)),
			uintptr(unsafe.Pointer(&resume)),
		)
		if status != 0 && status != windowsNetErrorMoreData {
			if buffer != nil {
				_ = windows.NetApiBufferFree(buffer)
			}
			return nil, windows.Errno(status)
		}
		if buffer != nil && read > 0 {
			for _, entry := range unsafe.Slice((**windows.SID)(unsafe.Pointer(buffer)), read) {
				if entry != nil && entry.IsValid() {
					members = append(members, entry.String())
				}
			}
		}
		if buffer != nil {
			_ = windows.NetApiBufferFree(buffer)
		}
		if status != windowsNetErrorMoreData {
			return members, nil
		}
	}
}
