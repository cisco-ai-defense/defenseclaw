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
// existing rows kept, never revoked, until they next sign in. Well-known
// groups other than Everyone (Authenticated Users, INTERACTIVE, NETWORK,
// Local account, ...) are assigned at sign-in and appear in no account
// database, so they are decided from a token only; Everyone is in every
// token.
//
// Entries name a group by SID (S-1-5-32-544, S-1-12-1-...) or by name
// (Administrators, BUILTIN\Administrators, CONTOSO\Developers). A name is
// resolved to a SID while the directory answers and the resolution is
// cached; Entra ID group names cannot be resolved on the device, so Entra ID
// groups are listed by SID. A name that does not resolve and was never
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

// windowsGroupMembership is one user's membership of one configured group.
type windowsGroupMembership int

const (
	windowsGroupMembershipUnknown windowsGroupMembership = iota
	windowsGroupMember
	windowsGroupNotMember
	// windowsGroupUnresolved: the entry names a group that did not resolve
	// to a SID and has no cached SID, so it cannot be evaluated for anyone.
	windowsGroupUnresolved
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
}

// Seams: session tokens, name resolution, local group members and the
// machine SID. Tests replace them.
var (
	windowsActiveSessionGroups       = readWindowsActiveSessionGroups
	windowsResolveGroupName          = resolveWindowsGroupName
	windowsLocalGroupDirectMembers   = readWindowsLocalGroupDirectMembers
	windowsMachineAccountDomainSID   = readWindowsMachineAccountDomainSID
	windowsGroupNameLookupTimeout    = 3 * time.Second
	windowsGroupNameLookupCycleLimit = 15 * time.Second
)

// newWindowsEnrollmentGroups resolves the configured groups. cache is
// updated in place: the resolved names, and the token groups of every user
// signed in now.
func newWindowsEnrollmentGroups(
	include, exclude []string,
	sessions map[string][]string,
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
	for sid, groups := range sessions {
		canon := canonicalManifestTargetSID(sid)
		signedIn[canon] = canonicalWindowsGroupSIDs(groups)
		cache.Users[canon] = signedIn[canon]
	}
	groups := &windowsEnrollmentGroups{sessions: signedIn, cache: cache}
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
				entry.sid = cache.Names[key]
				logfSafely(logf, "enrollment", fmt.Sprintf("group %q did not resolve (%v); using its cached SID %s", entry.raw, err, entry.sid))
			case list == "exclude_groups":
				logfSafely(logf, "enrollment", fmt.Sprintf("enterprise.enrollment.exclude_groups %q does not resolve to a group on this computer (%v); it excludes no one this cycle (name the group by SID)", entry.raw, err))
			default:
				logfSafely(logf, "enrollment", fmt.Sprintf("enterprise.enrollment.include_groups %q does not resolve to a group on this computer (%v); users no other entry admits are pending this cycle (name the group by SID)", entry.raw, err))
			}
		}
		if entry.sid != "" && groups.localGroupSID(entry.sid) {
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

func boundedWindowsGroupNameLookup(name string, remaining time.Duration) (string, error) {
	if remaining <= 0 {
		return "", errors.New("group name lookup budget for this cycle is exhausted")
	}
	if remaining > windowsGroupNameLookupTimeout {
		remaining = windowsGroupNameLookupTimeout
	}
	type result struct {
		sid string
		err error
	}
	done := make(chan result, 1)
	lookup := windowsResolveGroupName
	go func() {
		sid, err := lookup(name)
		done <- result{sid, err}
	}()
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case r := <-done:
		if r.err == nil {
			if r.sid = canonicalWindowsGroupSID(r.sid); r.sid == "" {
				r.err = errors.New("group name lookup returned no SID")
			}
		}
		return r.sid, r.err
	case <-timer.C:
		return "", errors.New("group name lookup timed out")
	}
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

func (g *windowsEnrollmentGroups) membership(userSID string, entry windowsEnrollmentGroupEntry) windowsGroupMembership {
	if entry.sid == "" {
		return windowsGroupUnresolved
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
		return inList(groups)
	}
	if groups, cached := g.cache.Users[userSID]; cached {
		return inList(groups)
	}
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
// no other entry admits.
func (g *windowsEnrollmentGroups) decide(userSID string) (windowsEnrollmentDecision, string) {
	if !g.active() {
		return windowsEnrollmentEnrolled, ""
	}
	userSID = strings.ToUpper(strings.TrimSpace(userSID))
	var unknown []string
	for _, entry := range g.exclude {
		switch g.membership(userSID, entry) {
		case windowsGroupMember:
			return windowsEnrollmentExcluded, fmt.Sprintf("member of %q (enterprise.enrollment.exclude_groups)", entry.raw)
		case windowsGroupMembershipUnknown:
			unknown = append(unknown, entry.raw)
		}
	}
	if len(unknown) > 0 {
		return windowsEnrollmentUndecided, windowsGroupsPendingReason("exclude_groups", unknown)
	}
	if len(g.include) == 0 {
		return windowsEnrollmentEnrolled, ""
	}
	var unresolved []string
	for _, entry := range g.include {
		switch g.membership(userSID, entry) {
		case windowsGroupMember:
			return windowsEnrollmentEnrolled, ""
		case windowsGroupMembershipUnknown:
			unknown = append(unknown, entry.raw)
		case windowsGroupUnresolved:
			unresolved = append(unresolved, entry.raw)
		}
	}
	switch {
	case len(unresolved) > 0:
		return windowsEnrollmentUndecided, windowsGroupsUnresolvedReason(unresolved)
	case len(unknown) > 0:
		return windowsEnrollmentUndecided, windowsGroupsPendingReason("include_groups", unknown)
	}
	return windowsEnrollmentExcluded, "not a member of any enterprise.enrollment.include_groups group"
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
// deny-only groups count, since the user is a member).
func readWindowsActiveSessionGroups() (map[string][]string, error) {
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil {
		return nil, fmt.Errorf("enumerate Windows sessions: %w", err)
	}
	if sessions != nil {
		defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	}
	out := map[string][]string{}
	if count == 0 || sessions == nil {
		return out, nil
	}
	for _, session := range unsafe.Slice(sessions, count) {
		if session.State != windows.WTSActive {
			continue
		}
		var token windows.Token
		if err := windows.WTSQueryUserToken(session.SessionID, &token); err != nil {
			continue
		}
		user, err := token.GetTokenUser()
		if err != nil {
			token.Close()
			continue
		}
		sid := canonicalManifestTargetSID(user.User.Sid.String())
		groups, err := token.GetTokenGroups()
		if sid == "" || err != nil {
			token.Close()
			continue
		}
		for _, group := range groups.AllGroups() {
			if group.Sid == nil || group.Attributes&windows.SE_GROUP_LOGON_ID == windows.SE_GROUP_LOGON_ID {
				continue
			}
			out[sid] = append(out[sid], group.Sid.String())
		}
		if _, ok := out[sid]; !ok {
			out[sid] = []string{}
		}
		token.Close()
	}
	for sid, groups := range out {
		out[sid] = canonicalWindowsGroupSIDs(groups)
	}
	return out, nil
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
