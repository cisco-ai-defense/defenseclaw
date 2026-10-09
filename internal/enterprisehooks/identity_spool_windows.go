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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// On Windows the SYSTEM enumerator writes one identity record per user in
// its token-group cache: the directory facts it resolves as SYSTEM (the
// identity store, the join state, TranslateNameW) and the user's groups,
// each SID followed by its DOMAIN\name where the name resolves. The
// gateway's service account cannot read the SYSTEM-only group cache itself.

const (
	// windowsIdentityGroupNameLimit bounds the group SIDs named per user.
	windowsIdentityGroupNameLimit = 128
	// windowsIdentityGroupNameBudget bounds the time spent naming them.
	windowsIdentityGroupNameBudget = 2 * time.Second
)

// WriteWindowsIdentitySpool replaces dir's records with one per user in the
// group cache. emails holds each account's connector addresses by upper-case
// SID (WindowsConnectorEmails), nil when ai_discovery.include_user_email is
// off. setOwnership applies the guardian authorization protection (SYSTEM
// and Administrators, read for the gateway service) to the directory and to
// each new file before it is renamed into place.
func WriteWindowsIdentitySpool(dir string, cache *WindowsEnrollmentGroupCache, emails map[string]map[string]string,
	setOwnership func(string) error, logf func(string, ...any)) error {
	if dir == "" || cache == nil {
		return nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create identity spool: %w", err)
	}
	if setOwnership != nil {
		if err := setOwnership(dir); err != nil {
			return fmt.Errorf("set identity spool protection: %w", err)
		}
	}
	keep := map[string]bool{}
	sids := make([]string, 0, len(cache.Users))
	for sid := range cache.Users {
		sids = append(sids, sid)
	}
	sort.Strings(sids)
	for _, sid := range sids {
		key := strings.ToUpper(strings.TrimSpace(sid))
		if !validIdentitySpoolKey(key) {
			continue
		}
		name := key + ".json"
		keep[strings.ToLower(name)] = true
		now := time.Now().UTC()
		facts := useridentity.WindowsDirectoryFacts(key, 0)
		groupSIDs := cache.Users[sid]
		names := useridentity.WindowsGroupNames(groupSIDs, windowsIdentityGroupNameLimit, windowsIdentityGroupNameBudget)
		groups := make([]string, 0, 2*len(groupSIDs))
		for i, groupSID := range groupSIDs {
			groups = append(groups, groupSID)
			if i < len(names) && names[i] != groupSID {
				groups = append(groups, names[i])
			}
		}
		facts.Groups = groups
		// Without an active session this cycle the groups are the last
		// session token, which can miss a group the account has gained
		// since (an Entra group after a restart, GAP-0243).
		facts.GroupsPartial = !cache.SignedIn[sid]
		if facts.ResolvedAt.IsZero() {
			facts.ResolvedAt = now
		}
		record := IdentitySpoolRecord{Key: key, User: windowsIdentitySpoolUser(key), UpdatedAt: now, Facts: facts,
			ConnectorEmails: emails[key]}
		switch {
		case facts.UPN != "" && facts.Source == useridentity.SourceWindowsIdentityStore:
			record.UPNSource = UPNSourceIdentityStore
		case facts.UPN != "":
			record.UPNSource = UPNSourceTranslateName
		}
		if previous, err := ReadIdentitySpoolRecord(dir, key, nil); err == nil {
			record = KeepLastKnownUPN(record, previous)
		}
		if err := writeIdentitySpoolFile(dir, name, record, setOwnership); err != nil && logf != nil {
			logf("[hook-enumerator] WARN identity facts for %s: %v", key, err)
		}
	}
	if entries, err := os.ReadDir(dir); err == nil {
		for _, entry := range entries {
			if !keep[strings.ToLower(entry.Name())] {
				_ = os.RemoveAll(filepath.Join(dir, entry.Name()))
			}
		}
	}
	return nil
}

// windowsIdentitySpoolUser names a record's account DOMAIN\account, as the
// Linux and macOS records name theirs, so a record maps to an account
// without a SID lookup; "" when the SID no longer resolves.
func windowsIdentitySpoolUser(sid string) string {
	names := useridentity.WindowsGroupNames([]string{sid}, 1, windowsIdentityGroupNameBudget)
	if len(names) == 1 && names[0] != sid {
		return names[0]
	}
	return ""
}

// windowsConnectorEmailWarned keeps an unreadable connector file from being
// reported at every enumerator cycle.
var windowsConnectorEmailWarned sync.Map

// WindowsConnectorEmails reads, as SYSTEM, the Claude Code and Codex account
// address of each enrolled profile in manifest (ai_discovery.include_user_email),
// keyed by upper-case SID. Each is read from the profile owner's own file and
// only through ordinary folders: a file reached through a link or junction,
// one that cannot be read, or one that is not a regular file gives no address
// and a named warning, logged once per account, connector and reason.
func WindowsConnectorEmails(manifest Manifest, logf func(string, ...any)) map[string]map[string]string {
	out := map[string]map[string]string{}
	seen := map[string]bool{}
	for _, target := range manifest.Targets {
		if target.Enabled != nil && !*target.Enabled {
			continue
		}
		key := strings.ToUpper(strings.TrimSpace(target.SID))
		home := filepath.Clean(strings.TrimSpace(target.UserHome))
		if !validIdentitySpoolKey(key) || home == "." || seen[key] {
			continue
		}
		seen[key] = true
		for _, connector := range []string{"claudecode", "codex"} {
			email, err := windowsProfileConnectorEmail(connector, home)
			if err == nil {
				if out[key] == nil {
					out[key] = map[string]string{}
				}
				out[key][connector] = email
				continue
			}
			if !errors.Is(err, useridentity.ErrEmailFileUnreadable) || logf == nil {
				continue
			}
			if _, warned := windowsConnectorEmailWarned.LoadOrStore(key+"\x00"+connector+"\x00"+err.Error(), true); !warned {
				logf("[hook-enumerator] WARN include_user_email: no %s address for %s: %v", connector, key, err)
			}
		}
	}
	return out
}

// windowsProfileConnectorEmail reads one address; tests replace it.
var windowsProfileConnectorEmail = useridentity.ProfileEmailForConnector
