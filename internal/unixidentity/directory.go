//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"fmt"
	"maps"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Directory facts for a Linux account, resolved through NSS and realmd.
//
// The backend that owns an account is found by asking each directory
// service named on the passwd line of nsswitch.conf for the uid with
// `getent -s <service>`; the first that answers owns it, and an account no
// directory service knows is local. The domain comes from the
// fully-qualified name SSSD (alice@corp.example.com) or winbind
// (CORP\alice) reports, and groups from initgroups plus group lookups for
// all of their ids. The realm and directory type of an SSSD or winbind
// account come from realmd, which any account may ask (realm_linux.go).
// UPN and mail need SSSD InfoPipe, which only root may call, so the root
// guardian adds them (enterprisehooks identity spool).

// directoryService describes one NSS passwd service DefenseClaw recognises.
type directoryService struct {
	directory useridentity.Directory
	source    string
}

// directoryServices are the NSS passwd services that name a directory. The
// sss service serves AD, IPA and plain LDAP domains alike, so its directory
// comes from the realm that serves the account's domain.
var directoryServices = map[string]directoryService{
	"sss":        {source: useridentity.SourceSSSD},
	"winbind":    {directory: useridentity.DirectoryActiveDirectory, source: useridentity.SourceWinbind},
	"ldap":       {directory: useridentity.DirectoryLDAP, source: useridentity.SourceNSSLDAP},
	"himmelblau": {directory: useridentity.DirectoryEntraID, source: "himmelblau"},
	"aad":        {directory: useridentity.DirectoryEntraID, source: "nss_aad"},
}

// maxDirectoryGroups bounds how many group ids are named per account. An
// Active Directory token holds about a thousand groups at most; an account
// past the bound has no facts (the lookup fails, and the default profile
// applies as default_lookup_failed) instead of facts with some of its
// groups missing, which would select a profile on part of its membership.
const maxDirectoryGroups = 2048

// A cold SSSD answers every group id with a directory query of its own
// (about 30 ms), so one getent call for a few hundred ids outlasts the
// seconds a single command gets, and its failure used to leave the ids as
// numbers that no assignment matches (GAP-0138). The ids are named
// groupQueryBatch at a time, groupQueryParallel batches at once, and a batch
// that fails fails the lookup.
const (
	groupQueryBatch    = 64
	groupQueryParallel = 4
)

// DirectoryFactsForUID resolves the verified directory facts of uid. The
// caller has verified the uid (peer credentials or a per-user credential);
// everything here comes from the host's own account database.
//
// A lookup that does not finish fails as a whole: facts that lack the
// groups, or take a directory account for a local one, would be cached as
// resolved (the gateway keeps them for 15 minutes) and select the default
// profile as though the account had no groups.
func (r *NSSResolver) DirectoryFactsForUID(uid int, now time.Time) (useridentity.DirectoryFacts, error) {
	account, err := r.LookupUID(uid)
	if err != nil {
		return useridentity.DirectoryFacts{}, err
	}
	facts := useridentity.DirectoryFacts{
		Directory:  useridentity.DirectoryLocal,
		Source:     useridentity.SourceNSSFiles,
		Assurance:  useridentity.AssuranceVerified,
		ResolvedAt: now,
	}
	if data, readErr := readSmallFile(nsswitchPath, 1<<20); readErr == nil {
		for _, service := range ParseNSSwitchPasswdServices(string(data)) {
			known, ok := directoryServices[service]
			if !ok {
				continue
			}
			if _, lookupErr := r.LookupUIDInService(service, uid); lookupErr != nil {
				if IsNotFound(lookupErr) {
					continue
				}
				// A directory that did not answer is not one that does not
				// own the account.
				return useridentity.DirectoryFacts{}, lookupErr
			}
			facts.Directory, facts.Source = known.directory, known.source
			bare, domain := useridentity.SplitQualifiedName(account.Name)
			if domain != "" {
				facts.Domain = domain
				if strings.Contains(domain, ".") {
					facts.Realm = strings.ToUpper(domain)
					// sAMAccountName@REALM, the Kerberos principal SSSD
					// and winbind accounts authenticate as.
					facts.Principal = useridentity.NormalizePrincipal(bare + "@" + facts.Realm)
				}
			}
			break
		}
	}
	groups, err := r.groupNames(account)
	if err != nil {
		return useridentity.DirectoryFacts{}, fmt.Errorf("unixidentity: groups of %s: %w", account.Name, err)
	}
	facts.Groups = groups
	if facts.Source == useridentity.SourceSSSD || facts.Source == useridentity.SourceWinbind {
		applyRealm(&facts, account.Name, hostRealms(r.context()))
	}
	return facts, nil
}

// groupNames names the account's groups with getent group calls of
// groupQueryBatch ids each. An id no group answers for is kept as its number.
func (r *NSSResolver) groupNames(account Account) ([]string, error) {
	ids, err := r.GroupIDs(account)
	if err != nil {
		return nil, err
	}
	if len(ids) > maxDirectoryGroups {
		return nil, fmt.Errorf("in %d groups, more than the %d DefenseClaw names", len(ids), maxDirectoryGroups)
	}
	var (
		mu    sync.Mutex
		wg    sync.WaitGroup
		names = make(map[int]string, len(ids))
		first error
		slots = make(chan struct{}, groupQueryParallel)
	)
	for start := 0; start < len(ids); start += groupQueryBatch {
		batch := ids[start:min(start+groupQueryBatch, len(ids))]
		slots <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-slots; wg.Done() }()
			found, queryErr := r.groupBatchNames(batch)
			mu.Lock()
			defer mu.Unlock()
			if queryErr != nil && first == nil {
				first = queryErr
			}
			maps.Copy(names, found)
		}()
	}
	wg.Wait()
	if first != nil {
		return nil, first
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if name := names[id]; name != "" {
			out = append(out, name)
		} else {
			out = append(out, strconv.Itoa(id))
		}
	}
	return out, nil
}

// groupBatchNames asks one getent group call for the names of ids.
func (r *NSSResolver) groupBatchNames(ids []int) (map[int]string, error) {
	keys := make([]string, 0, len(ids))
	for _, id := range ids {
		keys = append(keys, strconv.Itoa(id))
	}
	result, err := r.query("group", keys...)
	if err != nil {
		return nil, err
	}
	// Exit 2 means some id has no group, which stays a number.
	if result.exitCode != getentExitOK && result.exitCode != getentExitNotFound {
		return nil, fmt.Errorf("getent group exited %d", result.exitCode)
	}
	names := make(map[int]string, len(ids))
	for _, line := range nonEmptyLines(string(result.stdout)) {
		if gid, name, ok := parseGroupName(line); ok {
			names[gid] = name
		}
	}
	return names, nil
}

// ParseNSSwitchPasswdServices lists the services on the passwd line of an
// nsswitch.conf, in order, lower-cased, without actions.
func ParseNSSwitchPasswdServices(content string) []string {
	for _, line := range strings.Split(content, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		key, sources, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok || strings.TrimSpace(key) != "passwd" {
			continue
		}
		var out []string
		for _, source := range strings.Fields(sources) {
			if !strings.HasPrefix(source, "[") {
				out = append(out, strings.ToLower(source))
			}
		}
		return out
	}
	return nil
}

// parseGroupName reads the name and gid of a group(5) line. Unlike
// ParseGroupLine it accepts the spaces directory group names carry ("domain
// users@corp.example.com"): the name is only reported, never used to
// resolve an account.
func parseGroupName(line string) (int, string, bool) {
	fields := strings.Split(strings.TrimRight(line, "\r\n"), ":")
	if len(fields) != 4 || fields[0] == "" || len(fields[0]) > maxNameLength {
		return 0, "", false
	}
	for _, r := range fields[0] {
		if r < 0x20 || r == 0x7f || r == ',' {
			return 0, "", false
		}
	}
	gid, err := parseID(fields[2], "gid")
	if err != nil {
		return 0, "", false
	}
	return gid, fields[0], true
}
