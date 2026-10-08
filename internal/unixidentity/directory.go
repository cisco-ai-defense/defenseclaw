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
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Directory facts for a Linux account, resolved through NSS and realmd.
//
// The backend that owns an account is found by asking each directory
// service named on the passwd line of nsswitch.conf for the uid with
// `getent -s <service>`; the first that answers owns it, and an account no
// directory service knows, or one /etc/passwd holds, is local. The domain
// comes from the fully-qualified name winbind (CORP\alice) or another
// directory module reports, a NetBIOS domain by the DNS name of its realm,
// and groups from initgroups plus group lookups for all of their ids. The
// realm and directory type of a winbind account come from realmd, which any
// account may ask (realm_linux.go).
//
// SSSD serves Active Directory, IPA and plain LDAP domains side by side, and
// the name it gives an account does not say which domain holds it: with
// use_fully_qualified_names = False every domain names its accounts bare, and
// a plain LDAP domain may name them by e-mail address (bob@corp.example.com).
// An SSSD account therefore takes its domain from its SID, which SSSD holds
// for the uid itself (sssd_nss_linux.go): it gets the domain, realm and
// principal of a joined realm only when SSSD holds a user of the same name
// with the same SID in that realm's domain, and groups only inside the
// domain of its SID. An account without a SID, such as one of a plain LDAP
// domain, gets no realm and no principal (GAP-0497, GAP-0568, GAP-0605).
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

// A cold SSSD answers every group id with a directory query of its own
// (about 30 ms), so one getent call for a few hundred ids outlasts the
// seconds a single command gets, and its failure used to leave the ids as
// numbers that no assignment matches (GAP-0138). The ids are named
// groupQueryBatch at a time, and a batch that fails fails the lookup. The
// batches run one after the other: SSSD fills its cache one request at a
// time, so four getent calls at once each finished only after the calls
// before it, and the last ones ran past the five seconds one command gets
// while the first finished within two (GAP-0230).
const groupQueryBatch = 64

// DirectoryFactsForUID resolves the verified directory facts of uid. The
// caller has verified the uid (peer credentials or a per-user credential);
// everything here comes from the host's own account database.
//
// A lookup that does not finish fails as a whole: facts that lack the
// groups, or take a directory account for a local one, would be cached as
// resolved (the gateway keeps them for 15 minutes) and select the default
// profile as though the account had no groups. So does an SSSD NSS
// responder that does not answer, while SSSD is stopped or restarting.
func (r *NSSResolver) DirectoryFactsForUID(uid int, now time.Time) (useridentity.DirectoryFacts, error) {
	return r.directoryFactsForUID(uid, now, true)
}

// DirectoryFactsWithoutGroupsForUID is for the guardian spool. The Linux
// gateway resolves groups itself, so naming them here can consume the time
// reserved for the privileged InfoPipe UPN lookup.
func (r *NSSResolver) DirectoryFactsWithoutGroupsForUID(uid int, now time.Time) (useridentity.DirectoryFacts, error) {
	return r.directoryFactsForUID(uid, now, false)
}

func (r *NSSResolver) directoryFactsForUID(uid int, now time.Time, includeGroups bool) (useridentity.DirectoryFacts, error) {
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
	// /etc/passwd is authoritative for a matching local name and uid.
	// Check it before directory probes so an unavailable backend cannot
	// make a local account's facts fail.
	local, localErr := LocalAccounts(r.context())
	if localErr != nil && !errors.Is(localErr, os.ErrNotExist) {
		return useridentity.DirectoryFacts{}, localErr
	}
	_, isLocal := local[account.Name]
	isLocal = isLocal && local[account.Name] == uid
	// sssd is the connection to the SSSD NSS responder for an SSSD account,
	// sid the SID SSSD holds for its uid ("" for none) and inDomain the SSSD
	// domain that holds a user of its name with that SID.
	var (
		sssd          *sssdNSS
		sid, inDomain string
	)
	if !isLocal {
		if data, readErr := readSmallFile(nsswitchPath, 1<<20); readErr == nil {
			for _, service := range ParseNSSwitchServices(string(data), "passwd") {
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
				switch {
				case known.source == useridentity.SourceSSSD:
					if sssd, err = dialSSSDNSS(r.context()); err != nil {
						return useridentity.DirectoryFacts{}, err
					}
					defer sssd.Close()
					if sid, err = sssdAccountSID(sssd, uid); err != nil {
						return useridentity.DirectoryFacts{}, err
					}
					if inDomain, err = r.applySSSDDomain(&facts, sssd, account.Name, sid); err != nil {
						return useridentity.DirectoryFacts{}, err
					}
				case domain == "":
				case known.directory == useridentity.DirectoryEntraID:
					// The aad module, and Himmelblau with cn_name_mapping =
					// false, name an Entra ID account by its UPN. It has no
					// Kerberos realm, and the UPN is the principal Windows
					// reports for the same user. Himmelblau's default
					// (cn_name_mapping = true) names it by the short name, which
					// carries no domain: such an account has no UPN here
					// (GAP-0328).
					facts.Domain = strings.ToLower(domain)
					facts.UPN = useridentity.NormalizeUPN(account.Name)
					facts.Principal = facts.UPN
				default:
					// Lower case, as Windows reports a NetBIOS domain it knows
					// no DNS name for; applyRealm gives the DNS name of the
					// realm a NetBIOS domain names.
					facts.Domain = strings.ToLower(domain)
					if strings.Contains(domain, ".") {
						facts.Realm = strings.ToUpper(domain)
						// sAMAccountName@REALM, the Kerberos principal winbind
						// accounts authenticate as, in the UPN form.
						facts.Principal = useridentity.AccountPrincipal(bare, facts.Realm)
					}
				}
				break
			}
		}
	}
	if includeGroups {
		ids, err := r.accountGroupIDs(account, inDomain)
		if err == nil && sssd != nil {
			ids, err = sssdGroupsOfDomain(sssd, ids, account.GID, sidDomain(sid))
		}
		if err != nil {
			return useridentity.DirectoryFacts{}, fmt.Errorf("unixidentity: groups of %s: %w", account.Name, err)
		}
		groups, err := r.groupNames(ids)
		if err != nil {
			return useridentity.DirectoryFacts{}, fmt.Errorf("unixidentity: groups of %s: %w", account.Name, err)
		}
		facts.Groups = groups
	}
	if facts.Source == useridentity.SourceWinbind {
		realms, realmErr := hostRealms(r.context())
		if realmErr != nil {
			return useridentity.DirectoryFacts{}, fmt.Errorf("unixidentity: realmd lookup: %w", realmErr)
		}
		applyRealm(&facts, account.Name, realms)
	}
	return facts, nil
}

// applySSSDDomain gives an SSSD account the domain, realm, directory type
// and principal of the joined realm that holds it, and returns the SSSD
// domain that confirmed it ("" for none). A joined realm holds the account
// when SSSD holds a SID for the uid and a user of the account's name with
// that same SID in the realm's domain, asked in the domain\name form, which
// SSSD looks up in that domain only (sidOfUserInDomain). A qualified name
// (use_fully_qualified_names = True, what realm join writes) is asked in the
// domain it names; a child domain may inherit a joined parent only if
// SSSD resolves the same SID in the parent. A short name is asked in
// each joined SSSD realm. The same SID is the same account,
// so the realm, principal and groups of an account never go to another
// account that only shares its name: a plain LDAP account of the same short
// name, one named by an e-mail address in the joined domain, or one SSSD
// finds through a UPN or e-mail search. An account without a SID, or one no
// joined realm holds, gets no realm, principal or directory type, and no
// domain from a name that only looks qualified (bob@corp.example.com in a
// plain LDAP domain).
func (r *NSSResolver) applySSSDDomain(facts *useridentity.DirectoryFacts, sssd *sssdNSS, name, sid string) (string, error) {
	bare, domain := useridentity.SplitQualifiedName(name)
	if domain != "" && !strings.Contains(domain, ".") {
		// The SSSD name of a domain with no DNS name, which names no realm.
		facts.Domain = strings.ToLower(domain)
	}
	if sidDomain(sid) == "" {
		return "", nil
	}
	realms, err := hostRealms(r.context())
	if err != nil {
		return "", fmt.Errorf("unixidentity: realmd lookup: %w", err)
	}
	var candidates []string
	if strings.Contains(domain, ".") {
		candidates = []string{strings.ToLower(domain)}
	} else {
		for _, realm := range realms {
			if strings.EqualFold(realm.ClientSoftware, "sssd") && realm.Domain != "" {
				candidates = append(candidates, realm.Domain)
			}
		}
	}
	for _, candidate := range candidates {
		held, err := sssd.sidOfUserInDomain(candidate, bare)
		if err != nil {
			return "", fmt.Errorf("unixidentity: SSSD SID of %s in %s: %w", bare, candidate, err)
		}
		if !strings.EqualFold(held, sid) {
			continue
		}
		realm, ok := realmFor(candidate, useridentity.SourceSSSD, realms)
		if !ok {
			// A child DNS name alone does not prove membership in a joined
			// parent realm: an independent LDAP domain can share its suffix.
			// Require SSSD to resolve this same SID in the parent domain.
			for _, parent := range realms {
				if !strings.EqualFold(parent.ClientSoftware, "sssd") ||
					!strings.HasSuffix(candidate, "."+parent.Domain) {
					continue
				}
				parentSID, lookupErr := sssd.sidOfUserInDomain(parent.Domain, bare)
				if lookupErr != nil {
					return "", fmt.Errorf("unixidentity: SSSD SID of %s in %s: %w", bare, parent.Domain, lookupErr)
				}
				if strings.EqualFold(parentSID, sid) && len(parent.Domain) > len(realm.Domain) {
					realm, ok = parent, true
				}
			}
		}
		if !ok {
			continue
		}
		facts.Domain = candidate
		facts.Realm = strings.ToUpper(candidate)
		if candidate == realm.Domain && realm.Name != "" {
			facts.Realm = realm.Name
		}
		facts.Directory = realmDirectory(realm)
		facts.Principal = useridentity.AccountPrincipal(bare, facts.Realm)
		return candidate, nil
	}
	return "", nil
}

// sssdAccountSID returns the SID SSSD holds for the user with uid, "" for
// none. A SID that SSSD maps back to another uid is not the account's: a
// domain that copies the SIDs of another domain holds the uid, not the SID.
func sssdAccountSID(sssd *sssdNSS, uid int) (string, error) {
	sid, err := sssd.sidByUID(uid)
	if err != nil {
		return "", fmt.Errorf("unixidentity: SSSD SID of uid %d: %w", uid, err)
	}
	if sid == "" {
		return "", nil
	}
	mapped, err := sssd.uidOfSID(sid)
	if err != nil {
		return "", fmt.Errorf("unixidentity: SSSD uid of %s: %w", sid, err)
	}
	if mapped != uid {
		return "", nil
	}
	return sid, nil
}

// accountGroupIDs lists the groups of account with initgroups. An SSSD
// account a joined domain confirmed is asked for in the domain\name form,
// which SSSD looks up in that domain only: by its short name SSSD may find
// another domain's account of that name and list its groups (GAP-0563).
func (r *NSSResolver) accountGroupIDs(account Account, inDomain string) ([]int, error) {
	bare, _ := useridentity.SplitQualifiedName(account.Name)
	if inDomain != "" {
		ids, err := r.GroupIDs(Account{Name: inDomain + `\` + bare, GID: account.GID})
		if !IsNotFound(err) {
			return ids, err
		}
	}
	return r.GroupIDs(account)
}

// sssdGroupsOfDomain keeps the groups of an SSSD account that are inside
// its own domain, the domain of its SID (domainSID, "" for an account
// without one): groups SSSD holds a SID for in that domain, and, for an
// account without a SID, the groups SSSD holds no SID for. initgroups looks
// the account up by name, and two SSSD domains may hold the same short name,
// so it may list the other account's groups (GAP-0563). A group of the
// host's /etc/group counts for every account, and the primary group, which
// comes with the uid's own entry, always counts. A group SSSD could not
// answer for fails the lookup.
func sssdGroupsOfDomain(sssd *sssdNSS, ids []int, primary int, domainSID string) ([]int, error) {
	local, err := localGroupIDs()
	if err != nil {
		return nil, err
	}
	kept := make([]int, 0, len(ids))
	for _, id := range ids {
		if id == primary {
			kept = append(kept, id)
			continue
		}
		sid, err := sssd.sidByGID(id)
		if err != nil {
			return nil, fmt.Errorf("SSSD SID of gid %d: %w", id, err)
		}
		if (sid != "" && domainSID != "" && sidDomain(sid) == domainSID) || (sid == "" && (domainSID == "" || local[id])) {
			kept = append(kept, id)
		}
	}
	return kept, nil
}

// localGroupIDs reads the gids /etc/group holds. A missing file holds none.
func localGroupIDs() (map[int]bool, error) {
	data, err := readSmallFile(localGroupPath, 16<<20)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ids := map[int]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		if gid, _, ok := parseGroupName(line); ok {
			ids[gid] = true
		}
	}
	return ids, nil
}

// groupNames names group ids with getent group calls of groupQueryBatch ids
// each, one after the other. An id no group answers for is kept as its
// number.
func (r *NSSResolver) groupNames(ids []int) ([]string, error) {
	if len(ids) > maxDirectoryGroups {
		return nil, fmt.Errorf("in %d groups, more than the %d DefenseClaw names", len(ids), maxDirectoryGroups)
	}
	names := make(map[int]string, len(ids))
	for start := 0; start < len(ids); start += groupQueryBatch {
		found, queryErr := r.groupBatchNames(ids[start:min(start+groupQueryBatch, len(ids))])
		if queryErr != nil {
			return nil, queryErr
		}
		maps.Copy(names, found)
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

// groupBatchNames asks one getent group call for the names of ids. The
// member lists getent prints are dropped as they arrive (query), so a batch
// of large directory groups stays within the output limit.
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

// ParseNSSwitchServices lists the services on the line of database
// ("passwd", "group") of an nsswitch.conf, in order, lower-cased, without
// actions.
func ParseNSSwitchServices(content, database string) []string {
	for _, line := range strings.Split(content, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		key, sources, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok || strings.TrimSpace(key) != database {
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

// Group lookups by name.
//
// Profile assignments name groups, and the gateway warns when the host does
// not know a group by the name an assignment spells (renamed or deleted in
// the directory). Two directory setups make that answer misleading:
//
//   - Himmelblau answers an Entra group only by gid or object id: `getent
//     group NAME` finds nothing by design, while `id` and initgroups name the
//     group. Its "no such group" by name says nothing (GAP-0292).
//   - SSSD joined with realm join names groups name@domain
//     (use_fully_qualified_names = True), so the short name an assignment
//     spells is unknown while the qualified one exists (GAP-0332).

// groupNameUnsearchableServices are NSS group services that cannot look a
// group up by its name.
var groupNameUnsearchableServices = map[string]bool{"himmelblau": true}

// GroupNameLookupDefinitive reports whether a "no such group" answer to a
// lookup by name is definitive on this host: false when the group line of
// nsswitch.conf names a service that cannot look groups up by name, or the
// file cannot be read.
func GroupNameLookupDefinitive() bool {
	data, err := readSmallFile(nsswitchPath, 1<<20)
	if err != nil {
		return errors.Is(err, os.ErrNotExist)
	}
	for _, service := range ParseNSSwitchServices(string(data), "group") {
		if groupNameUnsearchableServices[service] {
			return false
		}
	}
	return true
}

// QualifiedGroupName returns name@domain for the first realm the host is
// joined to (realmd) that has a group of that name, or "" when name is
// already qualified or no realm has it.
func QualifiedGroupName(ctx context.Context, r Resolver, name string) string {
	if r == nil || name == "" || strings.ContainsAny(name, `@\`) {
		return ""
	}
	realms, err := hostRealms(ctx)
	if err != nil {
		return ""
	}
	for _, realm := range realms {
		if realm.Domain == "" {
			continue
		}
		candidate := name + "@" + realm.Domain
		if _, err := r.LookupGroup(candidate); err == nil {
			return candidate
		}
	}
	return ""
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
