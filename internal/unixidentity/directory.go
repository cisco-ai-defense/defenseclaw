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
	"slices"
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
// directory service knows, or one /etc/passwd holds, is local. The domain
// comes from the fully-qualified name winbind (CORP\alice) or an Entra ID
// module reports, a NetBIOS domain by the DNS name of its realm, and groups
// from initgroups plus group lookups for all of their ids. An nss_ldap
// (nslcd) name gives no domain: nslcd names an account by its uid
// attribute, which may be an e-mail address (GAP-0730). The
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
// with the same SID in that realm's domain. A domain-qualified initgroups
// lookup supplies its groups, including trusted-domain memberships. An
// account without a SID, such as one of a plain LDAP domain, gets no
// realm and no principal (GAP-0497, GAP-0568, GAP-0605).
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
		data, readErr := readSmallFile(nsswitchPath, 1<<20)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return useridentity.DirectoryFacts{}, fmt.Errorf("unixidentity: read NSS configuration: %w", readErr)
		}
		if readErr == nil {
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
				case known.source == useridentity.SourceNSSLDAP:
					// nslcd names an account by its uid attribute, which is an
					// e-mail address for the Okta LDAP Interface and for
					// directories that name accounts by mail, so the name gives
					// no domain, realm or principal: an LDAP bob@corp.example.com
					// took the principal of the AD bob (GAP-0730).
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
					// winbind: lower case, as Windows reports a NetBIOS domain
					// it knows no DNS name for; applyRealm gives the DNS name
					// of the realm a NetBIOS domain names.
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
		ids, qualified, err := r.accountGroupIDs(account, inDomain)
		if err == nil && sssd != nil && !qualified {
			ids, err = r.sssdGroupsOfDomain(sssd, ids, account, sidDomain(sid))
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
		facts.AccountDomain, err = r.winbindAccountDomain(account, realms)
		if err != nil {
			return useridentity.DirectoryFacts{}, err
		}
	}
	return facts, nil
}

// winbindAccountDomain is the NetBIOS domain winbind confirms for an
// account, which a users entry DOMAIN\user names: the domain of the
// DOMAIN\name winbind reports, or, for the bare name winbind reports with
// use default domain = yes, the NetBIOS name of its realm that winbind
// answers with the same uid when asked as NETBIOS\name. A NetBIOS name no
// directory confirms is not taken: the NetBIOS domain of corp.example.com
// may be EXAMPLE, and a guess may name a trusted domain (GAP-0456).
func (r *NSSResolver) winbindAccountDomain(account Account, realms []Realm) (string, error) {
	bare, domain := useridentity.SplitQualifiedName(account.Name)
	if strings.Contains(account.Name, `\`) {
		return domain, nil
	}
	if domain != "" {
		return "", nil
	}
	realm, ok := realmFor("", useridentity.SourceWinbind, realms)
	if !ok {
		return "", nil
	}
	for _, candidate := range netBIOSCandidates(realm.NetBIOS, realm.Domain) {
		held, err := r.LookupUserInService("winbind", candidate+`\`+bare)
		if err != nil {
			if IsNotFound(err) {
				continue
			}
			return "", fmt.Errorf("unixidentity: winbind account domain of %s: %w", account.Name, err)
		}
		if held.UID == account.UID {
			return candidate, nil
		}
	}
	return "", nil
}

// sssdAccountDomain is the NetBIOS (flat) name of the Active Directory
// domain SSSD confirmed an account in by its SID: a candidate SSSD holds
// the same SID for when asked as FLAT\name. The candidates are the flat
// domain of the account own name (full_name_format = %3$s\%1$s), the
// realm NetBIOS name, the Samba workgroup and the first label of the DNS
// domain, and then the flat name the domain's controllers announce
// (domainShort, adcli info), which the others miss when the first label is
// longer than 15 characters (an Entra Domain Services domain) or is not the
// NetBIOS name (GAP-1095). Only the answer of SSSD confirms one, so a first
// label is never taken on its own (GAP-0456).
func sssdAccountDomain(sssd *sssdNSS, name, dnsDomain, netBIOS, sid string, domainShort func(string) (string, error)) (string, error) {
	bare, nameDomain := useridentity.SplitQualifiedName(name)
	var candidates []string
	if strings.Contains(name, `\`) && !strings.Contains(nameDomain, ".") {
		candidates = append(candidates, nameDomain)
	}
	candidates = append(candidates, netBIOSCandidates(netBIOS, dnsDomain)...)
	confirm := func(candidate string) (bool, error) {
		held, err := sssd.sidOfUserInDomain(candidate, bare)
		if err != nil {
			return false, fmt.Errorf("unixidentity: SSSD account domain of %s in %s: %w", bare, candidate, err)
		}
		return held != "" && strings.EqualFold(held, sid), nil
	}
	for _, candidate := range candidates {
		if ok, err := confirm(candidate); err != nil {
			return "", err
		} else if ok {
			return candidate, nil
		}
	}
	if domainShort == nil {
		return "", nil
	}
	short, err := domainShort(dnsDomain)
	if err != nil {
		return "", err
	}
	announced := strings.TrimSpace(short)
	if !validNetBIOSCandidate(announced) || slices.ContainsFunc(candidates, func(seen string) bool { return strings.EqualFold(seen, announced) }) {
		return "", nil
	}
	if ok, err := confirm(announced); err != nil || !ok {
		return "", err
	}
	return strings.ToUpper(announced), nil
}

// netBIOSCandidates lists the NetBIOS names a joined domain may have, to be
// confirmed by its directory: the one realmd reports, the Samba workgroup
// and the upper-cased first label of the DNS domain.
func netBIOSCandidates(netBIOS, dnsDomain string) []string {
	first, _, _ := strings.Cut(dnsDomain, ".")
	var out []string
	for _, candidate := range []string{netBIOS, sambaWorkgroup(), strings.ToUpper(first)} {
		candidate = strings.TrimSpace(candidate)
		if !validNetBIOSCandidate(candidate) ||
			slices.ContainsFunc(out, func(seen string) bool { return strings.EqualFold(seen, candidate) }) {
			continue
		}
		out = append(out, candidate)
	}
	return out
}

// validNetBIOSCandidate accepts a name that can be a NetBIOS domain: 1 to 15
// characters, none of them a separator.
func validNetBIOSCandidate(candidate string) bool {
	return candidate != "" && len(candidate) <= 15 && !strings.ContainsAny(candidate, `\/@. :,`)
}

// adcliPaths are where adcli, the tool realm join uses to join an Active
// Directory domain for SSSD, is installed; adcliTool picks the trusted one
// (replaceable in tests).
var (
	adcliPaths = []string{"/usr/sbin/adcli", "/usr/bin/adcli"}
	adcliTool  = func() (string, error) { return firstTrustedTool(adcliPaths...) }
)

// adcliAnswerTimeout bounds one adcli info call; adcliRetryAfter is how long
// a domain whose controllers did not announce a flat name is not asked
// again.
const (
	adcliAnswerTimeout = 3 * time.Second
	adcliRetryAfter    = 10 * time.Minute
)

// adcliShortNames keeps the flat name each domain's controllers announced,
// for the process, and when a domain's did not answer.
var adcliShortNames struct {
	sync.Mutex
	byDomain map[string]adcliShortName
}

type adcliShortName struct {
	short    string
	failedAt time.Time
}

// adcliDomainShort is the NetBIOS (flat) name the controllers of dnsDomain
// announce, as adcli info prints it (domain-short). If adcli is installed,
// an execution failure is returned to the caller and not cached, so incomplete
// directory facts cannot be cached as verified. A successful answer with no
// flat name is cached briefly.
func (r *NSSResolver) adcliDomainShort(dnsDomain string) (string, error) {
	dnsDomain = strings.ToLower(strings.TrimSpace(dnsDomain))
	if dnsDomain == "" || strings.HasPrefix(dnsDomain, "-") || strings.ContainsAny(dnsDomain, " \t\x00\r\n/\\@") {
		return "", nil
	}
	adcliShortNames.Lock()
	known, ok := adcliShortNames.byDomain[dnsDomain]
	adcliShortNames.Unlock()
	if ok && (known.short != "" || time.Since(known.failedAt) < adcliRetryAfter) {
		return known.short, nil
	}
	path, err := adcliTool()
	if err != nil {
		// adcli is optional on hosts whose NSS and realmd data suffice.
		return "", nil
	}
	ctx, cancel := context.WithTimeout(r.context(), adcliAnswerTimeout)
	result, err := r.runner(ctx, path, []string{"info", dnsDomain})
	cancel()
	if err != nil {
		return "", fmt.Errorf("unixidentity: adcli info of %s: %w", dnsDomain, err)
	}
	if result.exitCode != 0 {
		return "", fmt.Errorf("unixidentity: adcli info of %s exited %d", dnsDomain, result.exitCode)
	}
	answer := adcliShortName{short: parseADCLIDomainShort(string(result.stdout)), failedAt: time.Now()}
	adcliShortNames.Lock()
	if adcliShortNames.byDomain == nil {
		adcliShortNames.byDomain = map[string]adcliShortName{}
	}
	adcliShortNames.byDomain[dnsDomain] = answer
	adcliShortNames.Unlock()
	return answer.short, nil
}

// parseADCLIDomainShort reads "domain-short = NAME" of adcli info output.
func parseADCLIDomainShort(output string) string {
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok && strings.TrimSpace(key) == "domain-short" {
			return strings.ToUpper(strings.TrimSpace(value))
		}
	}
	return ""
}

// sambaWorkgroup reads the workgroup of the [global] section of smb.conf,
// the NetBIOS domain a winbind join writes, or "".
func sambaWorkgroup() string {
	data, err := readSmallFile(sambaConfPath, 1<<20)
	if err != nil {
		return ""
	}
	global := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			global = strings.EqualFold(strings.Trim(line, "[] \t"), "global")
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if global && ok && strings.EqualFold(strings.Join(strings.Fields(key), " "), "workgroup") {
			return strings.ToUpper(strings.TrimSpace(value))
		}
	}
	return ""
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
	if domain != "" && !strings.Contains(domain, ".") && !strings.Contains(name, `\`) {
		// The SSSD name of a domain with no DNS name, which names no realm.
		// A DOMAIN\name gets no domain from its name: a plain LDAP domain may
		// name an account so, as nslcd may (GAP-0814); SSSD confirms the
		// domain of an AD account by its SID below.
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
		facts.AccountDomain, err = sssdAccountDomain(sssd, name, candidate, realm.NetBIOS, sid, r.adcliDomainShort)
		if err != nil {
			return "", err
		}
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
// The files module matches no /etc/group member to that form, so the
// /etc/group groups that list the account by its passwd name, the groups the
// OS gives it at login, are read from /etc/group (GAP-0729). Its name
// qualified with the domain is not matched: under short names that is the
// passwd name of an account a domain names by e-mail address, and a group
// listing it is that account's. The boolean reports whether the
// domain-qualified query succeeded, so its trusted-domain groups are kept.
func (r *NSSResolver) accountGroupIDs(account Account, inDomain string) ([]int, bool, error) {
	bare, _ := useridentity.SplitQualifiedName(account.Name)
	if inDomain != "" {
		ids, err := r.GroupIDs(Account{Name: inDomain + `\` + bare, GID: account.GID})
		if !IsNotFound(err) {
			if err != nil {
				return nil, false, err
			}
			local, err := localGroupsListing(account.Name)
			if err != nil {
				return nil, false, err
			}
			ids = append(ids, local...)
			slices.Sort(ids)
			return slices.Compact(ids), true, nil
		}
	}
	ids, err := r.GroupIDs(account)
	return ids, false, err
}

// sssdGroupsOfDomain limits groups from an ambiguous, unqualified
// initgroups lookup to the SSSD account domain, the domain of its SID.
// A successful domain-qualified lookup is authoritative and skips this
// filter. The primary group always counts. An SSSD group counts when its SID
// belongs to the account's domain, or when neither account nor group has a
// SID. A SID-less group of a SID-bearing account counts only if /etc/group
// lists the account as a member or another configured NSS initgroups service
// confirms its membership. This keeps LDAP-supplied groups without accepting
// a group of another SSSD account with the same short name.
func (r *NSSResolver) sssdGroupsOfDomain(sssd *sssdNSS, ids []int, account Account, domainSID string) ([]int, error) {
	localIDs, err := localGroupsListing(account.Name)
	if err != nil {
		return nil, err
	}
	local := make(map[int]bool, len(localIDs))
	for _, id := range localIDs {
		local[id] = true
	}
	sids := make(map[int]string, len(ids))
	needOther := false
	for _, id := range ids {
		if id == account.GID {
			continue
		}
		sid, err := sssd.sidByGID(id)
		if err != nil {
			return nil, fmt.Errorf("SSSD SID of gid %d: %w", id, err)
		}
		sids[id] = sid
		if sid == "" && domainSID != "" && !local[id] {
			needOther = true
		}
	}
	var other map[int]bool
	if needOther {
		other, err = r.otherNSSGroupMemberships(account.Name)
		if err != nil {
			return nil, err
		}
	}
	kept := make([]int, 0, len(ids))
	for _, id := range ids {
		sid := sids[id]
		if id == account.GID ||
			(sid != "" && domainSID != "" && sidDomain(sid) == domainSID) ||
			(sid == "" && (domainSID == "" || local[id] || other[id])) {
			kept = append(kept, id)
		}
	}
	return kept, nil
}

// otherNSSGroupMemberships asks each configured non-SSSD initgroups service
// for this account's groups. Looking up a group by gid alone would prove only
// that the group exists, not that the account belongs to it.
func (r *NSSResolver) otherNSSGroupMemberships(name string) (map[int]bool, error) {
	data, err := readSmallFile(nsswitchPath, 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil // glibc defaults to files
	}
	if err != nil {
		return nil, fmt.Errorf("unixidentity: read NSS configuration: %w", err)
	}
	services := ParseNSSwitchServices(string(data), "initgroups")
	if len(services) == 0 {
		services = ParseNSSwitchServices(string(data), "group")
	}
	groups := map[int]bool{}
	for _, service := range services {
		if service == "sss" || service == "files" || !validServiceName(service) {
			continue
		}
		result, err := r.runner(r.context(), r.path, []string{"-s", service, "initgroups", name})
		if err != nil {
			return nil, fmt.Errorf("unixidentity: %s initgroups of %s: %w", service, name, err)
		}
		if result.exitCode == getentExitNotFound {
			continue
		}
		if result.exitCode != getentExitOK {
			return nil, fmt.Errorf("unixidentity: getent -s %s initgroups %s exited %d", service, name, result.exitCode)
		}
		ids, err := ParseInitgroups(string(result.stdout), name)
		if err != nil {
			return nil, fmt.Errorf("unixidentity: %s initgroups of %s: %w", service, name, err)
		}
		for _, id := range ids {
			groups[id] = true
		}
	}
	return groups, nil
}

// localGroupsListing returns the gids of the /etc/group entries whose member
// list names name, split and compared as the glibc files module does, so
// DefenseClaw and id(1) agree: white space before each member is skipped,
// and only the newline ends the line, so the CR of a CRLF line stays in its
// last member, which then names no account (GAP-0815). A missing file holds
// none.
func localGroupsListing(name string) ([]int, error) {
	data, err := readSmallFile(localGroupPath, 16<<20)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []int
	for _, line := range strings.Split(string(data), "\n") {
		gid, _, ok := parseGroupName(line)
		if !ok {
			continue
		}
		members := strings.Split(line, ":")[3]
		if slices.ContainsFunc(strings.Split(members, ","), func(member string) bool {
			return strings.TrimLeft(member, " \t\n\v\f\r") == name
		}) {
			ids = append(ids, gid)
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

// QualifiedGroupName returns name@domain, as the host spells it, for the
// first realm the host is joined to (realmd) that has a group of that name,
// or "" when name is already qualified or no realm has it.
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
		if listed := GroupSpelling(r, name+"@"+realm.Domain); listed != "" {
			return listed
		}
	}
	return ""
}

// QualifiedUserName finds the spelling NSS accepts for a short account name
// on a joined host configured to require fully qualified names.
func QualifiedUserName(ctx context.Context, r Resolver, name string) string {
	if r == nil || name == "" || strings.ContainsAny(name, `@\`) {
		return ""
	}
	realms, err := hostRealms(ctx)
	if err != nil {
		return ""
	}
	for _, realm := range realms {
		for _, candidate := range []string{name + "@" + realm.Domain, realm.NetBIOS + `\` + name} {
			if candidate == name+"@" || strings.HasPrefix(candidate, `\`) {
				continue
			}
			if _, err := r.LookupUser(candidate); err == nil {
				return candidate
			}
		}
	}
	return ""
}

// SameNameAccounts lists the other accounts the host holds under the bare
// name of account: the account NSS answers that bare name with, and the
// directory account of each joined realm that it answers name@domain or
// NETBIOS\name with. A local and a directory account of one name are two
// accounts (twins); an answer counts only when its own bare name is that
// name and its uid is not account's (GAP-1087).
func SameNameAccounts(ctx context.Context, r Resolver, account Account) []Account {
	bare, _ := useridentity.SplitQualifiedName(account.Name)
	if r == nil || bare == "" {
		return nil
	}
	candidates := []string{bare}
	if realms, err := hostRealms(ctx); err == nil {
		for _, realm := range realms {
			if realm.Domain != "" {
				candidates = append(candidates, bare+"@"+realm.Domain)
			}
			if realm.NetBIOS != "" {
				candidates = append(candidates, realm.NetBIOS+`\`+bare)
			}
		}
	}
	seen := map[int]bool{account.UID: true}
	var twins []Account
	for _, candidate := range candidates {
		found, err := r.LookupUser(candidate)
		var mismatch *NameMismatchError
		if errors.As(err, &mismatch) {
			found, err = mismatch.Answered, nil
		}
		foundBare, _ := useridentity.SplitQualifiedName(found.Name)
		if err != nil || seen[found.UID] || !useridentity.EqualFold(foundBare, bare) {
			continue
		}
		seen[found.UID] = true
		twins = append(twins, found)
	}
	return twins
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
