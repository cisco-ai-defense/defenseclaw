// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// profileExplainAccount names an account (SID, DOMAIN\name, name or UPN)
// through the LSA, as the hook path names a verified SID (see
// resolveWindowsExplainAccount).
var profileExplainAccount = LookupWindowsAccount

func init() {
	windowsSAMNameForUPN = func(upn string) string { return useridentity.SAMNameForUPN(upn, profileExplainUPNWait) }
}

// LookupWindowsAccount names a user account given as a SID, DOMAIN\name,
// bare name or UPN through the LSA (see resolveWindowsExplainAccount).
// Entra ID accounts resolve only this way; `enterprise policy show|verify
// --user` uses it too (GAP-0242).
func LookupWindowsAccount(name string) (id, userName string, err error) {
	// LookupAccountName does not take ".\name", the form Windows tools print
	// for an account of this computer (GAP-0636).
	if rest, local := strings.CutPrefix(strings.TrimSpace(name), `.\`); local && rest != "" {
		if computer, cerr := windows.ComputerName(); cerr == nil && computer != "" {
			name = computer + `\` + rest
		}
	}
	return resolveWindowsExplainAccount(name, lsaAccountBySID, lsaAccountByName)
}

// adminViewDomainCouldHold reports whether the domain of user, a qualified
// --user filter, could hold sid: .\name and COMPUTER\name name an account of
// this computer, any other domain or a UPN a directory account, and the SID
// tells which. A deleted account read by its qualified name is never its
// twin of the other kind (GAP-0366, GAP-1221). A directory SID is also held
// only by the domain the filter names: the domain the LSA names for the
// SID's domain part, or one the gateway's cached facts for it name, so
// CORP\alice never lists a deleted OTHER\alice (GAP-1183).
func adminViewDomainCouldHold(user, sid string) bool {
	local := false
	if domain, _, qualified := strings.Cut(strings.TrimSpace(user), `\`); qualified {
		computer, _ := windows.ComputerName()
		local = domain == "." || computer != "" && strings.EqualFold(domain, computer)
	}
	if enterprisehooks.WindowsLocalAccountSID(sid) != local {
		return false
	}
	if local {
		return true
	}
	_, domain := useridentity.SplitQualifiedName(user)
	return adminViewKnownDomain(domain, sid, windowsSIDDomainName(sid))
}

// windowsSIDDomainName is the NetBIOS name the LSA gives the domain of a
// directory account SID (the SID without its last part), which it still
// names once the account is deleted; "" when it does not answer.
var windowsSIDDomainName = func(sid string) string {
	sid = strings.TrimSpace(sid)
	cut := strings.LastIndexByte(sid, '-')
	if cut <= 0 {
		return ""
	}
	parsed, err := windows.StringToSid(sid[:cut])
	if err != nil {
		return ""
	}
	_, domain, use, err := parsed.LookupAccount("")
	if err != nil || use != windows.SidTypeDomain {
		return ""
	}
	return strings.TrimSpace(domain)
}

// profileExplainUnresolved reports an account the LSA cannot name with the
// LSA's reason. Windows has no second account database to try: os/user asks
// the same LSA.
func profileExplainUnresolved(_ string, err error) (profileSubject, error) {
	return profileSubject{}, err
}

// lsaAccountBySID names a SID (LookupAccountSid).
func lsaAccountBySID(sid string) (windowsAccount, error) {
	parsed, err := windows.StringToSid(sid)
	if err != nil {
		return windowsAccount{}, err
	}
	return lsaAccount(parsed)
}

// lsaAccountByName resolves an account name (LookupAccountName) and names
// the SID it maps to, so every spelling gives the account's own name.
func lsaAccountByName(name string) (windowsAccount, error) {
	sid, _, _, err := windows.LookupSID("", name)
	if err != nil {
		return windowsAccount{}, err
	}
	return lsaAccount(sid)
}

func lsaAccount(sid *windows.SID) (windowsAccount, error) {
	account, domain, use, err := sid.LookupAccount("")
	if err != nil {
		return windowsAccount{}, err
	}
	// The name the hook path gives the account, not the UPN its user signed
	// in with (GAP-0533).
	account = useridentity.CanonicalWindowsAccountName(sid.String(), account, domain)
	return windowsAccount{SID: sid.String(), Name: sanitizeLLMEventUser(account), User: use == windows.SidTypeUser}, nil
}

// profileExplainUPNWait is how long explain waits for TranslateNameW: for an
// AD account's UPN, and to turn a UPN it was given into
// DOMAIN\sAMAccountName.
const profileExplainUPNWait = 5 * time.Second

// profileExplainDirectoryFacts returns the facts a verified request from sid
// carries (the Windows identity store plus the guardian identity spool) from
// the cache requests read, after a lookup of explain's own
// (explainDirectoryFacts). A new sign-in token's groups replace the cached
// ones first, as they do for a request (GAP-1027). An AD account's UPN is
// asked for first, within profileExplainUPNWait: the answer is kept, so the
// lookup that refreshes the cache has it even where requests do not wait
// for it (no users or groups assignment).
var profileExplainDirectoryFacts = func(id string) (useridentity.DirectoryFacts, error) {
	sid := strings.ToUpper(strings.TrimSpace(id))
	useridentity.WindowsDirectoryFacts(sid, profileExplainUPNWait)
	cache := peerDirectoryCache()
	forgetOnSpoolGroupChange(cache, sid, time.Now())
	return explainDirectoryFacts(cache, sid)
}
