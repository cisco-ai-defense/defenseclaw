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
// twin of the other kind (GAP-0366, GAP-1221).
func adminViewDomainCouldHold(user, sid string) bool {
	local := false
	if domain, _, qualified := strings.Cut(strings.TrimSpace(user), `\`); qualified {
		computer, _ := windows.ComputerName()
		local = domain == "." || computer != "" && strings.EqualFold(domain, computer)
	}
	return enterprisehooks.WindowsLocalAccountSID(sid) == local
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
	account, _, use, err := sid.LookupAccount("")
	if err != nil {
		return windowsAccount{}, err
	}
	return windowsAccount{SID: sid.String(), Name: sanitizeLLMEventUser(account), User: use == windows.SidTypeUser}, nil
}

// profileExplainUPNWait is how long explain waits for an AD account's UPN, so
// a users assignment by UPN is reported as a request would match it.
const profileExplainUPNWait = 5 * time.Second

// profileExplainDirectoryFacts resolves the facts a verified request from
// sid carries: the Windows identity store plus the guardian identity spool.
var profileExplainDirectoryFacts = func(id string) (useridentity.DirectoryFacts, error) {
	return resolveWindowsDirectoryFacts(id, profileExplainUPNWait)
}
