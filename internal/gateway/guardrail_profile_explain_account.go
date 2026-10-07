// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"strings"
)

// How `guardrail profile explain --user` names a Windows account: through
// the LSA directly, as the hook path names a verified SID
// (LookupAccountSid), never through os/user. os/user also looks up the
// account's primary group in its domain, and the AzureAD domain of an Entra
// ID account has no SID mapping (LookupAccountName answers "No mapping
// between account names and security IDs was done" and NetUserGetInfo
// cannot reach it), so it failed for every Entra ID account, as SYSTEM and
// as the gateway's service account alike (GAP-0222). The LSA calls are
// parameters so this is tested on every platform;
// guardrail_profile_explain_windows.go passes the real ones.

// windowsAccount is one LSA answer: the account's SID, its bare name and
// whether it is a user account (SidTypeUser).
type windowsAccount struct {
	SID, Name string
	User      bool
}

// entraAccountDomain is the domain the LSA puts Entra ID accounts in.
const entraAccountDomain = "AzureAD"

// resolveWindowsExplainAccount names an account given as a SID, DOMAIN\name,
// bare name or UPN. LookupAccountName takes an Entra ID account only as
// AzureAD\<name> or AzureAD\<UPN>, so a name without a domain that does not
// resolve is tried in that domain too. An account the LSA cannot name is an
// error that says so.
func resolveWindowsExplainAccount(name string, bySID, byName func(string) (windowsAccount, error)) (id, userName string, err error) {
	name = strings.TrimSpace(name)
	isSID := strings.HasPrefix(strings.ToUpper(name), "S-1-")
	var account windowsAccount
	if isSID {
		account, err = bySID(name)
	} else if account, err = byName(name); err != nil && !strings.Contains(name, `\`) {
		if entra, entraErr := byName(entraAccountDomain + `\` + name); entraErr == nil {
			account, err = entra, nil
		}
	}
	switch {
	case err != nil && isSID:
		return "", "", fmt.Errorf("cannot resolve %s: Windows names no account for this SID (%v)", name, err)
	case err != nil:
		return "", "", fmt.Errorf("cannot resolve %q: Windows has no account by this name (%v); name the account by its SID, as DOMAIN\\name, or an Entra ID account as AzureAD\\<name or UPN>", name, err)
	case !account.User:
		return "", "", fmt.Errorf("cannot resolve %q: it names a group or a service account, not a user account", name)
	}
	return account.SID, account.Name, nil
}
