// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// On macOS the root enumerator reads the account's Open Directory record
// (with the Platform SSO login UPN of AltSecurityIdentities), the AD binding
// and the device Platform SSO configuration
// (useridentity.ParseMacOSDirectoryFacts), and the SID of an Active
// Directory account from its domain node (macOSAccountSID). The flow lives
// here, built for every Unix, so it is tested on Linux too; the darwin
// build runs it with the root-owned tools.

const (
	macOSIdentityToolTimeout = 10 * time.Second
	// macOSDirectoryNodeReadTimeout bounds the read of an account's domain
	// node: a domain whose traffic is dropped (a half-up VPN) must not hold
	// each account's lookup for the whole identitySpoolLookupTimeout.
	macOSDirectoryNodeReadTimeout = 3 * time.Second
)

// macOSToolResult is what a root-owned macOS identity tool gave: its bounded
// stdout and stderr, and its exit code (-1 when it did not exit on its own:
// not a root-owned tool, it did not start, or it timed out).
type macOSToolResult struct {
	Stdout string
	Stderr string
	Code   int
}

// macOSIdentityRunner runs a root-owned macOS identity tool.
type macOSIdentityRunner func(ctx context.Context, timeout time.Duration, tool string, args ...string) macOSToolResult

// The exit codes of dscl for a domain node read: 56 is Open Directory's
// eDSRecordNotFound (the node answered: no such account), 69 a data source
// that is not valid (the node is not reachable: the domain controller is
// away).
const (
	dsclExitRecordNotFound = 56
	dsclExitNodeNotValid   = 69
)

// macOSSearchAttributes are what the /Search read asks for.
var macOSSearchAttributes = []string{"UniqueID", "AuthenticationAuthority", "OriginalNodeName", "AppleMetaNodeLocation",
	"GeneratedUID", "AltSecurityIdentities", "dsAttrTypeNative:userPrincipalName"}

func collectMacOSIdentityRecord(ctx context.Context, run macOSIdentityRunner, account IdentitySpoolAccount, now time.Time) (IdentitySpoolRecord, error) {
	name := strings.TrimSpace(account.User)
	if name == "" || strings.ContainsAny(name, "/\x00\n") || strings.HasPrefix(name, "-") {
		return IdentitySpoolRecord{}, errors.New("account has no usable name")
	}
	in := useridentity.MacOSDirectoryInputs{
		DSCL:       run(ctx, macOSIdentityToolTimeout, "/usr/bin/dscl", append([]string{"/Search", "-read", "/Users/" + name}, macOSSearchAttributes...)...).Stdout,
		DSConfigAD: run(ctx, macOSIdentityToolTimeout, "/usr/sbin/dsconfigad", "-show").Stdout,
		AppSSO:     run(ctx, macOSIdentityToolTimeout, "/usr/bin/app-sso", "platform", "-s").Stdout,
	}
	if in.DSCL == "" {
		return IdentitySpoolRecord{}, errors.New("dscl returned no record")
	}
	if err := checkMacOSRecordUID(in.DSCL, account.UID); err != nil {
		return IdentitySpoolRecord{}, err
	}
	facts := useridentity.ParseMacOSDirectoryFacts(in, now)
	sid, unanswered := macOSAccountSID(facts, in.DSCL, account.UID, func(node string) macOSToolResult {
		return run(ctx, macOSDirectoryNodeReadTimeout, "/usr/bin/dscl", node, "-read", "/Users/"+name, "UniqueID", "GeneratedUID", "SMBSID")
	})
	return IdentitySpoolRecord{
		Key:                strconv.Itoa(account.UID),
		User:               name,
		UpdatedAt:          now,
		AccountDomain:      facts.AccountDomain,
		AccountSID:         sid,
		Facts:              facts,
		macOSSIDUnanswered: unanswered,
	}, nil
}

// macOSAccountSID is the SID of a macOS Active Directory account, read from
// its domain's node (read runs `dscl <node> -read /Users/<name> UniqueID
// GeneratedUID SMBSID`): the record there (its stdout) must be the uid's
// (checkMacOSRecordUID), carry a GeneratedUID the /Search answer names when
// both have one, and name exactly one domain account SID. It gives none for
// any other account or a record that does not match. unanswered reports an
// Active Directory account whose node gave no answer (the domain is away),
// whose SID from an earlier pass is kept (carryMacOSAccountSID). This is the
// directory-verified identifier the account join key uses, as the SSSD SID
// on Linux (rel-1-0-6:GAP-0275).
func macOSAccountSID(facts useridentity.DirectoryFacts, search string, uid int, read func(node string) macOSToolResult) (sid string, unanswered bool) {
	if facts.Directory != useridentity.DirectoryActiveDirectory {
		return "", false
	}
	node, ok := useridentity.MacOSADNode(search)
	if !ok {
		return "", false
	}
	result := read(node)
	if macOSNodeUnanswered(result) {
		return "", true
	}
	out := result.Stdout
	if checkMacOSRecordUID(out, uid) != nil {
		return "", false
	}
	if searched, read := useridentity.MacOSGeneratedUIDs(search), useridentity.MacOSGeneratedUIDs(out); len(searched) > 0 && len(read) > 0 {
		for _, value := range read {
			if !slices.ContainsFunc(searched, func(s string) bool { return strings.EqualFold(s, value) }) {
				return "", false
			}
		}
	}
	sid, ok = useridentity.MacOSDirectorySID(out)
	if !ok {
		return "", false
	}
	return sid, false
}

// macOSNodeUnanswered reports a domain node read that did not answer for the
// account: no output (a timeout), or dscl's "Data source (<node>) is not
// valid." on stdout with exit code 69, its answer at once while the domain
// controller is unreachable. Read as an answer without a SID, that dropped
// the SID of every Active Directory account and their account join keys
// (rel-1-0-6:GAP-0447). Open Directory's eDSRecordNotFound (exit code 56,
// the text on stderr, nothing on stdout) is a definitive answer: the account
// is gone from the domain, and nothing is carried. Every other output is an
// answer, read as before (a record without a UniqueID gives no SID).
func macOSNodeUnanswered(result macOSToolResult) bool {
	if result.Code == dsclExitNodeNotValid || macOSNodeNotValid(result.Stdout) {
		return true
	}
	if result.Code == dsclExitRecordNotFound || strings.Contains(result.Stderr, "eDSRecordNotFound") {
		return false
	}
	return strings.TrimSpace(result.Stdout) == ""
}

// macOSNodeNotValid reports dscl's "Data source (<node>) is not valid." line,
// at the start of a line (an attribute value is indented or follows its key).
func macOSNodeNotValid(stdout string) bool {
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimRight(line, " \r")
		if strings.HasPrefix(line, "Data source (") && strings.HasSuffix(line, ") is not valid.") {
			return true
		}
	}
	return false
}

// carryMacOSAccountSID keeps the SID of the account's previous record when
// this pass could not reach its domain node, while the record still names
// the same account (name) in the same Active Directory domain: an Active
// Directory Mac off the corporate network kept no SID, and its account
// join key and its SID comparison (identitySpoolSameIdentity) flapped with
// every pass away from the domain. Linux keeps the SID in SSSD's cache the
// same way.
func carryMacOSAccountSID(record, previous IdentitySpoolRecord) IdentitySpoolRecord {
	if !record.macOSSIDUnanswered || record.AccountSID != "" || previous.AccountSID == "" ||
		record.Facts.Directory != useridentity.DirectoryActiveDirectory || previous.Facts.Directory != useridentity.DirectoryActiveDirectory ||
		!strings.EqualFold(record.User, previous.User) || !strings.EqualFold(record.Facts.Domain, previous.Facts.Domain) {
		return record
	}
	for _, pair := range [][2]string{{record.Facts.Principal, previous.Facts.Principal}, {record.Facts.Realm, previous.Facts.Realm}} {
		if pair[0] != "" && pair[1] != "" && !strings.EqualFold(pair[0], pair[1]) {
			return record
		}
	}
	record.AccountSID = previous.AccountSID
	return record
}
