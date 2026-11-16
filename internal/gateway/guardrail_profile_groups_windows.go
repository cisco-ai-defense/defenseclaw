// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"context"
	"errors"
	osuser "os/user"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// profileGroupExists asks the LSA whether a group named in an assignment
// (DOMAIN\name or a bare name) exists. An error means the answer is unknown,
// not that the group is absent.
var profileGroupExists = func(_ context.Context, name string) (bool, error) {
	// Go's os/user.LookupGroup does not reliably resolve DOMAIN\name for
	// the LocalSystem service. Ask the LSA directly, as profile explain does
	// for accounts. Only ERROR_NONE_MAPPED proves the group is absent.
	if !strings.HasPrefix(strings.ToUpper(name), "S-1-") {
		// The lookup the assignment's SID comes from, so .\name is read
		// as it is there.
		_, err := lsaProfileGroupSID(name)
		if errors.Is(err, errProfileGroupUnknown) {
			return false, nil
		}
		return err == nil, err
	}
	sid, err := windows.StringToSid(name)
	if err != nil {
		// Parsing is local and definitive: a malformed SID cannot match.
		return false, nil
	}
	_, _, kind, err := sid.LookupAccount("")
	if errors.Is(err, windows.ERROR_NONE_MAPPED) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return kind == windows.SidTypeGroup || kind == windows.SidTypeAlias ||
		kind == windows.SidTypeWellKnownGroup, nil
}

func init() {
	profileGroupSIDLookup = lsaProfileGroupSID
	profileGroupLocalSIDLookup = lsaLocalProfileGroupSID
	profileGroupLocalDomain = lsaComputerName
}

func lsaComputerName() string {
	computer, err := windows.ComputerName()
	if err != nil {
		return ""
	}
	return computer
}

// lsaProfileGroupSID resolves an assignment group name (DOMAIN\name, .\name
// or a bare name) to the SID of that group (LookupAccountName). A name the
// LSA maps to no group, or to an account that is not a group, is
// errProfileGroupUnknown. LookupAccountName does not take .\name, the form
// Windows tools print for this computer's accounts, so a .\name assignment
// never got a SID (GAP-0636); it is looked up among this computer's groups.
func lsaProfileGroupSID(name string) (string, error) {
	if rest, local := strings.CutPrefix(strings.TrimSpace(name), `.\`); local {
		return lsaLocalProfileGroupSID(rest)
	}
	return lsaGroupSID(name)
}

// lsaLocalProfileGroupSID resolves a bare group name among this computer's
// own groups, in the order the LSA reads a bare name: BUILTIN, then the
// computer's account database. Neither asks a domain controller.
func lsaLocalProfileGroupSID(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || !profileGroupBareName(name) {
		return "", errProfileGroupUnknown
	}
	candidates := []string{`BUILTIN\` + name}
	if computer := lsaComputerName(); computer != "" {
		candidates = append(candidates, computer+`\`+name)
	}
	for _, candidate := range candidates {
		sid, err := lsaGroupSID(candidate)
		if !errors.Is(err, errProfileGroupUnknown) {
			return sid, err
		}
	}
	return "", errProfileGroupUnknown
}

// lsaGroupSID asks the LSA for the SID of one group name.
func lsaGroupSID(name string) (string, error) {
	sid, _, kind, err := windows.LookupSID("", name)
	if errors.Is(err, windows.ERROR_NONE_MAPPED) {
		return "", errProfileGroupUnknown
	}
	if err != nil {
		return "", err
	}
	if kind != windows.SidTypeGroup && kind != windows.SidTypeAlias && kind != windows.SidTypeWellKnownGroup {
		return "", errProfileGroupUnknown
	}
	return sid.String(), nil
}

// bareGroupsDirectorySilent is not needed on Windows: the LSA looks every
// group name up, and a bare name is checked like any other.
var bareGroupsDirectorySilent func(context.Context) bool

// profileGroupQualifiedName has nothing to offer on Windows, where an
// assignment names a group as DOMAIN\\name or by its SID.
var profileGroupQualifiedName = func(context.Context, string) string { return "" }

// profileUserEntryUnresolved has nothing to add on Windows: the LSA names
// every account DOMAIN\name, and an entry it cannot name says nothing about
// the domain.
func profileUserEntryUnresolved() func(ctx context.Context, domain string, err error) string {
	return func(context.Context, string, error) string { return "" }
}

// matchedGroupSource says whether the group an assignment matched by is a
// local group of this computer (BUILTIN or one of its own SAM) or a
// directory group, for explain (GAP-0356); "" while the name has no SID.
func matchedGroupSource(set *guardrailProfileSet, _ *profileSubject, group string) string {
	sid := strings.ToUpper(strings.TrimSpace(group))
	if profileGroupNeedsSID(sid) {
		var ok bool
		if set == nil {
			return ""
		}
		if sid, ok = set.groupSIDs.sid(group); !ok {
			return ""
		}
	}
	if strings.HasPrefix(sid, "S-1-5-32-") || enterprisehooks.WindowsLocalAccountSID(sid) {
		return "local"
	}
	return "directory"
}

// accountGroupIDs uses the signed-in token record of the requested SID. The
// current process can use its own token when no guardian record is available.
var accountGroupIDs = func(account *osuser.User) ([]string, error) {
	sid := strings.ToUpper(strings.TrimSpace(account.Uid))
	if record, ok := readIdentitySpoolFacts(sid, time.Now()); ok {
		return profileGroupSIDsForAccount(sid, record)
	}
	if current, err := osuser.Current(); err == nil && strings.EqualFold(current.Uid, sid) {
		return account.GroupIds()
	}
	return nil, errors.New("profile groups: current token groups are unavailable for account SID")
}
