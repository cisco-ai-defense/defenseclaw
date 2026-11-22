// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"errors"
	"strings"

	"golang.org/x/sys/windows"
)

// enrollmentExcludeEntryUnknown reports an exclude_users entry the LSA maps
// to no account (ERROR_NONE_MAPPED) in every spelling profile-explain tries
// (DOMAIN\name, a UPN, AzureAD\name, a SID); any other lookup failure is
// not reported.
var enrollmentExcludeEntryUnknown = func(entry string) bool {
	if rest, local := strings.CutPrefix(strings.TrimSpace(entry), `.\`); local && rest != "" {
		if computer, err := windows.ComputerName(); err == nil && computer != "" {
			entry = computer + `\` + rest
		}
	}
	return windowsEntryNamesNoAccount(entry, lsaAccountBySID, lsaAccountByName)
}

func windowsEntryNamesNoAccount(entry string, bySID, byName func(string) (windowsAccount, error)) bool {
	other := false
	track := func(lookup func(string) (windowsAccount, error)) func(string) (windowsAccount, error) {
		return func(name string) (windowsAccount, error) {
			account, err := lookup(name)
			if err != nil && !errors.Is(err, windows.ERROR_NONE_MAPPED) {
				other = true
			}
			return account, err
		}
	}
	_, _, err := resolveWindowsExplainAccount(entry, track(bySID), track(byName))
	return err != nil && !other && !strings.Contains(err.Error(), "names a group or a service account")
}
