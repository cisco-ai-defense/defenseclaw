// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package managed

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// DescribeUntrustedSource explains, for the standalone profile, why an
// administrator input such as the config was refused: the account by name,
// the folder, and the icacls commands that fix it. A standard user who owns
// the staging folder, or can write to it, can change what LocalSystem
// applies (GAP-0527, GAP-0528, GAP-0562). ok is false when err is not an
// ownership or write-access refusal.
func DescribeUntrustedSource(label, source string, err error) (string, bool) {
	var principal *UntrustedPrincipalError
	if !errors.As(err, &principal) {
		return "", false
	}
	account := principal.SID
	if name := windowsAccountName(principal.SID); name != "" {
		account = name + " (" + principal.SID + ")"
	}
	source = filepath.Clean(source)
	folder := filepath.Dir(source)
	failed := filepath.Clean(principal.Path)
	what := "can write to"
	if principal.Owner {
		what = "owns"
	}
	text := fmt.Sprintf("the %s %s is not protected: %s %s %s, and only Administrators, SYSTEM and TrustedInstaller may own or write it and the folders above it",
		label, source, account, what, failed)
	if !strings.EqualFold(failed, source) && !strings.EqualFold(failed, folder) {
		return text + fmt.Sprintf(". Copy the %s into a folder that only administrators can write, such as C:\\ProgramData\\DefenseClaw-Staging, and run it again (nothing was changed)", label), true
	}
	fix := untrustedFolderFix(folder, principal, "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F")
	return text + ". From an elevated prompt run " + strings.Join(fix, ", then ") + ", and run it again (nothing was changed)", true
}

// DescribeUntrustedRulePack explains, for the standalone profile, why an
// administrator rule pack was refused: the account by name, the file or
// folder it can change, and the icacls commands that fix it. Setup refused
// such a pack only after it had stopped every service, with a SID and no fix
// (GAP-0668). ok is false when err is not an ownership or write-access
// refusal.
func DescribeUntrustedRulePack(label, pack string, err error) (string, bool) {
	var principal *UntrustedPrincipalError
	if !errors.As(err, &principal) {
		return "", false
	}
	account := principal.SID
	if name := windowsAccountName(principal.SID); name != "" {
		account = name + " (" + principal.SID + ")"
	}
	pack = filepath.Clean(pack)
	failed := filepath.Clean(principal.Path)
	what := "can write to"
	if principal.Owner {
		what = "owns"
	}
	text := fmt.Sprintf("the rule pack %s (%s) is not protected: %s %s %s, and only Administrators, SYSTEM and TrustedInstaller may own or write a rule pack, the files and folders in it and the folders above it",
		pack, label, account, what, failed)
	inside := strings.EqualFold(failed, pack) ||
		strings.HasPrefix(strings.ToLower(failed), strings.ToLower(pack)+`\`)
	if !inside {
		return text + `. Copy the pack into a folder that only administrators can write, such as C:\ProgramData\DefenseClaw-RulePacks, set that path in the config, and run it again (nothing was changed)`, true
	}
	fix := untrustedFolderFix(pack, principal, "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX")
	return text + ". From an elevated prompt run " + strings.Join(fix, ", then ") + ", and run it again (nothing was changed)", true
}

// untrustedFolderFix is the icacls commands that leave folder, and the files
// in it, with only the given grants and take the refused principal off them
// (GAP-0953):
//   - Each argument is quoted, so the commands also run in PowerShell, where
//     an unquoted (OI) is a command.
//   - The grants go on the folder alone and its files inherit them. With /T
//     icacls would also strip each file's inherited entries and give it the
//     container grants, which a file cannot use: its DACL would be empty.
//   - /inheritance:r keeps an entry that is the folder's own, and on a Windows
//     client edition a new folder under C:\ holds Authenticated Users that
//     way, so the principal is removed by name from the folder and its files.
//   - /remove:g takes every grant of the principal, so a grant for that same
//     principal (Users Read & execute on a rule pack, which the gateway
//     service reads through) is given again after it (GAP-1326).
func untrustedFolderFix(folder string, principal *UntrustedPrincipalError, grants ...string) []string {
	var fix []string
	if principal.Owner {
		fix = append(fix, fmt.Sprintf(`icacls "%s" /setowner "*S-1-5-32-544" /T /C`, folder))
	}
	grant := fmt.Sprintf(`icacls "%s" /inheritance:r /grant:r`, folder)
	regrant := ""
	for _, entry := range grants {
		grant += ` "` + entry + `"`
		if sid, _, _ := strings.Cut(strings.TrimPrefix(entry, "*"), ":"); strings.EqualFold(sid, principal.SID) {
			regrant += ` "` + entry + `"`
		}
	}
	fix = append(fix, grant, fmt.Sprintf(`icacls "%s" /remove:g "*%s" /T /C`, folder, principal.SID))
	if regrant != "" {
		fix = append(fix, fmt.Sprintf(`icacls "%s" /grant:r`, folder)+regrant)
	}
	return fix
}

// windowsAccountName is DOMAIN\name for a SID, or "" when it does not resolve.
func windowsAccountName(value string) string {
	sid, err := windows.StringToSid(value)
	if err != nil {
		return ""
	}
	account, domain, _, err := sid.LookupAccount("")
	if err != nil || account == "" {
		return ""
	}
	if domain == "" {
		return account
	}
	return domain + `\` + account
}
