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
	fix := fmt.Sprintf(`icacls "%s" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F /T /C`, folder)
	if principal.Owner {
		fix = fmt.Sprintf(`icacls "%s" /setowner *S-1-5-32-544 /T /C, then `, folder) + fix
	}
	return text + ". From an elevated prompt run " + fix + ", and run it again (nothing was changed)", true
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
	first := fmt.Sprintf(`icacls "%s" /remove:g *%s /T /C`, pack, principal.SID)
	if principal.Owner {
		first = fmt.Sprintf(`icacls "%s" /setowner *S-1-5-32-544 /T /C`, pack)
	}
	grant := fmt.Sprintf(`icacls "%s" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX /T /C`, pack)
	return text + ". From an elevated prompt run " + first + ", then " + grant + ", and run it again (nothing was changed)", true
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
