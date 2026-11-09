//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// windowsPrincipalName is the account or group a SID names on this
// computer (BUILTIN\Users, CREATOR OWNER, NT SERVICE\DefenseClawGateway,
// COMPUTER\alice), or "" when it names none; tests replace it.
var windowsPrincipalName = func(sid string) string {
	parsed, err := windows.StringToSid(strings.TrimSpace(sid))
	if err != nil {
		return ""
	}
	account, domain, _, err := parsed.LookupAccount("")
	if err != nil || account == "" {
		return ""
	}
	if domain == "" {
		return account
	}
	return domain + `\` + account
}

// windowsPrincipalLabel is a SID as an administrator reads it: the name
// next to the SID, or the bare SID when it names no account.
func windowsPrincipalLabel(sid string) string {
	if name := windowsPrincipalName(sid); name != "" {
		return name + " (" + sid + ")"
	}
	return sid
}

// windowsAccessMaskWords names a file access mask in the terms of the
// Windows security dialog, with the raw mask after it.
func windowsAccessMaskWords(mask uint32) string {
	const (
		fullControl    = 0x1f01ff
		modify         = 0x1301bf
		readAndExecute = 0x1200a9
	)
	var words []string
	switch {
	case mask&fullControl == fullControl || mask&windows.GENERIC_ALL != 0:
		words = []string{"full control"}
	case mask&modify == modify:
		words = []string{"modify"}
	default:
		for _, bit := range []struct {
			mask uint32
			word string
		}{
			{0x2, "write data"}, {0x4, "append data"}, {0x10, "write extended attributes"},
			{0x40, "delete subfolders and files"}, {0x100, "write attributes"}, {0x10000, "delete"},
			{0x40000, "change permissions"}, {0x80000, "take ownership"}, {windows.GENERIC_WRITE, "write"},
		} {
			if mask&bit.mask != 0 {
				words = append(words, bit.word)
			}
		}
		if len(words) == 0 && mask&readAndExecute == readAndExecute {
			words = []string{"read and execute"}
		}
	}
	if len(words) == 0 {
		return fmt.Sprintf("access 0x%x", mask)
	}
	return fmt.Sprintf("%s (0x%x)", strings.Join(words, ", "), mask)
}

// windowsPrincipalReadsPath reports whether sid holds an allow entry on path
// that lets it read data; tests replace it.
var windowsPrincipalReadsPath = func(path, sid string) bool {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return false
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, uint32(index), &ace) != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || uint32(ace.Mask)&0x1 == 0 {
			continue
		}
		if (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String() == sid {
			return true
		}
	}
	return false
}

// windowsPathIsDirectory is os.Stat's answer for path; tests replace it.
var windowsPathIsDirectory = func(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// windowsDefenseClawOwnedPath is a path inside DefenseClaw's own install or
// state folders (a folder named exactly DefenseClaw), which are
// administrator-only by design.
var windowsDefenseClawOwnedPath = regexp.MustCompile(`(?i)\\DefenseClaw(\\|$)`)

// windowsWriterFix is the icacls command that takes a write-like entry of
// one account off path. For a path DefenseClaw owns, or an account that holds
// no read there, it removes the account's entries. For a folder or file that
// is not DefenseClaw's (a vendor folder under ProgramData) and the stock
// reader groups (Users, Authenticated Users, Everyone) it removes the
// account's entries and grants read and execute again, so the write is gone and the read
// every standard user needs stays: /remove:g would take the vendor's own
// read entry away too and break reading for everyone (GAP-0602 review D3).
func windowsWriterFix(path, sid string) string {
	quoted := `icacls "` + path + `"`
	switch sid {
	case "S-1-5-32-545", "S-1-5-11", "S-1-1-0":
		if !windowsDefenseClawOwnedPath.MatchString(path) && windowsPrincipalReadsPath(path, sid) {
			inherit := ""
			if windowsPathIsDirectory(path) {
				inherit = "(OI)(CI)"
			}
			// /grant:r alone leaves an entry with other inheritance flags (a
			// Modify entry for this folder only next to the stock read entry);
			// /remove:g first takes every entry of the account off, and the
			// grant puts the read back in the same command.
			return quoted + " /remove:g *" + sid + ` /grant "*` + sid + `:` + inherit + `(RX)"`
		}
	}
	return quoted + " /remove:g *" + sid
}

// Trust refusals named only a raw SID and a hex mask, for well-known
// principals too (BUILTIN\Users, CREATOR OWNER, NT SERVICE accounts), and no
// fix (GAP-0925). windowsEnterpriseNamePrincipals names the account next to
// the SID, puts the mask in words and appends the icacls command that
// clears the finding. Standalone results and managed config loads only.
var windowsEnterprisePrincipalRewrites = []struct {
	pattern *regexp.Regexp
	rewrite func(match []string) string
}{
	{
		// The lifecycle module: a writer it does not trust.
		regexp.MustCompile(`untrusted principal (S-1-[0-9-]+) has write-like access to managed path: ([A-Za-z]:\\[^;)"]*)`),
		func(m []string) string {
			return windowsPrincipalLabel(m[1]) + " has write access to " + m[2] +
				", which only SYSTEM, Administrators and TrustedInstaller may change. Fix: " + windowsWriterFix(m[2], m[1])
		},
	},
	{
		regexp.MustCompile(`untrusted principal (S-1-[0-9-]+) can read protected managed path: ([A-Za-z]:\\[^;)"]*)`),
		func(m []string) string {
			return windowsPrincipalLabel(m[1]) + " can read " + m[2] +
				", which only SYSTEM, Administrators and the DefenseClaw services may read. Fix: icacls \"" + m[2] + "\" /remove:g *" + m[1]
		},
	},
	{
		regexp.MustCompile(`untrusted owner (S-1-[0-9-]+) on managed path: ([A-Za-z]:\\[^;)"]*)`),
		func(m []string) string {
			return m[2] + " is owned by " + windowsPrincipalLabel(m[1]) + ", not an administrator. Fix: icacls \"" + m[2] + "\" /setowner *S-1-5-32-544"
		},
	},
	{
		// The managed trust check: "<path>: untrusted Windows principal <sid> has write-like access mask 0x..".
		regexp.MustCompile(`([A-Za-z]:\\[^:;"]*): untrusted Windows principal (S-1-[0-9-]+) has write-like access mask 0x([0-9a-fA-F]+)`),
		func(m []string) string {
			return m[1] + ": " + windowsPrincipalLabel(m[2]) + " has write access (" + windowsHexMaskWords(m[3]) +
				"), which only SYSTEM, Administrators and TrustedInstaller may hold. Fix: " + windowsWriterFix(m[1], m[2])
		},
	},
	{
		// enterprise hooks: "... has write-like access mask 0x.. on <path>".
		regexp.MustCompile(`untrusted Windows principal (S-1-[0-9-]+) has write-like access mask 0x([0-9a-fA-F]+) on ([A-Za-z]:\\[^;)"]*)`),
		func(m []string) string {
			return windowsPrincipalLabel(m[1]) + " has write access (" + windowsHexMaskWords(m[2]) + ") on " + m[3] +
				", which only SYSTEM, Administrators and TrustedInstaller may hold. Fix: " + windowsWriterFix(m[3], m[1])
		},
	},
	{
		regexp.MustCompile(`([A-Za-z]:\\[^:;"]*): owner (S-1-[0-9-]+) is not trusted for ([^;]*?); expected ([^;]*)`),
		func(m []string) string {
			return m[1] + ": owner " + windowsPrincipalLabel(m[2]) + " is not trusted for " + m[3] + "; expected " + m[4] +
				". Fix: icacls \"" + m[1] + "\" /setowner *S-1-5-32-544"
		},
	},
}

func windowsHexMaskWords(hex string) string {
	mask, err := strconv.ParseUint(hex, 16, 32)
	if err != nil {
		return "access 0x" + hex
	}
	return windowsAccessMaskWords(uint32(mask))
}

// windowsEnterpriseNamePrincipals rewrites each trust refusal in message.
func windowsEnterpriseNamePrincipals(message string) string {
	for _, rewrite := range windowsEnterprisePrincipalRewrites {
		message = rewrite.pattern.ReplaceAllStringFunc(message, func(found string) string {
			return rewrite.rewrite(rewrite.pattern.FindStringSubmatch(found))
		})
	}
	return message
}

func init() {
	// The relaxed-ancestor advisory that status, verify and policy show
	// print names the account and the fix too, not a raw SID and mask
	// (GAP-0925).
	managed.DescribeTrustAdvisoryReason = func(reason string) string {
		if _, standalone := managedHostWindowsStandalone(); !standalone {
			return reason
		}
		return windowsEnterpriseNamePrincipals(reason)
	}
	describeManagedConfigLoadError = func(err error) error {
		if err == nil {
			return nil
		}
		if _, standalone := managedHostWindowsStandalone(); !standalone {
			return err
		}
		if text := windowsEnterpriseNamePrincipals(err.Error()); text != err.Error() {
			return &describedTrustError{text: text, err: err}
		}
		return err
	}
}

// describedTrustError is a trust refusal with the accounts named; it still
// unwraps to the original error.
type describedTrustError struct {
	text string
	err  error
}

func (e *describedTrustError) Error() string { return e.text }
func (e *describedTrustError) Unwrap() error { return e.err }
