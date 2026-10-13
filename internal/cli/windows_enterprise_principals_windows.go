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
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"
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
				", which only SYSTEM, Administrators and TrustedInstaller may change. Fix: icacls \"" + m[2] + "\" /remove:g *" + m[1]
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
				"), which only SYSTEM, Administrators and TrustedInstaller may hold. Fix: icacls \"" + m[1] + "\" /remove:g *" + m[2]
		},
	},
	{
		// enterprise hooks: "... has write-like access mask 0x.. on <path>".
		regexp.MustCompile(`untrusted Windows principal (S-1-[0-9-]+) has write-like access mask 0x([0-9a-fA-F]+) on ([A-Za-z]:\\[^;)"]*)`),
		func(m []string) string {
			return windowsPrincipalLabel(m[1]) + " has write access (" + windowsHexMaskWords(m[2]) + ") on " + m[3] +
				", which only SYSTEM, Administrators and TrustedInstaller may hold. Fix: icacls \"" + m[3] + "\" /remove:g *" + m[1]
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
