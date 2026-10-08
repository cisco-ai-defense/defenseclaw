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
