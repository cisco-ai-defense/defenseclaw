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

package enterprisehooks

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
)

// WindowsEnrolledSessionPrimaryToken returns a primary token of the first
// enabled target of the guardian's manifest whose account is signed in to
// an active Windows session (resolveWindowsEnterpriseSessionToken, the
// guardian's own session lookup), and that account's SID. GAP-0751: Setup
// starts the new hook image once with it, so the account's application
// control and EDR rules decide that start as they will decide its agent's
// hook. It needs LocalSystem (WTSQueryUserToken); an elevated administrator
// gets an error and the caller uses its filtered token instead. The caller
// closes the token.
func WindowsEnrolledSessionPrimaryToken(manifestPath string) (windows.Token, string, error) {
	manifest, err := LoadManifest(manifestPath)
	if err != nil {
		return 0, "", fmt.Errorf("read %s: %w", manifestPath, err)
	}
	seen := map[string]bool{}
	var problems []string
	for _, target := range manifest.Targets {
		if target.Enabled != nil && !*target.Enabled {
			continue
		}
		sidText := strings.TrimSpace(target.SID)
		if sidText == "" || seen[strings.ToUpper(sidText)] {
			continue
		}
		seen[strings.ToUpper(sidText)] = true
		sid, err := windows.StringToSid(sidText)
		if err != nil {
			continue
		}
		impersonation, err := resolveWindowsEnterpriseSessionToken(sid, false)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		var primary windows.Token
		err = windows.DuplicateTokenEx(
			impersonation,
			windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|
				windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ADJUST_SESSIONID,
			nil,
			windows.SecurityImpersonation,
			windows.TokenPrimary,
			&primary,
		)
		impersonation.Close()
		if err != nil {
			problems = append(problems, fmt.Sprintf("duplicate the session token of %s: %v", sidText, err))
			continue
		}
		return primary, sidText, nil
	}
	if len(problems) > 0 {
		return 0, "", errors.New("no enrolled account's session token could be used: " + strings.Join(problems, "; "))
	}
	return 0, "", errors.New("no enrolled account is signed in")
}
