// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package winpath

import (
	"strconv"
	"strings"
)

// InteractiveUserSIDOptions selects which account authorities count as
// interactive users.
type InteractiveUserSIDOptions struct {
	// AllowEntraID admits Microsoft Entra ID user SIDs
	// (S-1-12-1-a-b-c-d), which Intune/Entra-joined devices create for
	// cloud accounts. The standalone enterprise profile enables it; the
	// Secure Client profile keeps the historical local/AD filter exactly.
	AllowEntraID bool
}

// IsInteractiveUserSID reports whether sid (string form, as it appears as a
// ProfileList subkey name) names a real user account whose profile can carry
// per-user agent configuration:
//
//   - local and Active Directory users: S-1-5-21-A-B-C-RID (NT AUTHORITY,
//     SECURITY_NT_NON_UNIQUE, at least five sub-authorities so the SID names
//     a user rather than the bare domain S-1-5-21-A-B-C);
//   - with AllowEntraID, Microsoft Entra ID users: S-1-12-1-a-b-c-d
//     (authority 12, exactly five sub-authorities).
//
// Every well-known and machine-scoped principal (SYSTEM S-1-5-18, LocalService,
// NetworkService, BUILTIN S-1-5-32-*, NT SERVICE S-1-5-80-*, Everyone, Entra
// group SIDs S-1-12-1-... with another shape, and so on) is rejected by
// construction. The check is purely syntactic: no offline name translation,
// which would fail for cloud accounts on a disconnected device.
func IsInteractiveUserSID(sid string, options InteractiveUserSIDOptions) bool {
	parts := strings.Split(strings.TrimSpace(sid), "-")
	if len(parts) < 3 || !strings.EqualFold(parts[0], "S") || parts[1] != "1" {
		return false
	}
	for _, part := range parts[2:] {
		if !sidDecimalComponent(part) {
			return false
		}
	}
	switch {
	case parts[2] == "5" && len(parts) >= 8 && parts[3] == "21":
		return true
	case options.AllowEntraID && parts[2] == "12" && len(parts) == 8 && parts[3] == "1":
		return true
	default:
		return false
	}
}

// sidDecimalComponent accepts a canonical unsigned 32-bit decimal SID
// component (no sign, no leading zero padding, no hex authority form).
func sidDecimalComponent(part string) bool {
	if part == "" || len(part) > 10 || (len(part) > 1 && part[0] == '0') {
		return false
	}
	value, err := strconv.ParseUint(part, 10, 32)
	return err == nil && value <= 0xFFFFFFFF
}
