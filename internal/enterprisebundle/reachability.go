// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// Reachability warning codes. A warning never blocks a bundle (owner
// decision 2026-10-12): the console and bundle sign show it, the device
// keeps enforcing.
const (
	WarnGroupPattern          = "group_pattern"
	WarnGroupSIDMalformed     = "group_sid_malformed"
	WarnGroupSIDNotOnPlatform = "group_sid_not_on_platform"
	WarnGroupNumericID        = "group_numeric_id"
	WarnEntraGroupWindows     = "group_entra_windows_local_group_only"
	WarnEntraGroupLinux       = "group_entra_linux_needs_directory_bridge"
	WarnEntraGroupMacOS       = "group_entra_macos_unreachable"
	WarnEntraObjectIDWindows  = "group_entra_object_id_windows"
	// WarnTruncated replaces the warnings past MaxWarnings, so a large
	// fleet's warning list never makes the manifest invalid.
	WarnTruncated = "warnings_truncated"
)

// GroupKind classifies a guardrail.profile_assignments group identifier.
type GroupKind string

const (
	GroupName          GroupKind = "name"            // plain or DOMAIN\name
	GroupPattern       GroupKind = "pattern"         // holds * or ?
	GroupNumericID     GroupKind = "numeric_id"      // a Unix gid
	GroupEntraSID      GroupKind = "entra_sid"       // S-1-12-1-...
	GroupEntraObjectID GroupKind = "entra_object_id" // a GUID
	GroupSID           GroupKind = "sid"             // any other valid SID (AD, built-in)
	GroupSIDMalformed  GroupKind = "sid_malformed"   // S-1-... that is not a SID
)

var objectIDPattern = lazyregexp.New(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ClassifyGroup returns the kind of a group identifier.
func ClassifyGroup(group string) GroupKind {
	group = strings.TrimSpace(group)
	upper := strings.ToUpper(group)
	switch {
	case strings.ContainsAny(group, "*?"):
		return GroupPattern
	case strings.HasPrefix(upper, "S-1-"):
		if !validSID(upper) {
			return GroupSIDMalformed
		}
		if strings.HasPrefix(upper, "S-1-12-1-") {
			return GroupEntraSID
		}
		return GroupSID
	case objectIDPattern.MatchString(group):
		return GroupEntraObjectID
	case group != "" && strings.Trim(group, "0123456789") == "":
		return GroupNumericID
	}
	return GroupName
}

// validSID reports the SID string form: S-1, an identifier authority and one
// to fifteen sub-authorities, all decimal.
func validSID(upper string) bool {
	parts := strings.Split(upper, "-")
	if len(parts) < 4 || len(parts) > 18 || parts[0] != "S" || parts[1] != "1" {
		return false
	}
	for _, part := range parts[2:] {
		if part == "" || len(part) > 15 || strings.Trim(part, "0123456789") != "" {
			return false
		}
	}
	return true
}

// Reachability warns, per platform, for each guardrail.profile_assignments
// group that cannot select anyone there (spec section 10, design review
// section 4): Windows reports groups as SIDs and DOMAIN\name, Linux and
// macOS as names; Entra groups reach Windows only through an Intune
// local-group membership, Linux only through a directory bridge (Himmelblau,
// or Entra Domain Services with SSSD; not Microsoft's aad module) and never
// macOS Platform SSO. Plain names are not warned: whether a name resolves
// is known only on the host. Warnings come in assignment, group and platform
// order.
func Reachability(cfg *config.Config, platforms []string) []Warning {
	if cfg == nil {
		return nil
	}
	var warnings []Warning
	for i, assignment := range cfg.Guardrail.ProfileAssignments {
		for _, group := range assignment.Match.Groups {
			group = strings.TrimSpace(group)
			if group == "" {
				continue
			}
			kind := ClassifyGroup(group)
			for _, platform := range platforms {
				if code, message := groupReach(kind, platform); code != "" {
					warnings = append(warnings, Warning{
						Code:     code,
						Platform: platform,
						Subject:  boundedText(group, 256),
						Message:  fmt.Sprintf("profile_assignments[%d] (profile %s): %s", i, boundedText(assignment.Profile, 64), message),
					})
				}
			}
		}
	}
	if len(warnings) > MaxWarnings {
		dropped := len(warnings) - (MaxWarnings - 1)
		warnings = append(warnings[:MaxWarnings-1], Warning{
			Code:    WarnTruncated,
			Message: fmt.Sprintf("%d more group reachability warnings are not listed", dropped),
		})
	}
	return warnings
}

func groupReach(kind GroupKind, platform string) (code, message string) {
	windows := platform == PlatformWindows
	switch kind {
	case GroupPattern:
		return WarnGroupPattern, "group names are compared literally, so a pattern selects nobody"
	case GroupSIDMalformed:
		return WarnGroupSIDMalformed, "not a valid SID (S-1-<authority>-<sub-authority>...), so it selects nobody"
	case GroupNumericID:
		if !windows {
			return WarnGroupNumericID, "a group id matches only while the directory gives the group no name; use the name id -Gn lists"
		}
	case GroupSID:
		if !windows {
			return WarnGroupSIDNotOnPlatform, "a Windows SID selects nobody here: account groups are names on " + platformName(platform)
		}
	case GroupEntraSID, GroupEntraObjectID:
		switch {
		case windows && kind == GroupEntraSID:
			return WarnEntraGroupWindows, "an Entra group reaches Windows only when Intune adds it to a local group (Account protection policy)"
		case windows:
			return WarnEntraObjectIDWindows, "Windows reports an Entra group as its S-1-12-1 SID, not its object id; write the SID"
		case platform == PlatformLinux:
			return WarnEntraGroupLinux, "an Entra group reaches Linux only through Himmelblau or Entra Domain Services with SSSD, not Microsoft's aad module, and then by name"
		case platform == PlatformDarwin:
			return WarnEntraGroupMacOS, "Entra groups do not reach macOS with Platform SSO; sync the members into a local group and name that group"
		}
	}
	return "", ""
}

func platformName(platform string) string {
	switch platform {
	case PlatformDarwin:
		return "macOS"
	case PlatformLinux:
		return "Linux"
	}
	return platform
}

// boundedText is text as manifest display text of at most max characters:
// itself when it passes checkDisplayText, else quoted and cut, so a warning
// never makes the manifest invalid.
func boundedText(text string, max int) string {
	if checkDisplayText(text, max) == nil {
		return text
	}
	quoted := safePath(text) // ASCII
	if len(quoted) > max {
		quoted = quoted[:max-3] + "..."
	}
	return quoted
}
