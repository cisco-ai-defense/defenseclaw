// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

// LinkedPathFact is the path fact for the file an operand reaches through an
// existing link (symbolic link, junction, mount point). It is one more
// spelling of the operand: the access, command and flavor of the operand
// stay, and the name is the physical path written the way every other path
// fact writes it. The operating system spells a Windows physical path with
// back slashes (C:\x\y) or an extended prefix (\\?\C:\x\y); the path rules
// and the facts that come from the tool call read a Windows path as
// C:/x/y, so the physical path is canonicalized the same way before it is
// scanned. Without that, a link to a protected file never matched the rule
// its target name matches.
func LinkedPathFact(operand PathFact, physical string) PathFact {
	linked := operand
	linked.Linked = true
	linked.LinkedFrom = operand.Resolved
	linked.Absolute = true
	canonical := physical
	if windowsPhysicalPath(physical) {
		parsed := parseWindowsPathWithPolicy(physical, pathExpansionPolicy{literal: true})
		if parsed.normalized != "" {
			canonical = parsed.normalized
		} else {
			canonical = strings.ReplaceAll(physical, `\`, "/")
		}
		linked.Flavor = PathFlavorWindows
	}
	linked.Value = canonical
	linked.Normalized = canonical
	linked.Resolved = canonical
	return linked
}

// windowsPhysicalPath reports a path the Windows file system spells: a drive
// letter, or a UNC or extended prefix. A POSIX path never starts that way
// (it is rooted at a slash), so a back slash inside a POSIX file name is
// never read as a separator.
func windowsPhysicalPath(value string) bool {
	return DriveLetterPath(value) || strings.HasPrefix(value, `\\`)
}
