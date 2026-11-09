// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"regexp"
	"runtime"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// pathCaseFoldHost reports a host whose default file system names a file in
// any letter case and in either Unicode normalization form (APFS and HFS+ on
// macOS), so ~/.NETRC and ~/.netrc are one file. The path rules write each
// home folder and credential file in one spelling, so a path on such a host
// is also read in the spelling the rules write (caseFoldedPOSIXRuleText).
// Windows has the same property and keeps its own drive-letter handling
// (windowsNameFold). Other hosts stay case sensitive: a volume mounted
// case-insensitively there (vfat, SMB, ext4 casefold directories) is not
// detected, which is a known limit of the lexical path rules.
var pathCaseFoldHost = runtime.GOOS == "darwin"

// posixHomeFolderPath splits a path under a home root, in any letter case,
// into the root, the account folder and the rest.
var posixHomeFolderPath = regexp.MustCompile(`(?i)^/(users|home)/([^/]+)/(.+)$`)

// posixRootHomePath is the path form of the root account home, in any case.
var posixRootHomePath = regexp.MustCompile(`(?i)^/root/(.+)$`)

// caseFoldedPOSIXRuleText is the text the path rules read for an absolute path
// on a case-folding host. The home of the user is spelled ~ (or its folder in
// the case the rules read), and every name below it is read in lower case,
// which is how the rules write them. Any other path is read in lower case
// whole, so a system file the rules name in lower case is found in any case.
// Both Unicode normalization forms read as one (NFC), as the file system
// treats them.
func caseFoldedPOSIXRuleText(resolved, home string) string {
	text := respellActiveHome(norm.NFC.String(resolved), norm.NFC.String(home), true)
	if rest, ok := strings.CutPrefix(text, "~/"); ok {
		return "~/" + windowsNameFold(rest)
	}
	if match := posixHomeFolderPath.FindStringSubmatch(text); match != nil {
		return "/" + canonicalHomeRoot(match[1]) + "/" + match[2] + "/" + windowsNameFold(match[3])
	}
	if match := posixRootHomePath.FindStringSubmatch(text); match != nil {
		return "/root/" + windowsNameFold(match[1])
	}
	return windowsNameFold(text)
}

// canonicalHomeRoot is the spelling of a home root folder the path rules read.
func canonicalHomeRoot(folded string) string {
	if strings.EqualFold(folded, "users") {
		return "Users"
	}
	return "home"
}
