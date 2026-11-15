// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effectrules

import (
	"path"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/effects"
)

// RestrictedBlockPrograms is the reviewed allowlist of programs whose known,
// fully-accounted mutation of an exact canonical protected path may block in
// the effect lane (the restricted tier, owner decision 2026-11-13). It is a
// single data table on purpose, so a review can clear more programs by adding
// a name here, not by touching scattered logic. Names are lower-case
// basenames (POSIX) or cmdlets (PowerShell). Shell redirection carries no
// program word, so the empty string is listed for it.
var RestrictedBlockPrograms = map[string]bool{
	"":            true, // shell redirection  >  >>
	"cp":          true,
	"mv":          true,
	"ln":          true,
	"tee":         true,
	"rm":          true,
	"install":     true,
	"set-content": true,
	"add-content": true,
	"out-file":    true,
	"copy-item":   true,
	"move-item":   true,
	"remove-item": true,
	"new-item":    true,
}

// RestrictedBlockCommand reports whether a mutating effect's producing program
// is on the restricted allowlist for its surface. A connector file write, edit
// or patch tool qualifies by surface (no program word); a shell/argv mutation
// qualifies by program name.
func RestrictedBlockCommand(program string, surface effects.Surface) bool {
	switch surface {
	case effects.SurfaceFileTool, effects.SurfacePatch:
		return true
	}
	return RestrictedBlockPrograms[strings.ToLower(strings.TrimSpace(program))]
}

// canonicalAbsolute reports whether a path is already absolute and in cleaned
// canonical form, so it names exactly one file with no .. or . or doubled
// separators to reinterpret. Windows uses backslash separators.
func CanonicalAbsolute(p string, flavor effects.Flavor) bool {
	if p == "" {
		return false
	}
	if flavor == effects.FlavorWindows {
		// Accept a drive-absolute path whose slash form is already clean.
		slash := strings.ReplaceAll(p, "\\", "/")
		if len(slash) < 3 || slash[1] != ':' || slash[2] != '/' {
			return false
		}
		drive := slash[:2]
		return p == drive+strings.ReplaceAll(path.Clean(slash[2:]), "/", "\\") ||
			p == drive+path.Clean(slash[2:])
	}
	return strings.HasPrefix(p, "/") && p == path.Clean(p)
}
