//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/codesig"
)

// ClaudeDesktopEngine returns the newest Claude Code engine build Claude
// Desktop keeps under the profile home (every data folder of
// internal/claudedesktop: Roaming\Claude, the MSIX Claude-Data folder,
// Claude-3p) and the claude.exe of it that verified; Version is "" when
// none verifies. A build counts as enrolment counts it
// (discoverWindowsClaudeDesktop): a claude.exe whose Authenticode signature
// names Anthropic and whose signed file version is its folder's. Nothing in
// the folders is run.
//
// The per-user gateway takes the Claude Code hook contract from it when
// agent discovery recorded no claude version (cowork-1-0-8 GAP-0037), and
// per-user setup binds Executable as the Claude Code executable of an
// account with Claude Desktop and no claude CLI (GAP-0039).
func ClaudeDesktopEngine(_ context.Context, home string) ClaudeDesktopEngineBuild {
	return claudeDesktopEngine(home, verifyWindowsClaudeDesktopEngine)
}

// ClaudeDesktopEngineWithDigest is ClaudeDesktopEngine whose last check of
// Executable also hashes it through the handle whose signature verified
// (codesig.VerifyAuthenticodeWithSHA256) and reports that digest in SHA256.
// Per-user setup runs it (connector claude-desktop-engine) and binds only an
// engine whose own hash equals it (GAP-0039).
func ClaudeDesktopEngineWithDigest(_ context.Context, home string) ClaudeDesktopEngineBuild {
	return claudeDesktopEngine(home, verifyWindowsClaudeDesktopEngineDigest)
}

// claudeDesktopEngine checks the newest build's claude.exe a second time
// with verify.
func claudeDesktopEngine(home string, verify func(string, []string) codesig.Result) (build ClaudeDesktopEngineBuild) {
	if home == "" {
		return build
	}
	surfaces, _ := discoverWindowsClaudeDesktop(home)
	for _, found := range surfaces {
		surface := found.surface
		if surface.EngineUnverified != "" || surface.EngineVersion == "" {
			if build.Unverified == "" {
				build.Unverified = surface.EngineUnverified
			}
			continue
		}
		// >= : for one version the later data folder (3p after 1p,
		// internal/claudedesktop) wins, as Python discovery picks it.
		if build.Version == "" || compareWindowsEnterpriseVersion(surface.EngineVersion, build.Version) >= 0 {
			build.Version, build.EngineDir = surface.EngineVersion, surface.Path
		}
	}
	if build.Version == "" {
		return build
	}
	build.Unverified = ""
	executable, digest, reason := verifiedWindowsClaudeDesktopBuild(filepath.Join(build.EngineDir, build.Version), verify)
	if executable == "" {
		// Changed between the two checks: report nothing verified.
		return ClaudeDesktopEngineBuild{Unverified: reason}
	}
	build.Executable, build.SHA256 = executable, digest
	return build
}
