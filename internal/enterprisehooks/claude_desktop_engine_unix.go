//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"os"
)

// ClaudeDesktopEngine returns the newest Claude Code engine build Claude
// Desktop keeps for the account whose home is home; its Version is "" when
// no build verifies. A build counts as enrolment counts it
// (discoverUnixClaudeDesktopEngines): on macOS its code signature is
// Anthropic's Claude Code and its sealed Info.plist names its folder's
// version; on Linux, where builds carry no vendor signature, its version
// folder holds an executable engine. Nothing in the folders is run. It must
// run as the account itself (the per-user gateway), never as root.
//
// The per-user gateway takes the Claude Code hook contract from it when
// agent discovery recorded no claude version: an account with Claude
// Desktop and no claude CLI (cowork-1-0-8 GAP-0037).
func ClaudeDesktopEngine(ctx context.Context, home string) (build ClaudeDesktopEngineBuild) {
	if home == "" || os.Geteuid() == 0 {
		return build
	}
	for _, probe := range unixSurfaceProbes["claudecode"].desktop {
		if probe.goos != unixSurfaceGOOS || !probe.claudeDesktopEngines {
			continue
		}
		surfaces, _ := discoverUnixClaudeDesktopEngines(ctx, home, probe)
		for _, surface := range surfaces {
			if surface.EngineUnverified != "" || surface.EngineVersion == "" {
				if build.Unverified == "" {
					build.Unverified = surface.EngineUnverified
				}
				continue
			}
			// >= : for one version the later data folder (3p after 1p,
			// internal/claudedesktop) wins, as Python discovery picks it.
			if build.Version == "" || compareUnixVersions(surface.EngineVersion, build.Version) >= 0 {
				build.Version, build.EngineDir = surface.EngineVersion, surface.Path
			}
		}
	}
	if build.Version != "" {
		build.Unverified = ""
	}
	return build
}

// ClaudeDesktopEngineWithDigest is ClaudeDesktopEngine: SHA256 is reported
// only on Windows, the one platform whose setup binds the engine as the
// Claude Code executable (GAP-0039).
func ClaudeDesktopEngineWithDigest(ctx context.Context, home string) ClaudeDesktopEngineBuild {
	return ClaudeDesktopEngine(ctx, home)
}
