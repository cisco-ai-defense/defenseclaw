// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import "context"

// ClaudeDesktopEngineBuild is the newest Claude Code engine build Claude
// Desktop keeps for one account that verifies as enrolment verifies it
// (ClaudeDesktopEngine).
type ClaudeDesktopEngineBuild struct {
	// Version is the build's version folder ("2.1.317"); "" when no build
	// verifies.
	Version string `json:"version"`
	// EngineDir is the engine folder it is in (<data>/claude-code).
	EngineDir string `json:"engine_dir"`
	// Executable is the claude.exe whose signature verified (Windows only:
	// per-user setup binds it as the Claude Code executable, GAP-0039).
	Executable string `json:"executable,omitempty"`
	// SHA256 is Executable's sha256, read through the handle whose
	// signature verified (ClaudeDesktopEngineWithDigest on Windows only).
	// Setup requires its own hash of Executable to equal it, so the
	// selection it records is bound to the signed bytes (GAP-0039).
	SHA256 string `json:"sha256,omitempty"`
	// Unverified is why the newest build of a folder did not verify, when
	// no build did.
	Unverified string `json:"unverified,omitempty"`
}

// ClaudeDesktopFolder is one Claude Desktop data folder of an account and
// the newest engine build in it, for the administrator's Cowork status
// (WindowsClaudeDesktopFolders, cowork-1-0-8 GAP-0057).
type ClaudeDesktopFolder struct {
	// Deployment is "1p" (Claude account) or "3p" (third-party inference).
	Deployment string
	// Path is the data folder.
	Path string
	// EngineVersion is the newest build's version folder; "" when the
	// folder holds none.
	EngineVersion string
	// EnginePath is the claude.exe whose signature verified, or the
	// version folder that was checked.
	EnginePath string
	// Unverified is why the newest build is not trusted; "" when it is.
	Unverified string
}

// ClaudeDesktopEngineVersion is ClaudeDesktopEngine's version and engine
// folder.
func ClaudeDesktopEngineVersion(ctx context.Context, home string) (version, engineDir string) {
	build := ClaudeDesktopEngine(ctx, home)
	return build.Version, build.EngineDir
}
