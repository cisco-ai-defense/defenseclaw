// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package codesig verifies the vendor code signature of an agent build that
// lives in a folder its user can write, so DefenseClaw can trust that build by
// who signed it instead of by who owns its folder.
//
// The one such build today is the Claude Code engine Claude Desktop keeps in
// its data folders (one per deployment and install, internal/claudedesktop)
// and runs for Claude Cowork and its Code tab. The folder never identifies
// the build; the signature does:
//
//   - macOS: <data>/claude-code/<version>/<build>/claude.app, <data> being
//     ~/Library/Application Support/Claude or, on third-party inference,
//     Claude-3p; signed with Anthropic's Developer ID (TeamIdentifier
//     Q6L2SF6YDW, signing identifier com.anthropic.claude-code; measured on
//     Claude Desktop 4.4212.0 with engine 2.1.309 and on 4.16336.0 with
//     engine 2.1.317, both deployments). VerifyDarwin runs
//     /usr/bin/codesign --verify --strict with a requirement that names the
//     team and the identifier and anchors the chain at Apple.
//   - Windows: claude.exe under <data>\claude-code\<version>\<build>
//     (%APPDATA%\Claude, %LOCALAPPDATA%\Claude-Data\claude_<id> for the
//     MSIX package, %LOCALAPPDATA%\Claude-3p on third-party inference;
//     measured signer "Anthropic, PBC" on 4.16336.0), an
//     Authenticode signature WinVerifyTrust accepts whose signer is one of
//     AnthropicPublishers (the signer names DefenseClaw's Windows installer
//     already accepts for Claude Code, packaging/windows/install-enterprise.ps1).
//
// Linux executables carry no vendor signature, so nothing here verifies one
// there: a Linux build in a user folder stays an unidentified engine.
//
// A check is bounded, never runs the checked code, and pins the files it
// checked: a file that changes while the check runs fails it.
package codesig

import (
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// Anthropic's code-signing identities.
const (
	// AnthropicTeamID is Anthropic's Apple Developer ID team.
	AnthropicTeamID = "Q6L2SF6YDW"
	// ClaudeCodeSigningID is the signing identifier of every macOS Claude
	// Code build (the native installer's and Claude Desktop's engine).
	ClaudeCodeSigningID = "com.anthropic.claude-code"
)

// AnthropicPublishers are the Authenticode signer display names Anthropic
// signs Windows builds with.
var AnthropicPublishers = []string{"Anthropic PBC", "Anthropic, PBC"}

// Result is the outcome of one check. Reason says why a build is not
// verified; it is empty when Verified is true.
type Result struct {
	Verified bool
	Reason   string
	// Version is the verified file's own version where the platform signs
	// one (Windows: the VS_FIXEDFILEINFO product version, a.b.c.d, read
	// while the file is held open); "" when it has none.
	Version string
	// Unsigned: the code carries no signature at all (macOS codesign:
	// "code object is not signed at all"), as opposed to a signature that
	// does not verify or names another signer. Reason still says why.
	Unsigned bool
}

func refused(format string, args ...any) Result {
	return Result{Reason: fmt.Sprintf(format, args...)}
}

// Darwin names the signer a macOS build must carry.
type Darwin struct {
	TeamID     string
	Identifier string
}

// ClaudeCodeDarwin is the signer of Anthropic's macOS Claude Code builds.
var ClaudeCodeDarwin = Darwin{TeamID: AnthropicTeamID, Identifier: ClaudeCodeSigningID}

var (
	darwinTeamIDPattern     = lazyregexp.New(`^[A-Z0-9]{10}$`)
	darwinIdentifierPattern = lazyregexp.New(`^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$`)
)

// Requirement is the code-signing requirement a build of want must satisfy:
// an Apple-anchored Developer ID chain (the Developer ID intermediate,
// 1.2.840.113635.100.6.2.6, and a Developer ID Application leaf,
// 1.2.840.113635.100.6.1.13, so an Apple Development certificate of the same
// team does not pass) whose leaf names the team, and the signing identifier.
// Both values must match closed patterns, so nothing a caller passes can
// change the requirement language.
func (want Darwin) Requirement() (string, error) {
	if !darwinTeamIDPattern.MatchString(want.TeamID) {
		return "", fmt.Errorf("codesig: team identifier %q is not a ten-character Apple team ID", want.TeamID)
	}
	if !darwinIdentifierPattern.MatchString(want.Identifier) {
		return "", fmt.Errorf("codesig: signing identifier %q is not a bundle identifier", want.Identifier)
	}
	return `anchor apple generic` +
		` and certificate 1[field.1.2.840.113635.100.6.2.6] exists` +
		` and certificate leaf[field.1.2.840.113635.100.6.1.13] exists` +
		` and certificate leaf[subject.OU] = "` + want.TeamID +
		`" and identifier "` + want.Identifier + `"`, nil
}

// PublisherAllowed reports whether signer is one of publishers, compared
// exactly, as the Windows installer compares them (-cnotin).
func PublisherAllowed(signer string, publishers []string) bool {
	for _, publisher := range publishers {
		if publisher = strings.TrimSpace(publisher); publisher != "" && signer == publisher {
			return true
		}
	}
	return false
}

// boundedText is the first line of text, at most 200 bytes, for a reason.
func boundedText(text string) string {
	text = strings.TrimSpace(text)
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		text = text[:i]
	}
	if len(text) > 200 {
		text = text[:200]
	}
	return strings.TrimSpace(text)
}
