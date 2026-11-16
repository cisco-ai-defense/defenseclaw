//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/claudedesktop"
	"github.com/defenseclaw/defenseclaw/internal/codesig"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// windowsClaudeDesktopFoldersReadAs runs fn where an account's Claude
// Desktop folders may be read. A LocalSystem caller (an MDM status run)
// reads under the token of the account's session, active or disconnected,
// as discovery does (windowsSurfaceReadAs), so a signed-out account is not
// checked. Any other caller is the account itself or an elevated
// administrator, who may read the profile already; its reads refuse reparse
// points (readWindowsDirBounded, codesig.VerifyAuthenticode) and run
// nothing. Tests replace it.
var windowsClaudeDesktopFoldersReadAs = func(sid, home string, fn func() error) error {
	if requireWindowsEnterpriseLocalSystem() == nil {
		return windowsSurfaceReadAs(sid, home, fn)
	}
	return fn()
}

// windowsClaudeDesktopProfileHome is sid's profile folder from ProfileList,
// checked as the guardian checks a target's home (owner, volume, no reparse
// anchor); tests replace it.
var windowsClaudeDesktopProfileHome = func(sid string) (string, error) {
	home, err := windowsProfileImagePathReader(sid)
	if err != nil {
		return "", err
	}
	home, _, err = validateWindowsEnterpriseHome(home, sid)
	return home, err
}

// WindowsClaudeDesktopFolders lists the Claude Desktop data folders of the
// account sid (internal/claudedesktop: Roaming\Claude, the MSIX Claude-Data
// folder, Claude-3p) that exist, each with its newest engine build and that
// build's trust, for the administrator's Cowork status (cowork-1-0-8
// GAP-0057, the Windows form of GAP-0031). A build is trusted as enrolment
// trusts it: a claude.exe whose Authenticode signature names Anthropic and
// whose signed file version is its folder's (verifiedWindowsClaudeDesktopBuild).
// It is read-only and runs nothing in the folders. The error says what was
// not read; the folders listed are still right.
func WindowsClaudeDesktopFolders(sid string) ([]ClaudeDesktopFolder, error) {
	sid = strings.TrimSpace(sid)
	if sid == "" {
		return nil, errors.New("the account has no SID")
	}
	home, err := windowsClaudeDesktopProfileHome(sid)
	if err != nil {
		return nil, fmt.Errorf("its profile folder was not resolved: %w", err)
	}
	var folders []ClaudeDesktopFolder
	var scanErr error
	if err := windowsClaudeDesktopFoldersReadAs(sid, home, func() error {
		folders, scanErr = windowsClaudeDesktopFolders(home, verifyWindowsClaudeDesktopEngine)
		return nil
	}); err != nil {
		return nil, err
	}
	return folders, scanErr
}

// windowsClaudeDesktopFolders is WindowsClaudeDesktopFolders under home,
// checking each claude.exe with verify.
func windowsClaudeDesktopFolders(home string, verify func(string, []string) codesig.Result) ([]ClaudeDesktopFolder, error) {
	var scanErr error
	dirs, overflow := claudedesktop.DataDirs("windows", claudedesktop.FoldersForHome("windows", home))
	if overflow {
		scanErr = fmt.Errorf("more Claude Desktop data folders match than the %d read", claudedesktop.MaxGlobMatches)
	}
	var out []ClaudeDesktopFolder
	for _, dir := range dirs {
		folder := ClaudeDesktopFolder{Deployment: string(dir.Root.Deployment), Path: dir.Path}
		if err := winpath.RejectReparseChain(dir.Path); err != nil {
			if _, statErr := os.Lstat(dir.Path); statErr == nil {
				folder.Unverified = "the folder was not inspected: " + err.Error()
				out = append(out, folder)
			}
			continue
		}
		if info, err := os.Lstat(dir.Path); err != nil || !info.IsDir() {
			continue
		}
		engineDir := filepath.Join(dir.Path, claudedesktop.EngineFolder)
		versions, err := windowsEngineVersionDirs(engineDir)
		if err != nil {
			scanErr = errors.Join(scanErr, err)
		}
		if len(versions) == 0 {
			if err != nil {
				folder.Unverified = err.Error()
			}
			out = append(out, folder)
			continue
		}
		folder.EngineVersion = versions[0]
		versionDir := filepath.Join(engineDir, versions[0])
		executable, _, reason := verifiedWindowsClaudeDesktopBuild(versionDir, verify)
		if executable == "" {
			folder.EnginePath, folder.Unverified = versionDir, reason
		} else {
			folder.EnginePath = executable
		}
		out = append(out, folder)
	}
	return out, scanErr
}
