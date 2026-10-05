// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// The native Windows Cursor Agent CLI (Cursor's PowerShell installer) ships
// no package.json version. It keeps each build as
// %LOCALAPPDATA%\cursor-agent\versions\<build>\ with the build's node.exe and
// index.js, and its cursor-agent and agent launchers in
// %LOCALAPPDATA%\cursor-agent run the build whose name carries the newest
// date. The standalone enumerator reads the version from those directory
// names, as the Linux and macOS probe reads ~/.local/share/cursor-agent/versions;
// nothing is executed. The profile owner controls these directories, so the
// result is only a version claim: it selects a hook contract and a floor, and
// a falsified name can at most keep this user's own Cursor row from enrolling.

// windowsCursorAgentMaxVersionEntries bounds the versions directory read, so
// a hostile profile cannot make the LocalSystem enumerator list an unbounded
// directory. Cursor keeps older builds after an update, so the bound is
// generous.
const windowsCursorAgentMaxVersionEntries = 256

// windowsCursorAgentBuildName is the launcher's build-directory filter: the
// YYYY.MM.DD-commit form and the newer YYYY.MM.DD-HH-MM-SS-commit form. The
// launcher matches case-insensitively.
var windowsCursorAgentBuildName = regexp.MustCompile(`^(\d{4})\.(\d{1,2})\.(\d{1,2})(?:-\d{2}-\d{2}-\d{2})?-[0-9A-Fa-f]+$`)

// windowsCursorAgentBuildDate is the launcher's sort key for a build name:
// the date as the number YYYYMMDD.
func windowsCursorAgentBuildDate(name string) (int, bool) {
	match := windowsCursorAgentBuildName.FindStringSubmatch(name)
	if match == nil {
		return 0, false
	}
	year, yearErr := strconv.Atoi(match[1])
	month, monthErr := strconv.Atoi(match[2])
	day, dayErr := strconv.Atoi(match[3])
	if yearErr != nil || monthErr != nil || dayErr != nil {
		return 0, false
	}
	return year*10000 + month*100 + day, true
}

// discoverWindowsCursorAgentCLIVersion returns the build the Cursor Agent CLI
// launchers run for this profile: the build directory with the newest date
// (the lexically greatest name among builds of that date, where the launcher
// order is unspecified), when it holds the node.exe and index.js the launcher
// starts. The reason explains an empty result.
func discoverWindowsCursorAgentCLIVersion(profileHome string) (string, string) {
	versionsDir := filepath.Join(profileHome, "AppData", "Local", "cursor-agent", "versions")
	if err := winpath.RejectReparseChain(versionsDir); err != nil {
		return "", "the Cursor Agent CLI install has a refused reparse chain"
	}
	info, err := os.Lstat(versionsDir)
	if err != nil {
		return "", "no Cursor Agent CLI under this profile"
	}
	if !info.IsDir() {
		return "", "the Cursor Agent CLI versions path is not a directory"
	}
	directory, err := os.Open(versionsDir)
	if err != nil {
		return "", "the Cursor Agent CLI versions directory is unreadable"
	}
	entries, err := directory.ReadDir(windowsCursorAgentMaxVersionEntries + 1)
	_ = directory.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return "", "the Cursor Agent CLI versions directory is unreadable"
	}
	if len(entries) > windowsCursorAgentMaxVersionEntries {
		return "", "the Cursor Agent CLI versions directory exceeds the bounded entry count"
	}
	best, bestDate := "", 0
	for _, entry := range entries {
		name := entry.Name()
		date, ok := windowsCursorAgentBuildDate(name)
		if !ok || !entry.IsDir() || !isValidWindowsAgentVersion(name) {
			continue
		}
		if best == "" || date > bestDate || (date == bestDate && name > best) {
			best, bestDate = name, date
		}
	}
	if best == "" {
		return "", "no Cursor Agent CLI build under this profile"
	}
	for _, leaf := range []string{"node.exe", "index.js"} {
		path := filepath.Join(versionsDir, best, leaf)
		if err := winpath.RejectReparseChain(path); err != nil {
			return "", "the Cursor Agent CLI build has a refused reparse chain"
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return "", fmt.Sprintf("the newest Cursor Agent CLI build %s has no %s", best, leaf)
		}
	}
	return best, ""
}
