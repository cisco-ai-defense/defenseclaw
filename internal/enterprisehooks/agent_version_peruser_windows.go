// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// Version discovery for the standalone per-user connectors follows the same
// rule as the machine-policy connectors: static, bounded reads of files under
// the user's profile, never executing a binary as LocalSystem. The values are
// user-controlled, so they only select a hook contract and a floor; a user who
// falsifies them can at most keep their own row from enrolling, which the
// enumerator reports.

const windowsAgentLogTailMaxBytes = 256 * 1024

var (
	windowsAntigravityLogVersion = regexp.MustCompile(`Language server version: (\d+\.\d+\.\d+)`)
	windowsVersionDirectoryName  = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
)

// windowsStandalonePerUserAgentVersionCandidatePaths returns package.json
// candidates for the npm-distributed per-user connectors.
func windowsStandalonePerUserAgentVersionCandidatePaths(profileHome, connectorName string) []string {
	appDataRoaming := filepath.Join(profileHome, "AppData", "Roaming")
	appDataLocal := filepath.Join(profileHome, "AppData", "Local")
	npmGlobal := filepath.Join(appDataRoaming, "npm", "node_modules")
	bunGlobal := filepath.Join(profileHome, ".bun", "install", "global", "node_modules")
	yarnGlobal := filepath.Join(appDataLocal, "Yarn", "Data", "global", "node_modules")
	packages := map[string][]string{
		"copilot":  {filepath.Join("@github", "copilot")},
		"opencode": {"opencode-ai"},
		"amp":      {filepath.Join("@ampcode", "cli"), filepath.Join("@sourcegraph", "amp")},
	}[connectorName]
	candidates := make([]string, 0, len(packages)*3)
	for _, root := range []string{npmGlobal, bunGlobal, yarnGlobal} {
		for _, name := range packages {
			candidates = append(candidates, filepath.Join(root, name, "package.json"))
		}
	}
	return candidates
}

// discoverWindowsStandalonePerUserAgentVersion covers the per-user connectors
// that ship native installers without a package.json.
func discoverWindowsStandalonePerUserAgentVersion(profileHome, connectorName string) string {
	switch connectorName {
	case "devin":
		return discoverWindowsDevinAgentVersion(profileHome)
	case "hermes":
		return discoverWindowsHermesAgentVersion(profileHome)
	case "antigravity":
		return discoverWindowsAntigravityAgentVersion(profileHome)
	case "kiro":
		return discoverWindowsKiroAgentVersion(profileHome)
	default:
		return ""
	}
}

// Devin keeps each installed release under
// %LOCALAPPDATA%\devin\cli\_versions\<version>\bin\devin.exe; the launcher
// runs the newest one.
func discoverWindowsDevinAgentVersion(profileHome string) string {
	root := filepath.Join(profileHome, "AppData", "Local", "devin", "cli", "_versions")
	if err := winpath.RejectReparseChain(root); err != nil {
		return ""
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
	best := ""
	for index, entry := range entries {
		if index >= 64 {
			break
		}
		name := entry.Name()
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !windowsVersionDirectoryName.MatchString(name) {
			continue
		}
		binary := filepath.Join(root, name, "bin", "devin.exe")
		info, err := os.Lstat(binary)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if best == "" || compareWindowsEnterpriseVersion(name, best) > 0 {
			best = name
		}
	}
	return best
}

// Hermes records the installed release in its install stamp.
func discoverWindowsHermesAgentVersion(profileHome string) string {
	stamp := filepath.Join(profileHome, "AppData", "Local", "hermes", "hermes-agent", "install-stamp.json")
	data, err := readBoundedWindowsAgentPackageJSON(stamp)
	if err != nil {
		return ""
	}
	var parsed struct {
		BaseVersion string `json:"baseVersion"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return ""
	}
	version := strings.TrimSpace(parsed.BaseVersion)
	if !isValidWindowsAgentVersion(version) {
		return ""
	}
	return version
}

// Antigravity ships no version manifest; its CLI log records the language
// server version on every start. The binary must be installed for the log to
// count.
func discoverWindowsAntigravityAgentVersion(profileHome string) string {
	binary := filepath.Join(profileHome, "AppData", "Local", "agy", "bin", "agy.exe")
	if err := winpath.RejectReparseChain(binary); err != nil {
		return ""
	}
	if info, err := os.Lstat(binary); err != nil || !info.Mode().IsRegular() {
		return ""
	}
	tail, err := readBoundedWindowsFileTail(filepath.Join(profileHome, ".gemini", "antigravity-cli", "cli.log"))
	if err != nil {
		return ""
	}
	matches := windowsAntigravityLogVersion.FindAllSubmatch(tail, -1)
	if len(matches) == 0 {
		return ""
	}
	version := string(matches[len(matches)-1][1])
	if !isValidWindowsAgentVersion(version) {
		return ""
	}
	return version
}

// readBoundedWindowsFileTail reads at most the last windowsAgentLogTailMaxBytes
// of a regular, reparse-free file.
func readBoundedWindowsFileTail(path string) ([]byte, error) {
	if err := winpath.RejectReparseChain(path); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("candidate is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() {
		return nil, fmt.Errorf("opened candidate is not a regular file")
	}
	offset := opened.Size() - windowsAgentLogTailMaxBytes
	if offset > 0 {
		if _, err := file.Seek(offset, io.SeekStart); err != nil {
			return nil, err
		}
	}
	data, err := io.ReadAll(io.LimitReader(file, windowsAgentLogTailMaxBytes))
	if err != nil {
		return nil, err
	}
	if offset > 0 {
		// Drop the partial first line.
		if newline := bytes.IndexByte(data, '\n'); newline >= 0 {
			data = data[newline+1:]
		}
	}
	return data, nil
}
