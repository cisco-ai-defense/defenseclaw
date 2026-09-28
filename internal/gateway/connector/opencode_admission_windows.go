// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

const openCodeWindowsPackageDirectory = "SST.opencode_Microsoft.Winget.Source_8wekyb3d8bbwe"

var openCodeWindowsExecutablePathResolver = func() string {
	if OpenCodeExecutablePathOverride != "" {
		return OpenCodeExecutablePathOverride
	}
	return currentUserOpenCodeWindowsExecutablePath()
}

// openCodeWindowsNPMExecutablePathResolver names the native image npm's
// opencode.cmd launches from the opencode-ai package for the user whose
// paths are being resolved.
var openCodeWindowsNPMExecutablePathResolver = currentUserOpenCodeWindowsNPMExecutablePath

// OpenCodeWindowsPackageIdentityVerified reports whether an OpenCode image
// comes from a recognized package: the SST WinGet package directory, or the
// npm opencode-ai package whose package.json names it.
func OpenCodeWindowsPackageIdentityVerified(executable string) bool {
	clean := filepath.Clean(strings.TrimSpace(executable))
	if !strings.EqualFold(filepath.Base(clean), "opencode.exe") {
		return false
	}
	if strings.EqualFold(filepath.Base(filepath.Dir(clean)), openCodeWindowsPackageDirectory) {
		return true
	}
	bin := filepath.Dir(clean)
	pkg := filepath.Dir(bin)
	if !strings.EqualFold(filepath.Base(bin), "bin") || !strings.EqualFold(filepath.Base(pkg), "opencode-ai") ||
		!strings.EqualFold(filepath.Base(filepath.Dir(pkg)), "node_modules") {
		return false
	}
	manifest := filepath.Join(pkg, "package.json")
	info, err := os.Lstat(manifest)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > 256<<10 {
		return false
	}
	data, err := os.ReadFile(manifest)
	if err != nil {
		return false
	}
	var parsed struct {
		Name string `json:"name"`
	}
	return json.Unmarshal(data, &parsed) == nil && parsed.Name == "opencode-ai"
}

type openCodeExecutableAuthority = protectedSetupExecutableAuthority

// validateOpenCodeWindowsSetupAdmission authenticates the exact SST WinGet
// image whose version selects OpenCode's hook contract. DefenseClaw does not
// launch this executable, but its bytes are still compatibility authority for
// the in-process policy plugin and must remain stable across restarts.
func validateOpenCodeWindowsSetupAdmission(opts SetupOpts) error {
	authority, err := loadOpenCodeExecutableAuthority(opts.DataDir)
	if err != nil {
		return fmt.Errorf("OpenCode executable admission: %w", err)
	}
	if opts.AgentVersion != authority.rawVersion {
		return errors.New("OpenCode executable admission: selected raw version does not match protected evidence")
	}
	if opts.HookContractID != "" && opts.HookContractID != authority.contractID {
		return errors.New("OpenCode executable admission: selected hook contract does not match protected evidence")
	}
	if err := validateOpenCodeExecutableEvidence(opts.AgentExecutable, authority); err != nil {
		return fmt.Errorf("OpenCode executable admission: %w", err)
	}
	return nil
}

// validateOpenCodeWindowsLockPublication prevents a path replacement between
// Python's replacement-locked version/digest probe and Go's durable lock
// publication. A fresh receipt authorizes first publication or repair; after
// it expires, an intact sealed lock is the only bounded reuse authority.
func validateOpenCodeWindowsLockPublication(dataDir string, entry HookContractLockEntry) error {
	if normalizeConnectorName(entry.Connector) != "opencode" {
		return nil
	}
	if !validSetupSelectedAgentExecutableEvidence(entry, "opencode") {
		return errors.New("OpenCode contract publication lacks valid setup-selected executable evidence")
	}
	authority, err := loadOpenCodeExecutableAuthority(dataDir)
	if err != nil {
		return fmt.Errorf("OpenCode contract publication: %w", err)
	}
	if entry.RawAgentVersion != authority.rawVersion ||
		entry.NormalizedAgentVersion != authority.normalizedVersion ||
		entry.ContractID != authority.contractID ||
		entry.CompatibilityStatus != HookCompatibilityKnown ||
		!sameCodexExecutablePath(entry.AgentExecutable, authority.path) ||
		!strings.EqualFold(entry.AgentExecutableSHA256, authority.digest) {
		return errors.New("OpenCode contract publication does not match protected executable evidence")
	}
	if err := validateOpenCodeExecutableEvidence(entry.AgentExecutable, authority); err != nil {
		return fmt.Errorf("OpenCode contract publication: %w", err)
	}
	return nil
}

func loadOpenCodeExecutableAuthority(dataDir string) (openCodeExecutableAuthority, error) {
	if strings.TrimSpace(dataDir) == "" || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return openCodeExecutableAuthority{}, errors.New("protected state directory is not an absolute normalized path")
	}
	if authority, ok := loadProtectedSetupExecutableAuthority(dataDir, "opencode"); ok {
		return authority, nil
	}
	if _, exists := loadProtectedHookContractEntry(dataDir, "opencode"); exists {
		return openCodeExecutableAuthority{}, errors.New("protected OpenCode contract lock executable evidence is invalid")
	}
	return openCodeExecutableAuthority{}, errors.New("fresh protected setup receipt or reusable protected contract lock is required")
}

func validateOpenCodeExecutableEvidence(selected string, authority openCodeExecutableAuthority) error {
	if selected == "" || strings.TrimSpace(selected) != selected ||
		strings.ContainsAny(selected, "\x00\r\n") || !filepath.IsAbs(selected) ||
		filepath.Clean(selected) != selected || !strings.EqualFold(filepath.Base(selected), "opencode.exe") {
		return errors.New("selected executable is not an absolute normalized opencode.exe path")
	}
	matched := false
	for _, expected := range []string{openCodeWindowsExecutablePathResolver(), openCodeWindowsNPMExecutablePathResolver()} {
		if expected == "" || strings.TrimSpace(expected) != expected ||
			strings.ContainsAny(expected, "\x00\r\n") || !filepath.IsAbs(expected) ||
			filepath.Clean(expected) != expected {
			continue
		}
		if sameCodexExecutablePath(selected, expected) {
			matched = true
		}
	}
	if !matched || !sameCodexExecutablePath(selected, authority.path) {
		return errors.New("selected executable is not the protected SST WinGet or npm opencode-ai executable for this user")
	}
	if !OpenCodeWindowsPackageIdentityVerified(selected) {
		return errors.New("selected executable package identity is not verified")
	}

	before, err := os.Lstat(selected)
	if err != nil {
		return fmt.Errorf("inspect selected executable: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return errors.New("selected executable is not a regular non-reparse file")
	}
	if err := hookAPIValidateDirectory(filepath.Dir(selected)); err != nil {
		return fmt.Errorf("validate selected executable directory custody: %w", err)
	}
	if err := hookAPIValidateOwner(selected, before); err != nil {
		return fmt.Errorf("validate selected executable custody: %w", err)
	}
	stablePath, digest, ok := setupSelectedAgentExecutableEvidence(selected)
	if !ok || !sameCodexExecutablePath(stablePath, selected) {
		return errors.New("selected executable changed during stable hashing")
	}
	after, err := os.Lstat(selected)
	if err != nil || after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() ||
		!os.SameFile(before, after) || before.Size() != after.Size() ||
		!before.ModTime().Equal(after.ModTime()) {
		return errors.New("selected executable changed during custody validation")
	}
	if err := hookAPIValidateOwner(selected, after); err != nil {
		return fmt.Errorf("revalidate selected executable custody: %w", err)
	}
	if !strings.EqualFold(digest, authority.digest) {
		return errors.New("selected executable digest does not match protected evidence")
	}
	return nil
}

func currentUserOpenCodeWindowsNPMExecutablePath() string {
	var roaming string
	if home := activeUserHomeOverride(); home != "" {
		roaming = filepath.Join(home, "AppData", "Roaming")
	} else {
		value, err := winpath.CurrentUserKnownFolderPath(windows.FOLDERID_RoamingAppData)
		if err != nil {
			return ""
		}
		roaming = value
	}
	if strings.TrimSpace(roaming) == "" || strings.ContainsAny(roaming, "\x00\r\n") || !filepath.IsAbs(roaming) {
		return ""
	}
	return filepath.Join(filepath.Clean(roaming), "npm", "node_modules", "opencode-ai", "bin", "opencode.exe")
}

func currentUserOpenCodeWindowsExecutablePath() string {
	if home := activeUserHomeOverride(); home != "" {
		return filepath.Join(filepath.Clean(home), "AppData", "Local", "Microsoft", "WinGet", "Packages",
			openCodeWindowsPackageDirectory, "opencode.exe")
	}
	localAppData, err := winpath.CurrentUserKnownFolderPath(windows.FOLDERID_LocalAppData)
	if err != nil || strings.TrimSpace(localAppData) == "" ||
		strings.ContainsAny(localAppData, "\x00\r\n") || !filepath.IsAbs(localAppData) {
		return ""
	}
	localAppData = filepath.Clean(localAppData)
	return filepath.Join(
		localAppData,
		"Microsoft",
		"WinGet",
		"Packages",
		openCodeWindowsPackageDirectory,
		"opencode.exe",
	)
}
