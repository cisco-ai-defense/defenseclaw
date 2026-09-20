// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type ampExecutableAuthority = protectedSetupExecutableAuthority

// validateAmpWindowsSetupAdmission binds every ordinary gateway setup or
// reconciliation to the still-current executable selected by explicit setup.
// It runs before the Amp plugin or its custody receipt can be changed.
func validateAmpWindowsSetupAdmission(opts SetupOpts) error {
	authority, err := loadAmpExecutableAuthority(opts.DataDir)
	if err != nil {
		return fmt.Errorf("Amp executable admission: %w", err)
	}
	if opts.AgentVersion != authority.rawVersion {
		return errors.New("Amp executable admission: selected raw version does not match protected evidence")
	}
	if opts.HookContractID != "" && opts.HookContractID != authority.contractID {
		return errors.New("Amp executable admission: selected hook contract does not match protected evidence")
	}
	if err := validateAmpExecutableEvidence(opts.AgentExecutable, authority); err != nil {
		return fmt.Errorf("Amp executable admission: %w", err)
	}
	return nil
}

// validateAmpWindowsLockPublication closes the admission/publication race. A
// binary replacement after plugin setup must not be sealed with the previous
// version and hook contract merely because the executable path is unchanged.
func validateAmpWindowsLockPublication(dataDir string, entry HookContractLockEntry) error {
	if normalizeConnectorName(entry.Connector) != "amp" {
		return nil
	}
	if !validSetupSelectedAgentExecutableEvidence(entry, "amp") {
		return errors.New("Amp contract publication lacks valid setup-selected executable evidence")
	}
	authority, err := loadAmpExecutableAuthority(dataDir)
	if err != nil {
		return fmt.Errorf("Amp contract publication: %w", err)
	}
	if entry.RawAgentVersion != authority.rawVersion ||
		entry.NormalizedAgentVersion != authority.normalizedVersion ||
		entry.ContractID != authority.contractID ||
		entry.CompatibilityStatus != HookCompatibilityKnown ||
		!sameCodexExecutablePath(entry.AgentExecutable, authority.path) ||
		!strings.EqualFold(entry.AgentExecutableSHA256, authority.digest) {
		return errors.New("Amp contract publication does not match protected executable evidence")
	}
	if err := validateAmpExecutableEvidence(entry.AgentExecutable, authority); err != nil {
		return fmt.Errorf("Amp contract publication: %w", err)
	}
	return nil
}

func loadAmpExecutableAuthority(dataDir string) (ampExecutableAuthority, error) {
	if strings.TrimSpace(dataDir) == "" || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return ampExecutableAuthority{}, errors.New("protected state directory is not an absolute normalized path")
	}

	if authority, ok := loadProtectedSetupExecutableAuthority(dataDir, "amp"); ok {
		return authority, nil
	}
	if _, exists := loadProtectedHookContractEntry(dataDir, "amp"); exists {
		return ampExecutableAuthority{}, errors.New("protected Amp contract lock executable evidence is invalid")
	}
	return ampExecutableAuthority{}, errors.New("fresh protected setup receipt or reusable protected contract lock is required")
}

func validateAmpExecutableEvidence(selected string, authority ampExecutableAuthority) error {
	if selected == "" || strings.TrimSpace(selected) != selected ||
		strings.ContainsAny(selected, "\x00\r\n") || !filepath.IsAbs(selected) ||
		filepath.Clean(selected) != selected {
		return errors.New("selected executable is not an absolute normalized path")
	}
	if !strings.EqualFold(filepath.Base(selected), "amp.exe") {
		return errors.New("selected executable is not the native Amp amp.exe image")
	}
	if !sameCodexExecutablePath(selected, authority.path) {
		return errors.New("selected executable path does not match protected evidence")
	}
	resolution := ResolveHookContract("amp", authority.rawVersion)
	if resolution.Status != HookCompatibilityKnown ||
		resolution.NormalizedVersion != authority.normalizedVersion ||
		resolution.Contract.ContractID != authority.contractID {
		return errors.New("protected Amp version or hook contract evidence is invalid")
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
