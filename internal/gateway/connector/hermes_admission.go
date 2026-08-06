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

package connector

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/hermespath"
	"github.com/defenseclaw/defenseclaw/internal/processutil"
)

const (
	hermesVersionProbeTimeout     = 10 * time.Second
	hermesVersionProbeOutputLimit = int64(4 << 10)
)

var (
	hermesManagedExecutablePathResolver = hermespath.ManagedExecutablePath
	hermesAgentVersionProbe             = probeHermesAgentVersion
)

type hermesExecutableAuthority struct {
	path              string
	digest            string
	rawVersion        string
	normalizedVersion string
	contractID        string
}

// validateHermesWindowsSetupAdmission authenticates all executable/version
// evidence that hook-only setup will use. It is intentionally read-only and
// must run before lifecycle locks, backups, hook assets, config, allowlist,
// contract-lock, or active-connector state can be created or changed.
func validateHermesWindowsSetupAdmission(ctx context.Context, opts SetupOpts) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	authority, err := loadHermesExecutableAuthority(opts.DataDir)
	if err != nil {
		return fmt.Errorf("Hermes executable admission: %w", err)
	}
	if opts.AgentVersion != authority.rawVersion {
		return errors.New("Hermes executable admission: selected raw version does not match protected evidence")
	}
	if opts.HookContractID != "" && opts.HookContractID != authority.contractID {
		return errors.New("Hermes executable admission: selected hook contract does not match protected evidence")
	}
	if err := validateHermesExecutableEvidence(ctx, opts.AgentExecutable, authority); err != nil {
		return fmt.Errorf("Hermes executable admission: %w", err)
	}
	return nil
}

// validateHermesWindowsLockPublication prevents NewHookContractLockEntry from
// sealing bytes that changed after setup admission while retaining a stale
// receipt version/contract. A fresh setup receipt is explicit repair authority;
// after it expires, the existing protected lock is the bounded reuse authority.
func validateHermesWindowsLockPublication(
	ctx context.Context,
	dataDir string,
	entry HookContractLockEntry,
) error {
	if runtime.GOOS != "windows" || normalizeConnectorName(entry.Connector) != "hermes" {
		return nil
	}
	if !validSetupSelectedAgentExecutableEvidence(entry, "hermes") {
		return errors.New("Hermes contract publication lacks valid setup-selected executable evidence")
	}
	authority, err := loadHermesExecutableAuthority(dataDir)
	if err != nil {
		return fmt.Errorf("Hermes contract publication: %w", err)
	}
	if entry.RawAgentVersion != authority.rawVersion ||
		entry.NormalizedAgentVersion != authority.normalizedVersion ||
		entry.ContractID != authority.contractID ||
		entry.CompatibilityStatus != HookCompatibilityKnown ||
		!sameCodexExecutablePath(entry.AgentExecutable, authority.path) ||
		!strings.EqualFold(entry.AgentExecutableSHA256, authority.digest) {
		return errors.New("Hermes contract publication does not match protected executable evidence")
	}
	if err := validateHermesExecutableEvidence(ctx, entry.AgentExecutable, authority); err != nil {
		return fmt.Errorf("Hermes contract publication: %w", err)
	}
	return nil
}

func loadHermesExecutableAuthority(dataDir string) (hermesExecutableAuthority, error) {
	if strings.TrimSpace(dataDir) == "" || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return hermesExecutableAuthority{}, errors.New("protected state directory is not an absolute normalized path")
	}
	if selection, ok := loadSetupAgentSelection(dataDir, "hermes"); ok {
		resolution := ResolveHookContract("hermes", selection.RawVersion)
		return hermesExecutableAuthority{
			path:              selection.Executable,
			digest:            selection.SHA256,
			rawVersion:        selection.RawVersion,
			normalizedVersion: selection.NormalizedVersion,
			contractID:        resolution.Contract.ContractID,
		}, nil
	}
	entry, exists := loadProtectedHookContractEntry(dataDir, "hermes")
	if !exists {
		return hermesExecutableAuthority{}, errors.New("fresh protected setup receipt or reusable protected contract lock is required")
	}
	if !validSetupSelectedAgentExecutableEvidence(entry, "hermes") {
		return hermesExecutableAuthority{}, errors.New("protected Hermes contract lock executable evidence is invalid")
	}
	return hermesExecutableAuthority{
		path:              entry.AgentExecutable,
		digest:            entry.AgentExecutableSHA256,
		rawVersion:        entry.RawAgentVersion,
		normalizedVersion: entry.NormalizedAgentVersion,
		contractID:        entry.ContractID,
	}, nil
}

func validateHermesExecutableEvidence(
	ctx context.Context,
	selected string,
	authority hermesExecutableAuthority,
) error {
	if selected == "" || strings.TrimSpace(selected) != selected ||
		strings.ContainsAny(selected, "\x00\r\n") || !filepath.IsAbs(selected) ||
		filepath.Clean(selected) != selected {
		return errors.New("selected executable is not an absolute normalized path")
	}
	rawManaged := hermesManagedExecutablePathResolver()
	managed := strings.TrimSpace(rawManaged)
	if managed == "" || managed != rawManaged || strings.ContainsAny(managed, "\x00\r\n") ||
		!filepath.IsAbs(managed) || filepath.Clean(managed) != managed {
		return errors.New("current-token updater-managed executable path is unavailable")
	}
	if !sameCodexExecutablePath(selected, managed) || !sameCodexExecutablePath(selected, authority.path) {
		return errors.New("selected executable is not the protected current-token updater-managed executable")
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
	if !strings.EqualFold(digest, authority.digest) {
		return errors.New("selected executable digest does not match protected evidence")
	}

	raw, err := hermesAgentVersionProbe(ctx, selected)
	if err != nil {
		return fmt.Errorf("fresh version probe failed: %w", err)
	}
	resolution := ResolveHookContract("hermes", raw)
	if raw != authority.rawVersion || resolution.Status != HookCompatibilityKnown ||
		resolution.NormalizedVersion != authority.normalizedVersion ||
		resolution.Contract.ContractID != authority.contractID {
		return errors.New("fresh version probe does not match protected raw, normalized, and contract evidence")
	}
	postProbePath, postProbeDigest, ok := setupSelectedAgentExecutableEvidence(selected)
	if !ok || !sameCodexExecutablePath(postProbePath, selected) ||
		!strings.EqualFold(postProbeDigest, authority.digest) {
		return errors.New("selected executable changed during fresh version probing")
	}
	return nil
}

type hermesBoundedCommandBuffer struct {
	bytes.Buffer
	limit int64
}

func (b *hermesBoundedCommandBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - int64(b.Len())
	if remaining <= 0 {
		return 0, fmt.Errorf("command output exceeds %d bytes", b.limit)
	}
	if int64(len(p)) > remaining {
		written, _ := b.Buffer.Write(p[:remaining])
		return written, fmt.Errorf("command output exceeds %d bytes", b.limit)
	}
	return b.Buffer.Write(p)
}

func probeHermesAgentVersion(ctx context.Context, executable string) (string, error) {
	probeCtx, cancel := context.WithTimeout(ctx, hermesVersionProbeTimeout)
	defer cancel()
	cmd := processutil.CommandContext(probeCtx, executable, "--version")
	stdout := &hermesBoundedCommandBuffer{limit: hermesVersionProbeOutputLimit}
	stderr := &hermesBoundedCommandBuffer{limit: hermesVersionProbeOutputLimit}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(probeCtx.Err(), context.DeadlineExceeded) {
			return "", fmt.Errorf("probe timed out after %s: %w", hermesVersionProbeTimeout, context.DeadlineExceeded)
		}
		return "", fmt.Errorf("probe exited unsuccessfully: %w", err)
	}
	raw := strings.TrimSpace(stdout.String())
	if raw == "" {
		raw = strings.TrimSpace(stderr.String())
	}
	if raw == "" || strings.ContainsAny(raw, "\x00\r\n") {
		return "", errors.New("probe returned an empty or multiline version")
	}
	return raw, nil
}
