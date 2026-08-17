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

package config

import (
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// ResolveDefaultEnvConfigPath returns the AVC drop location for Windows
// managed installs. ProgramData is resolved from protected 64-bit HKLM
// registration rather than assumed to be C:\ProgramData or inherited from an
// attacker-controlled process environment.
func ResolveDefaultEnvConfigPath() (string, error) {
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		return "", err
	}
	return filepath.Join(
		programData,
		"Cisco",
		"Cisco Secure Client",
		"DefenseClaw",
		"env_config.json",
	), nil
}

// openEnvConfig on Windows validates path-level trust up front (owner,
// no world/non-admin write, no reparse point, ancestor chain
// administrator-owned) via managed.ValidateTrustedFilePath, then does a
// plain read-only open.
//
// Windows has no direct O_NOFOLLOW-equivalent flag on os.OpenFile, so
// the darwin/linux "single-syscall atomic open + O_NOFOLLOW" pattern is
// not available. Instead we rely on the fact that only administrators
// can write into the AVC-owned parent directory (validated by
// ValidateTrustedFilePath's ancestor walk) — an attacker without admin
// cannot swap the file between validation and open, and an attacker
// WITH admin is inside the trust boundary of this check to begin with.
//
// The trust check applies to the restricted gateway virtual service account
// as well as elevated callers. DEFENSECLAW_ENV_CONFIG_SKIP_TRUST=1 is reserved
// for parser tests whose temporary fixtures cannot carry the production ACL.
//
// A missing file surfaces as os.ErrNotExist so LoadEnvConfigEndpoint
// can convert it to ErrEnvConfigMissing (the pre-arrival case). Trust
// failures surface as the wrapped ValidateTrustedFilePath error, which
// LoadEnvConfigEndpoint's caller (ConfigManager.Reload) treats the same
// as a malformed overlay: log + retain the previously-active endpoint.
func openEnvConfig(path string) (*os.File, error) {
	// Probe existence first so a missing file yields os.ErrNotExist
	// (mapped to ErrEnvConfigMissing upstream) rather than a wrapped
	// trust-validation error that would be logged as "malformed
	// overlay" in the ConfigManager reload path.
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	if shouldEnforceEnvConfigTrust() {
		if err := managed.ValidateTrustedFilePath(path, "env_config"); err != nil {
			return nil, err
		}
	}
	return os.Open(path)
}

// trustEnvConfigFilePlatform is a no-op on Windows because the full
// trust check (ancestor chain admin-owned, no reparse point, no world-
// writable ACLs) already ran inside openEnvConfig via
// managed.ValidateTrustedFilePath. Splitting the check across
// openEnvConfig and this hook would double-validate for no gain and
// diverge from the Unix path structure (see env_config_unix.go).
func trustEnvConfigFilePlatform(_ os.FileInfo) error {
	return nil
}

// shouldEnforceEnvConfigTrust is fail-closed for every production caller. The
// gateway intentionally runs as a restricted virtual service account, whose
// token is not elevated; elevation therefore cannot define this trust
// boundary. Tests explicitly opt out for parser-only temporary fixtures.
func shouldEnforceEnvConfigTrust() bool {
	return os.Getenv("DEFENSECLAW_ENV_CONFIG_SKIP_TRUST") != "1"
}
