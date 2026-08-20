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
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
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

// openEnvConfig on Windows opens a pinned kernel handle to the target
// file FIRST, then validates that same handle for reparse-point flags
// via GetFileInformationByHandle, then runs the path-based ancestor +
// DACL walk (managed.ValidateTrustedFilePath) for defense in depth.
// The bytes returned from the *os.File come from the handle opened in
// step 1, so an attacker who swaps the leaf file between validation
// and read cannot influence what we parse — the handle already targets
// the original kernel object.
//
// This eliminates the leaf-file stat→validate→open TOCTOU that a
// naïve three-syscall sequence would carry. The path-based ancestor
// walk still runs after the open because Windows lacks a fully
// handle-based ancestor-chain API; the ancestor walk is protected by
// the OS default DACLs on ProgramData (Users cannot write there) so
// a swap of an ancestor directory requires admin, which is the trust
// boundary this whole check terminates at.
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
	extended, err := winpath.Extended(path)
	if err != nil {
		return nil, fmt.Errorf("resolve env_config path: %w", err)
	}
	pathPtr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return nil, fmt.Errorf("encode env_config path: %w", err)
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		// OPEN_REPARSE_POINT so a symlink/junction posing as the file
		// surfaces as a reparse-flagged handle that the check below
		// rejects, rather than silently redirecting the open.
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		// Map ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND into
		// os.ErrNotExist so LoadEnvConfigEndpoint's pre-arrival branch
		// still fires. windows.CreateFile returns the same errno so
		// os.IsNotExist works via the wrapped syscall.Errno.
		return nil, err
	}
	var handleInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &handleInfo); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("inspect env_config handle: %w", err)
	}
	if handleInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("env_config must not be a reparse point")
	}
	if shouldEnforceEnvConfigTrust() {
		if err := managed.ValidateTrustedFilePath(path, "env_config"); err != nil {
			_ = windows.CloseHandle(handle)
			return nil, err
		}
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("wrap env_config Windows handle")
	}
	return file, nil
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
// boundary. Tests explicitly opt out for parser-only temporary fixtures; the
// waiver is honored only under a test binary so a production gateway that
// inherits DEFENSECLAW_ENV_CONFIG_SKIP_TRUST can never disable trust.
func shouldEnforceEnvConfigTrust() bool {
	return !envConfigTrustWaived()
}
