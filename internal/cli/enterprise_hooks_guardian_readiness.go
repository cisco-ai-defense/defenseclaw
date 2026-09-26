// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks/guardianstate"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// guardianReadinessStateTrustCheck gates the gateway-side read. The
// readiness literal is diagnostic health, not authorization, but it is still
// only honored when the file carries the same administrator-only-writable
// contract as the protected authorization ledger beside it, so a file the
// gateway (or any other non-administrator) could have written is reported as
// unknown rather than trusted.
var guardianReadinessStateTrustCheck = func(path string) error {
	return managed.ValidateTrustedFilePath(path, "hook guardian readiness state")
}

// writeEnterpriseHookGuardianReadinessState publishes the guardian's
// waiting_for_targets / ready literal at guardianstate.PathForDataDir, the
// same path newGuardianReadinessStateReader resolves in the gateway. The
// file is written exactly like the protected authorization and activation
// records in that directory: only into an already-trusted directory, through
// the protected machine-file writer, with the administrator-owned
// gateway-read-only ownership, and re-verified afterwards. It never creates
// or re-permissions the directory, so it cannot widen who may write there.
func writeEnterpriseHookGuardianReadinessState(dataDir, state string) (string, error) {
	path := guardianstate.PathForDataDir(dataDir)
	body, err := guardianstate.Encode(state)
	if err != nil {
		return path, err
	}
	dir := filepath.Dir(path)
	info, err := os.Lstat(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return path, fmt.Errorf("hook guardian authorization directory %s does not exist yet", dir)
		}
		return path, fmt.Errorf("inspect hook guardian authorization directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return path, fmt.Errorf("hook guardian authorization path is not a trusted directory: %s", dir)
	}
	if err := enterpriseHookAuthorizationDirTrustCheck(dir); err != nil {
		return path, err
	}
	if err := writeEnterpriseHookProtectedFile(path, body); err != nil {
		return path, err
	}
	if err := os.Chmod(path, 0o640); err != nil {
		return path, fmt.Errorf("make hook guardian readiness state readable: %w", err)
	}
	if err := enterpriseHookAuthorizationOwnershipSetter(path); err != nil {
		return path, fmt.Errorf("set hook guardian readiness state ownership: %w", err)
	}
	if err := enterpriseHookAuthorizationFileTrustCheck(path); err != nil {
		return path, err
	}
	return path, nil
}

// newGuardianReadinessStateReader is the gateway sidecar's probe for the
// guardian readiness literal. It resolves the path through the same helper
// as the writer and returns StateUnknown (the safe waiting_for_targets
// default) for a missing, unreadable, malformed, or untrusted file.
func newGuardianReadinessStateReader(dataDir string) func() string {
	path := guardianstate.PathForDataDir(dataDir)
	return func() string {
		if err := guardianReadinessStateTrustCheck(path); err != nil {
			return guardianstate.StateUnknown
		}
		return guardianstate.ReadState(path)
	}
}
