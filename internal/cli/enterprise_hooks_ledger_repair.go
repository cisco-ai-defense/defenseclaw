// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// enterpriseHookGuardianLedgerRepairer re-stamps one drifted ledger object.
// The platform implementation refuses reparse points, hard-linked files and
// any owner outside the installer set before it writes anything.
var enterpriseHookGuardianLedgerRepairer = repairEnterpriseHookGuardianLedgerObjectPlatform

type enterpriseHookGuardianLedgerObject struct {
	path      string
	directory bool
	check     func(string) error
}

func enterpriseHookGuardianLedgerObjects(dataDir string) []enterpriseHookGuardianLedgerObject {
	authorizationDir := managed.HookGuardianAuthorizationDir(dataDir)
	return []enterpriseHookGuardianLedgerObject{
		{path: authorizationDir, directory: true, check: enterpriseHookAuthorizationDirTrustCheck},
		{
			path:  filepath.Join(authorizationDir, hookGuardianAuthorizationFile),
			check: enterpriseHookAuthorizationFileTrustCheck,
		},
		{
			path:  filepath.Join(authorizationDir, hookGuardianActivationFile),
			check: enterpriseHookAuthorizationFileTrustCheck,
		},
		{
			path:  filepath.Join(dataDir, hookGuardianStateFile),
			check: enterpriseHookGuardianStateFileTrustCheck,
		},
	}
}

// repairEnterpriseHookGuardianLedger restores the canonical protection of the
// guardian's authorization folder, authorization, activation and state
// records before anything reads them. Permission drift on these files (an
// inherited ACE re-applied to the shared install tree, an owner reset by a
// backup restore) used to fail every reconcile and crash-loop the service.
//
// Healthy objects are never written. A missing object is left for the writer
// to create. Wrong object types and links are left alone so the strict
// validation that follows still reports them. The returned error only
// explains why a drifted object could not be repaired; callers join it with
// the validation verdict rather than treating it as a verdict of its own.
func repairEnterpriseHookGuardianLedger(dataDir string) error {
	if dataDir == "" {
		return nil
	}
	var failures []error
	for _, object := range enterpriseHookGuardianLedgerObjects(dataDir) {
		info, err := os.Lstat(object.path)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 || info.IsDir() != object.directory ||
			(!object.directory && !info.Mode().IsRegular()) {
			continue
		}
		trustErr := object.check(object.path)
		if trustErr == nil {
			continue
		}
		if err := enterpriseHookGuardianLedgerRepairer(object.path, object.directory); err != nil {
			failures = append(failures, fmt.Errorf("repair %s: %w", object.path, err))
			continue
		}
		if err := object.check(object.path); err != nil {
			failures = append(failures, fmt.Errorf("%s still fails trust after repair: %w", object.path, err))
			continue
		}
		managed.EmitResilienceEvent(managed.MarkerRepair, map[string]string{
			"path":   object.path,
			"reason": "hook guardian ledger protection drifted: " + trustErr.Error(),
		})
	}
	return errors.Join(failures...)
}

// enterpriseHookNoLifecycleTransactionPending reports whether no installer
// lifecycle transaction could still roll a runtime selector back. The
// installer keeps its pending marker and managed-hook lifecycle journal in the
// install folder beside the runtime data directory. Anything other than a
// clean absence of both counts as pending.
func enterpriseHookNoLifecycleTransactionPending(dataDir string) bool {
	if dataDir == "" {
		return false
	}
	installDir := filepath.Join(filepath.Dir(filepath.Clean(dataDir)), "install")
	for _, leaf := range []string{"pending.json", "managed-hooks-lifecycle-journal.json"} {
		if _, err := os.Lstat(filepath.Join(installDir, leaf)); !errors.Is(err, os.ErrNotExist) {
			return false
		}
	}
	return true
}
