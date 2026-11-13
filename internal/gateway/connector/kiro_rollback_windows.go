// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"strings"
)

// ConvertHooksForRollback rewrites the per-user Kiro hook commands this
// release writes (the bridge that answers a launcher that cannot start,
// rel-1-0-6 GAP-0676) into the form the rollback target release writes and
// owns (opts.RollbackTargetVersion, rel-1-0-10:GAP-0275), so the older
// release's setup and teardown find them. Rolling forward again
// runs Setup, which writes the current form. A copy of each file it changes
// goes to <data dir>/backups first.
func (c *KiroConnector) ConvertHooksForRollback(opts SetupOpts) (int, error) {
	return c.convertKiroConfigHookForms(opts, true, func(dataDir, name string, data []byte) error {
		dir, err := openClaudeCodeRollbackEvidence(dataDir, true)
		if err != nil {
			return err
		}
		defer dir.Close()
		return writeClaudeCodeRollbackEvidence(dir, name, data)
	})
}

// RestoreHooksAfterRollback puts the commands ConvertHooksForRollback
// rewrote back in this release's form when a rollback aborts.
func (c *KiroConnector) RestoreHooksAfterRollback(opts SetupOpts) (int, error) {
	return c.convertKiroConfigHookForms(opts, false, nil)
}

// convertKiroConfigHookForms applies convertKiroHookFileForms to every Kiro
// hook and agent file setup or teardown handles, each under its lock, and
// keeps a copy of a file before a rollback conversion. Managed installs are
// left alone: their guardian writes the managed form, which no release
// changed.
func (c *KiroConnector) convertKiroConfigHookForms(opts SetupOpts, toEarlier bool, keepCopy func(dataDir, name string, data []byte) error) (int, error) {
	if kiroManaged(opts) {
		return 0, nil
	}
	launchers := append([]string{strings.TrimSpace(opts.HookExecutable)}, nativeHookBinaryOwnershipCandidates()...)
	pairs := kiroWindowsHookFormPairs(launchers, opts.RollbackTargetVersion, toEarlier)
	paths := append(append(c.hookCleanupPaths(opts), c.agentConfigPaths(opts)...), c.agentCleanupPaths(opts)...)
	total := 0
	for _, path := range uniqueNonEmptyStrings(paths) {
		converted, err := convertKiroHooksFile(path, opts.DataDir, c.Name(), pairs, toEarlier, keepCopy)
		if err != nil {
			return total, err
		}
		total += converted
	}
	return total, nil
}
