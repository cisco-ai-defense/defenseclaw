// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

// codexRollbackBackupName is the copy of the per-user Codex config.toml taken
// before ConvertHooksForRollback rewrites it, under <data dir>/backups.
const codexRollbackBackupName = "codex-config.before-rollback.toml"

// ConvertHooksForRollback rewrites the per-user Codex handlers this
// release writes (the direct and guarded cmd.exe starts, the answering
// bridge) into the exact command the rollback target release writes
// (opts.RollbackTargetVersion; codexWindowsRollbackTargetCommand), carrying
// their Codex trust over, so that release setup finds its own handler and
// its teardown removes it. One bridge for every target was foreign to 1.0.0
// to 1.0.7: after a rollback their setup added a second handler per event
// (GAP-2553, rel-1-0-10:GAP-0759) and their uninstall left this release
// handlers. Rolling forward again runs Setup, which writes the current form.
// Edited and foreign handlers stay as they are; a copy of the file goes to
// <data dir>/backups first.
func (c *CodexConnector) ConvertHooksForRollback(opts SetupOpts) (int, error) {
	return convertCodexConfigHookForms(opts, true, func(dataDir string, data []byte) error {
		dir, err := openClaudeCodeRollbackEvidence(dataDir, true)
		if err != nil {
			return err
		}
		defer dir.Close()
		return writeClaudeCodeRollbackEvidence(dir, codexRollbackBackupName, data)
	})
}

// RestoreHooksAfterRollback puts the handlers ConvertHooksForRollback
// rewrote back in the form this release renders when a rollback aborts while
// this release still owns the installation. It rewrites only the exact forms
// a rollback writes for its launcher and runs no Setup.
func (c *CodexConnector) RestoreHooksAfterRollback(opts SetupOpts) (int, error) {
	return convertCodexConfigHookForms(opts, false, nil)
}
