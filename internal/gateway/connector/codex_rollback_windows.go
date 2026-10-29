// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

// ConvertHooksForRollback rewrites the per-user Codex handlers this release
// registers as the direct system cmd.exe start of the launcher (GAP-1908)
// into the encoded PowerShell bridge releases 1.0.1 to 1.0.4 write and own,
// carrying their Codex trust over. 1.0.4 read the direct form as foreign, so
// after a rollback its setup added a second handler per event and doctor
// failed (GAP-2553). Rolling forward again runs Setup, which writes the
// direct form. Edited and foreign handlers stay as they are; a copy of the
// file goes to <data dir>/backups first.
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
// rewrote back in the direct form when a rollback aborts while this release
// still owns the installation. It rewrites only the exact bridge this
// release renders for its launcher and runs no Setup.
func (c *CodexConnector) RestoreHooksAfterRollback(opts SetupOpts) (int, error) {
	return convertCodexConfigHookForms(opts, false, nil)
}
