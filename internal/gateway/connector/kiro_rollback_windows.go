// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// ConvertHooksForRollback rewrites the per-user Kiro hook commands this
// release writes (the bridge that answers a launcher that cannot start,
// rel-1-0-6 GAP-0676) into the form releases before 1.0.9 write and own, so
// the older release's setup and teardown find them. Rolling forward again
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
	pairs := kiroWindowsHookFormPairs(launchers)
	paths := append(append(c.hookCleanupPaths(opts), c.agentConfigPaths(opts)...), c.agentCleanupPaths(opts)...)
	total := 0
	for _, path := range uniqueNonEmptyStrings(paths) {
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return total, fmt.Errorf("read Kiro hooks %s: %w", path, err)
		}
		if _, changed := convertKiroHookFileForms(data, pairs, toEarlier); changed == 0 {
			continue
		}
		converted := 0
		var hold func([]byte) error
		var committed []byte
		err = withFileLockMode(path, false, func() error {
			return atomicTransformFileWithStateDir(path, opts.DataDir, 0o600,
				func(current []byte, exists bool) (atomicTransformResult, error) {
					if !exists {
						return atomicTransformResult{Remove: true}, nil
					}
					out, changed := convertKiroHookFileForms(current, pairs, toEarlier)
					if changed == 0 {
						return atomicTransformResult{Data: current}, nil
					}
					if keepCopy != nil {
						sum := sha256.Sum256([]byte(strings.ToLower(path)))
						if err := keepCopy(opts.DataDir, "kiro-"+hex.EncodeToString(sum[:6])+".before-rollback.json", current); err != nil {
							return atomicTransformResult{}, fmt.Errorf("keep a copy of the Kiro hooks: %w", err)
						}
					}
					converted = changed
					hold, committed = holdManagedExactRestore(opts.DataDir, c.Name(), path, current), out
					return atomicTransformResult{Data: out}, nil
				})
		})
		if err == nil && hold != nil {
			err = hold(committed)
		}
		if err != nil {
			return total, fmt.Errorf("rewrite Kiro hooks in %s: %w", path, err)
		}
		total += converted
	}
	return total, nil
}
