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

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// ConvertHooksForRollback rewrites the per-user Devin guarded starts this
// release writes (rel-1-0-6 GAP-0676) into the direct start releases before
// 1.0.9 write and own, so the older release's setup and teardown find them.
// Rolling forward again runs Setup, which writes the current form. A copy of
// each file it changes goes to <data dir>/backups first. Only Devin has a
// conversion; the other hook-only connectors return 0.
func (c *hookOnlyConnector) ConvertHooksForRollback(opts SetupOpts) (int, error) {
	if c.name != "devin" {
		return 0, nil
	}
	return c.convertDevinConfigHookForms(opts, true, func(dataDir, name string, data []byte) error {
		dir, err := openClaudeCodeRollbackEvidence(dataDir, true)
		if err != nil {
			return err
		}
		defer dir.Close()
		return writeClaudeCodeRollbackEvidence(dir, name, data)
	})
}

// RestoreHooksAfterRollback puts the Devin commands ConvertHooksForRollback
// rewrote back in this release's guarded form when a rollback aborts. It
// rewrites only the direct start of a block event whose guard program is
// there, and runs no Setup.
func (c *hookOnlyConnector) RestoreHooksAfterRollback(opts SetupOpts) (int, error) {
	if c.name != "devin" {
		return 0, nil
	}
	return c.convertDevinConfigHookForms(opts, false, nil)
}

// convertDevinConfigHookForms applies convertDevinHookForms to every Devin
// hooks file setup or teardown handles, each under its lock, and keeps a
// copy of a file before a rollback conversion. Managed installs are left
// alone: they write the direct form, which no release changed.
func (c *hookOnlyConnector) convertDevinConfigHookForms(opts SetupOpts, toEarlier bool, keepCopy func(dataDir, name string, data []byte) error) (int, error) {
	if opts.ManagedEnterprise {
		return 0, nil
	}
	launchers := append([]string{strings.TrimSpace(opts.HookExecutable)}, nativeHookBinaryOwnershipCandidates()...)
	pairs := devinWindowsHookFormPairs(launchers, !toEarlier)
	if len(pairs) == 0 {
		return 0, nil
	}
	total := 0
	for _, path := range uniqueNonEmptyStrings(HookConfigPathsForConnector(c, opts)) {
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			continue
		}
		converted := 0
		err := withFileLockMode(path, false, func() error {
			data, err := safefile.ReadRegularFileBounded(path, devinConfigReadLimit)
			if os.IsNotExist(err) {
				return nil
			}
			if err != nil {
				return err
			}
			cfg, err := readDevinJSONObject(path)
			if err != nil {
				return err
			}
			converted = convertDevinHookForms(devinHooksObject(path, cfg), pairs, toEarlier)
			if converted == 0 {
				return nil
			}
			if keepCopy != nil {
				sum := sha256.Sum256([]byte(strings.ToLower(path)))
				if err := keepCopy(opts.DataDir, "devin-"+hex.EncodeToString(sum[:6])+".before-rollback.json", data); err != nil {
					return fmt.Errorf("keep a copy of the Devin hooks: %w", err)
				}
			}
			return writeDevinHooksFile(path, cfg)
		})
		if err != nil {
			return total, fmt.Errorf("rewrite Devin hooks in %s: %w", path, err)
		}
		total += converted
	}
	return total, nil
}
