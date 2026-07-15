// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
)

// patchCodexManagedHooks merges only DefenseClaw's hook matrix into Codex's
// documented user-owned managed layer. The layer is trusted by Codex itself;
// trust is therefore established by provenance rather than by manufacturing
// an undocumented hooks.state hash. The managed-file backup and atomic
// transform primitives provide the same CAS, crash-safety, and drift-aware
// teardown behavior used for config.toml.
func (c *CodexConnector) patchCodexManagedHooks(opts SetupOpts, hookScript string) error {
	path := codexManagedConfigPath()
	hooksDir := filepath.Join(opts.DataDir, "hooks")
	hookScript = filepath.ToSlash(hookScript)
	if err := ensureCodexConfigDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("create Codex managed config directory: %w", err)
	}

	var transformed []byte
	render := func(raw []byte) error {
		cfg := map[string]interface{}{}
		if len(raw) > 0 {
			if err := toml.Unmarshal(raw, &cfg); err != nil {
				return fmt.Errorf("parse Codex managed config: %w", err)
			}
		}
		if rawFeatures, present := cfg["features"]; present {
			features, ok := rawFeatures.(map[string]interface{})
			if !ok {
				return fmt.Errorf("Codex managed features have unsupported type %T", rawFeatures)
			}
			for _, key := range []string{"hooks", "codex_hooks"} {
				if enabled, explicitlySet := features[key].(bool); explicitlySet && !enabled {
					return fmt.Errorf("Codex hooks are disabled by managed_config.toml features.%s", key)
				}
			}
		}
		hooks, exists := cfg["hooks"].(map[string]interface{})
		if _, present := cfg["hooks"]; present && !exists {
			return fmt.Errorf("Codex managed hooks have unsupported type %T; refusing to replace them", cfg["hooks"])
		}
		if !exists {
			hooks = map[string]interface{}{}
		}
		if err := mergeOwnedCodexHooks(hooks, path, hookScript, hooksDir, false); err != nil {
			return err
		}
		cfg["hooks"] = hooks

		out, err := toml.Marshal(cfg)
		if err != nil {
			return fmt.Errorf("marshal Codex managed config: %w", err)
		}
		rendered := map[string]interface{}{}
		if err := toml.Unmarshal(out, &rendered); err != nil {
			return fmt.Errorf("verify rendered Codex managed config: %w", err)
		}
		renderedHooks, ok := rendered["hooks"].(map[string]interface{})
		if !ok {
			return fmt.Errorf("verify rendered Codex managed config: hooks has unsupported type %T", rendered["hooks"])
		}
		if err := verifyManagedCodexHookMatrix(renderedHooks, path, hooksDir); err != nil {
			return fmt.Errorf("verify rendered managed DefenseClaw hooks: %w", err)
		}
		transformed = out
		return nil
	}

	if err := withFileLock(path, func() error {
		if err := captureManagedFileBackup(opts.DataDir, c.Name(), codexManagedConfigLogicalName, path); err != nil {
			return fmt.Errorf("capture Codex managed config backup: %w", err)
		}
		backup, err := loadManagedFileBackupForTransform(
			opts.DataDir,
			c.Name(),
			codexManagedConfigLogicalName,
			path,
		)
		if err != nil {
			return fmt.Errorf("load Codex managed config backup: %w", err)
		}
		exactBackupSafe := true
		if err := atomicTransformFileWithStateDir(path, opts.DataDir, 0o600, func(raw []byte, exists bool) (atomicTransformResult, error) {
			if !managedFileBackupMatchesSnapshot(backup, raw, exists) {
				exactBackupSafe = false
			}
			if err := render(raw); err != nil {
				return atomicTransformResult{}, err
			}
			if exactBackupSafe {
				if err := updateManagedFileBackupPostHashValue(
					opts.DataDir,
					c.Name(),
					codexManagedConfigLogicalName,
					path,
					managedFileSnapshotHash(transformed, true),
				); err != nil {
					return atomicTransformResult{}, fmt.Errorf("publish intended Codex managed config hash: %w", err)
				}
			}
			return atomicTransformResult{Data: append([]byte(nil), transformed...)}, nil
		}); err != nil {
			if !exactBackupSafe {
				discardManagedFileBackup(opts.DataDir, c.Name(), codexManagedConfigLogicalName)
			}
			return err
		}

		persisted, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read persisted Codex managed config: %w", err)
		}
		persistedConfig := map[string]interface{}{}
		if err := toml.Unmarshal(persisted, &persistedConfig); err != nil {
			return fmt.Errorf("parse persisted Codex managed config: %w", err)
		}
		persistedHooks, ok := persistedConfig["hooks"].(map[string]interface{})
		if !ok {
			return fmt.Errorf("verify persisted Codex managed config: hooks has unsupported type %T", persistedConfig["hooks"])
		}
		if err := verifyManagedCodexHookMatrix(persistedHooks, path, hooksDir); err != nil {
			return fmt.Errorf("verify persisted managed DefenseClaw hooks: %w", err)
		}
		if !bytes.Equal(persisted, transformed) {
			exactBackupSafe = false
		}
		if !exactBackupSafe {
			discardManagedFileBackup(opts.DataDir, c.Name(), codexManagedConfigLogicalName)
			return nil
		}
		return updateManagedFileBackupPostHashValue(
			opts.DataDir,
			c.Name(),
			codexManagedConfigLogicalName,
			path,
			managedFileSnapshotHash(transformed, true),
		)
	}); err != nil {
		return fmt.Errorf("write Codex managed config: %w", err)
	}
	return nil
}

func (c *CodexConnector) restoreCodexManagedHooks(opts SetupOpts) error {
	path := codexManagedConfigPath()
	if err := ensureCodexConfigDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("prepare Codex managed config directory for restore: %w", err)
	}
	if restored, err := restoreManagedFileBackupIfUnchanged(
		opts.DataDir,
		c.Name(),
		codexManagedConfigLogicalName,
		path,
	); err != nil {
		// A target that drifted or whose exact backup cannot be restored still
		// gets surgical cleanup below. A malformed/tampered backup must not block
		// removal of an owned active hook.
		fmt.Fprintf(os.Stderr, "[codex] exact managed hook restore skipped: %v\n", err)
	} else if restored {
		return nil
	}
	backup, err := loadManagedFileBackupForTransform(
		opts.DataDir,
		c.Name(),
		codexManagedConfigLogicalName,
		path,
	)
	if err != nil {
		return fmt.Errorf("load Codex managed hook backup: %w", err)
	}

	if err := withFileLock(path, func() error {
		return atomicTransformFileWithStateDir(path, opts.DataDir, 0o600, func(raw []byte, exists bool) (atomicTransformResult, error) {
			if exact, ok := managedFileBackupTransform(backup, raw, exists); ok {
				return exact, nil
			}
			if !exists {
				return atomicTransformResult{Remove: true}, nil
			}
			cfg := map[string]interface{}{}
			if err := toml.Unmarshal(raw, &cfg); err != nil {
				return atomicTransformResult{}, fmt.Errorf("parse Codex managed config: %w", err)
			}
			rawHooks, present := cfg["hooks"]
			if !present {
				return atomicTransformResult{Data: append([]byte(nil), raw...)}, nil
			}
			hooks, ok := rawHooks.(map[string]interface{})
			if !ok {
				return atomicTransformResult{}, fmt.Errorf("restore Codex managed hooks: unsupported type %T", rawHooks)
			}
			changed, err := removeOwnedCodexHooksAndState(hooks, path, filepath.Join(opts.DataDir, "hooks"))
			if err != nil {
				return atomicTransformResult{}, fmt.Errorf("restore Codex managed hooks: %w", err)
			}
			if !changed {
				return atomicTransformResult{Data: append([]byte(nil), raw...)}, nil
			}
			if len(hooks) == 0 {
				delete(cfg, "hooks")
			} else {
				cfg["hooks"] = hooks
			}
			if len(cfg) == 0 {
				return atomicTransformResult{Remove: true}, nil
			}
			out, err := toml.Marshal(cfg)
			if err != nil {
				return atomicTransformResult{}, fmt.Errorf("marshal restored Codex managed config: %w", err)
			}
			return atomicTransformResult{Data: out}, nil
		})
	}); err != nil {
		return fmt.Errorf("write restored Codex managed config: %w", err)
	}
	discardManagedFileBackup(opts.DataDir, c.Name(), codexManagedConfigLogicalName)
	return nil
}
