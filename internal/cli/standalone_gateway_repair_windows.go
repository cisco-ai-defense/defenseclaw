// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// validateRepairRollbackPolicyInputs checks the paths whose ACLs Repair does
// not restamp. Set-DefenseClawManagedAcls repairs the installed config and
// runtime root, and recursively repairs the installed bundle store. A
// configured policy or rule pack elsewhere must already be trusted and
// service-readable, or a rollback would stop a gateway that cannot restart.
func validateRepairRollbackPolicyInputs(cfg *config.Config, configPath string) error {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return nil
	}
	serviceAccount := strings.TrimSpace(os.Getenv(managed.WindowsServiceAccountEnv))
	seen := map[string]bool{}
	check := func(label, dir string) error {
		dir = strings.TrimSpace(dir)
		if dir == "" || seen[strings.ToLower(filepath.Clean(dir))] {
			return nil
		}
		seen[strings.ToLower(filepath.Clean(dir))] = true
		if _, err := os.Lstat(dir); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return fmt.Errorf("inspect %s %s before Repair: %w", label, dir, err)
		}
		restamped, err := repairRestampsBundlePath(configPath, dir)
		if err != nil {
			return fmt.Errorf("inspect %s %s before Repair: %w", label, dir, err)
		}
		if restamped {
			return nil
		}
		if err := managed.ValidateTrustedServiceRuntimeTree(dir, label, serviceAccount); err != nil {
			return fmt.Errorf("%s %s is outside Repair's ACL scope and is not administrator-controlled: %w", label, dir, err)
		}
		if err := standaloneServiceCanReadTree(dir, label, serviceAccount); err != nil {
			return fmt.Errorf("%s %s is outside Repair's ACL scope: %w", label, dir, err)
		}
		return nil
	}
	if err := check("policy_dir", cfg.PolicyDir); err != nil {
		return err
	}
	dirs := cfg.ReferencedRulePackDirs()
	for _, label := range config.RulePackCheckOrder(dirs) {
		if err := check(label, dirs[label]); err != nil {
			return err
		}
	}
	return nil
}

// repairRestampsBundlePath recognizes only the bundle store under the
// installed config directory. The PowerShell ACL pass walks that whole tree.
// A reparse point cannot be adopted by that pass, so refuse it before the
// lifecycle stops a running gateway.
func repairRestampsBundlePath(configPath, path string) (bool, error) {
	bundleRoot, err := filepath.Abs(filepath.Join(filepath.Dir(configPath), "bundles"))
	if err != nil {
		return false, err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(bundleRoot, path)
	if err != nil || rel == ".." || filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false, nil
	}
	if err := winpath.RejectReparseChain(path); err != nil {
		return false, err
	}
	return true, nil
}

// A missing JSONL file immediately under the runtime root inherits that
// root's ACL after Repair restamps it. An existing file or a nested folder is
// outside this narrow exception; Repair does not restamp their ACLs.
func repairRollbackCanCreateJSONLInRestampedRuntime(path, dataDir string) bool {
	path, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	dataDir, err = filepath.Abs(dataDir)
	if err != nil || !strings.EqualFold(filepath.Dir(path), dataDir) {
		return false
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return false
	}
	info, err := os.Lstat(dataDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	return winpath.RejectReparseChain(dataDir) == nil
}

func resolveRepairRollbackCredential(name, secretsDir string) (string, bool) {
	value, err := managed.ReadServiceCredentialForACLRepair(name, secretsDir)
	return string(value), err == nil
}
