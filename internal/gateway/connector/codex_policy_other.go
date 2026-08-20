// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func codexSystemRequirementsPath() (string, error) {
	return "/etc/codex/requirements.toml", nil
}

func readCodexSystemRequirements(path string, managedEnterprise bool) ([]byte, bool, error) {
	if !managedEnterprise {
		return readLegacyCodexSystemRequirements(path)
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		// The file itself is absent — the managed installer either has
		// not landed yet or intentionally omitted a policy pin. Trust
		// the parent directory anyway so a future attacker-controlled
		// write cannot create a look-alike file in a world-writable
		// staging tree that would be silently accepted on the next
		// scan (mirrors the parent-only trust branch in
		// codex_policy_windows.go).
		parent := filepath.Dir(path)
		parentInfo, parentErr := os.Lstat(parent)
		if errors.Is(parentErr, os.ErrNotExist) {
			return nil, false, fmt.Errorf(
				"managed Codex requirements parent %s is missing; pre-provision it with root-only owner and mode",
				parent,
			)
		}
		if parentErr != nil {
			return nil, false, fmt.Errorf("inspect managed Codex requirements parent %s: %w", parent, parentErr)
		}
		if !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
			return nil, false, fmt.Errorf("managed Codex requirements parent is not a regular directory: %s", parent)
		}
		if trustErr := managed.ValidateTrustedRuntimeDir(parent, "managed Codex requirements parent"); trustErr != nil {
			return nil, false, fmt.Errorf("managed Codex requirements parent is untrusted: %w", trustErr)
		}
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, false, fmt.Errorf("managed Codex requirements source is not a regular file")
	}
	if info.Size() > codexPolicyMessageLimit {
		return nil, false, fmt.Errorf("exceeds %d bytes", codexPolicyMessageLimit)
	}
	if err := managed.ValidateTrustedFilePath(path, "managed Codex requirements source"); err != nil {
		return nil, false, fmt.Errorf("managed Codex requirements source is untrusted: %w", err)
	}
	return readBoundedCodexSystemRequirements(path)
}

func startCodexAppServerTree(cmd *exec.Cmd) (func(), error) {
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			_ = cmd.Wait()
		})
	}, nil
}
