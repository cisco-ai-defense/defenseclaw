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
		// The file itself is absent — the managed installer either
		// has not landed yet or intentionally omitted a policy pin.
		// Unlike Windows (%ProgramData%\OpenAI\Codex is always
		// pre-provisioned by the installer, so a missing parent is
		// a hard error), the unix installer does not create /etc/codex
		// eagerly, so a missing parent is the common case on a fresh
		// unix host and must not fail reconcile.
		//
		// When the parent DOES exist, validate its trust anyway so a
		// future attacker-controlled write into a world-writable
		// staging tree cannot land a look-alike file that would be
		// silently accepted on the next scan. When it doesn't exist,
		// there is no attack surface to guard against and we return
		// "no pin" without failure.
		parent := filepath.Dir(path)
		parentInfo, parentErr := os.Lstat(parent)
		if errors.Is(parentErr, os.ErrNotExist) {
			return nil, false, nil
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
