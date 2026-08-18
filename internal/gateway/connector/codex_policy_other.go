// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
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
