// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func writeManagedTargetRuntimeFilePlatform(path string, data []byte, replace bool) error {
	if len(data) > atomicTransformMaxConfigBytes {
		return fmt.Errorf(
			"managed target runtime file exceeds %d-byte limit",
			atomicTransformMaxConfigBytes,
		)
	}
	if replace {
		return atomicWriteFile(path, data, 0o600)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create managed target runtime directory: %w", err)
	}
	stage, err := os.CreateTemp(dir, ".managed-runtime-stage-*")
	if err != nil {
		return fmt.Errorf("create managed target runtime stage: %w", err)
	}
	stagePath := stage.Name()
	keep := false
	defer func() {
		_ = stage.Close()
		if !keep {
			_ = os.Remove(stagePath)
		}
	}()
	if err := stage.Chmod(0o600); err != nil {
		return fmt.Errorf("protect managed target runtime stage: %w", err)
	}
	if _, err := stage.Write(data); err != nil {
		return fmt.Errorf("write managed target runtime stage: %w", err)
	}
	if err := stage.Sync(); err != nil {
		return fmt.Errorf("sync managed target runtime stage: %w", err)
	}
	if err := stage.Close(); err != nil {
		return fmt.Errorf("close managed target runtime stage: %w", err)
	}
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open managed target runtime directory: %w", err)
	}
	if err := moveAtomicTransformPathNoReplaceAt(
		int(directory.Fd()),
		filepath.Base(stagePath),
		filepath.Base(path),
	); err != nil {
		_ = directory.Close()
		if errors.Is(err, errAtomicTransformConflict) {
			return fmt.Errorf("managed target runtime destination exists: %w", os.ErrExist)
		}
		return fmt.Errorf("publish managed target runtime file without replacement: %w", err)
	}
	keep = true
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return fmt.Errorf("sync managed target runtime directory: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close managed target runtime directory: %w", closeErr)
	}
	return nil
}
