//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func installedPythonInterpreter() (string, error) {
	var lastErr error
	for _, candidate := range ManagedMacOSPythonCandidates() {
		if err := validateManagedPythonPath(candidate, true, true); err != nil {
			lastErr = err
			continue
		}
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			lastErr = err
			continue
		}
		framework := filepath.Dir(filepath.Dir(candidate))
		rel, err := filepath.Rel(framework, resolved)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			lastErr = fmt.Errorf("managed Fleet Python escapes trusted framework: %s", resolved)
			continue
		}
		if err := validateManagedPythonPath(resolved, false, true); err != nil {
			lastErr = err
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		probe := exec.CommandContext(ctx, resolved, "-I", "-c",
			"import sys, yaml; assert sys.version_info >= (3, 10); print(yaml.__version__); print(yaml.__file__)")
		output, err := probe.CombinedOutput()
		cancel()
		if err != nil {
			lastErr = fmt.Errorf("managed Fleet Python %s cannot import PyYAML in isolated mode: %v: %s", resolved, err, strings.TrimSpace(string(output)))
			continue
		}
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		if len(lines) != 2 || lines[0] != "6.0.3" {
			lastErr = fmt.Errorf("managed Fleet Python %s requires PyYAML 6.0.3", resolved)
			continue
		}
		yamlPath := strings.TrimSpace(lines[1])
		rel, err = filepath.Rel(framework, yamlPath)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) ||
			filepath.Ext(yamlPath) != ".py" {
			lastErr = fmt.Errorf("managed Fleet PyYAML is outside protected Python framework: %s", yamlPath)
			continue
		}
		if err := validateManagedPythonPath(yamlPath, false, false); err != nil {
			lastErr = err
			continue
		}
		if err := validateManagedPyYAMLTree(filepath.Dir(yamlPath)); err != nil {
			lastErr = err
			continue
		}
		return resolved, nil
	}
	return "", fmt.Errorf("managed Fleet requires protected Python.org Python 3.10+ with PyYAML: %w", lastErr)
}

func validateManagedPythonPath(candidate string, allowFinalSymlink, executable bool) error {
	for path := candidate; ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("stat managed Fleet Python path %s: %w", path, err)
		}
		finalSymlink := path == candidate && allowFinalSymlink && info.Mode()&os.ModeSymlink != 0
		if (!finalSymlink && info.Mode()&os.ModeSymlink != 0) ||
			(!finalSymlink && writableByOthers(info)) {
			return fmt.Errorf("managed Fleet Python path is not protected: %s", path)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return fmt.Errorf("managed Fleet Python path is not root-owned: %s", path)
		}
		if path == candidate && !finalSymlink &&
			(!info.Mode().IsRegular() || (executable && info.Mode().Perm()&0o111 == 0)) {
			return fmt.Errorf("managed Fleet Python is not a regular executable: %s", path)
		}
		if path != candidate && !info.IsDir() {
			return fmt.Errorf("managed Fleet Python parent is not a directory: %s", path)
		}
		if path == string(filepath.Separator) {
			break
		}
	}
	return nil
}

func validateManagedPyYAMLTree(dir string) error {
	const maxFiles = 512
	count := 0
	return filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		count++
		if count > maxFiles {
			return fmt.Errorf("managed PyYAML package exceeds %d files", maxFiles)
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || writableByOthers(info) ||
			(!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("managed PyYAML package path is not protected: %s", path)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return fmt.Errorf("managed PyYAML package path is not root-owned: %s", path)
		}
		return nil
	})
}
