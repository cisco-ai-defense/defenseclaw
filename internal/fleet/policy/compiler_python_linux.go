//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const managedLinuxPythonPath = "/usr/bin/python3"

// installedPythonInterpreter admits the distribution's fixed Python, not a
// PATH-selected binary. The isolated probes and ownership checks also cover
// imported PyYAML, since policy compilation executes that package as gateway.
func installedPythonInterpreter() (string, error) {
	if err := validateLinuxOwnedPath(managedLinuxPythonPath, true, false); err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(managedLinuxPythonPath)
	if err != nil || !strings.HasPrefix(resolved, "/usr/bin/python3") {
		return "", fmt.Errorf("managed Fleet Python must resolve within /usr/bin/python3*: %v", err)
	}
	if err := validateLinuxOwnedPath(resolved, false, false); err != nil {
		return "", err
	}
	// Inspect interpreter import directories before importing PyYAML. -I
	// excludes user site packages and PYTHONPATH; -S omits site initialization.
	basePaths, err := linuxPythonProbe(resolved, "import json, sys; print(json.dumps(sys.path))", true)
	if err != nil {
		return "", err
	}
	if err := validateLinuxPythonSearchPath(basePaths); err != nil {
		return "", err
	}
	searchPaths, err := linuxPythonProbe(resolved, "import json, sys; print(json.dumps(sys.path))", false)
	if err != nil {
		return "", err
	}
	if err := validateLinuxPythonSearchPath(searchPaths); err != nil {
		return "", err
	}
	output, err := linuxPythonProbe(resolved,
		"import json, sys, yaml; assert sys.version_info >= (3, 6); assert yaml.safe_load('x: 1') == {'x': 1}; print(json.dumps({'path': yaml.__file__, 'version': yaml.__version__}))", false)
	if err != nil {
		return "", fmt.Errorf("managed Fleet Python requires an isolated PyYAML safe_load: %w", err)
	}
	var imported struct {
		Path    string `json:"path"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal([]byte(output), &imported); err != nil || imported.Path == "" || imported.Version == "" {
		return "", fmt.Errorf("managed Fleet Python returned an invalid PyYAML import path: %q", output)
	}
	if !filepath.IsAbs(imported.Path) || filepath.Ext(imported.Path) != ".py" {
		return "", fmt.Errorf("managed Fleet PyYAML import path is not an absolute Python module: %s", imported.Path)
	}
	if err := validateLinuxOwnedPath(imported.Path, false, true); err != nil {
		return "", err
	}
	if err := validateLinuxPythonPackage(filepath.Dir(imported.Path)); err != nil {
		return "", err
	}
	return resolved, nil
}

func linuxPythonProbe(python, code string, noSite bool) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	args := []string{"-I"}
	if noSite {
		args = append(args, "-S")
	}
	args = append(args, "-c", code)
	output, err := exec.CommandContext(ctx, python, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("managed Fleet Python probe failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func validateLinuxPythonSearchPath(output string) error {
	var paths []string
	if err := json.Unmarshal([]byte(output), &paths); err != nil {
		return fmt.Errorf("invalid managed Fleet Python search path: %w", err)
	}
	for _, path := range paths {
		if !filepath.IsAbs(path) {
			return fmt.Errorf("managed Fleet Python has a relative import directory: %q", path)
		}
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			// Python often lists a future pythonXY.zip. Its nearest existing
			// parent must still be protected against a later user-created file.
			path = filepath.Dir(path)
		} else if err != nil {
			return err
		}
		if err := validateLinuxOwnedPath(path, false, false); err != nil {
			return err
		}
	}
	return nil
}

func validateLinuxOwnedPath(path string, finalSymlink, regularFile bool) error {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("stat managed Fleet Python path %s: %w", current, err)
		}
		isFinalLink := current == path && finalSymlink && info.Mode()&os.ModeSymlink != 0
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || (!isFinalLink && (info.Mode()&os.ModeSymlink != 0 || writableByOthers(info))) {
			return fmt.Errorf("managed Fleet Python path is not root-owned and protected: %s", current)
		}
		if current == path && !isFinalLink && regularFile && !info.Mode().IsRegular() {
			return fmt.Errorf("managed Fleet Python path is not a regular file: %s", current)
		}
		if current == path && !isFinalLink && !regularFile && !info.IsDir() && info.Mode().Perm()&0o111 == 0 {
			return fmt.Errorf("managed Fleet Python is not executable: %s", current)
		}
		if current != path && !info.IsDir() {
			return fmt.Errorf("managed Fleet Python parent is not a directory: %s", current)
		}
		if current == "/" {
			return nil
		}
	}
}

func validateLinuxPythonPackage(dir string) error {
	const maxFiles = 512
	count := 0
	return filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		count++
		if count > maxFiles {
			return fmt.Errorf("managed Fleet PyYAML package exceeds %d files", maxFiles)
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || writableByOthers(info) ||
			(!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("managed Fleet PyYAML package is not protected: %s", path)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return fmt.Errorf("managed Fleet PyYAML package is not root-owned: %s", path)
		}
		return nil
	})
}
