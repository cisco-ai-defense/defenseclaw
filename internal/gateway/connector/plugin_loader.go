// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"plugin"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// pluginManifest is the structure of plugin.yaml in each connector plugin dir.
type pluginManifest struct {
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	Description string `yaml:"description"`
	Entry       string `yaml:"entry"`
	SHA256      string `yaml:"sha256"`
}

// LoadPlugins scans a directory for connector plugin subdirectories, each
// containing a plugin.yaml manifest and a compiled Go .so file. Returns
// all successfully loaded connectors.
//
// Security invariants enforced before plugin.Open (which runs init()):
//   - manifest.SHA256 must be present and match the .so file on disk
//   - the .so real path must resolve inside the plugin directory (no symlink escape)
//   - the .so must not be group-writable or world-writable
func LoadPlugins(dir string) ([]Connector, error) {
	if dir == "" {
		return nil, nil
	}

	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("resolve plugin dir %s: %w", dir, err)
	}

	entries, err := os.ReadDir(realDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read plugin dir %s: %w", realDir, err)
	}

	var connectors []Connector
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pluginDir := filepath.Join(realDir, entry.Name())
		manifestPath := filepath.Join(pluginDir, "plugin.yaml")

		manifestData, err := os.ReadFile(manifestPath)
		if err != nil {
			log.Printf("[connector] skipping %s: no plugin.yaml: %v", entry.Name(), err)
			continue
		}

		var manifest pluginManifest
		if err := yaml.Unmarshal(manifestData, &manifest); err != nil {
			log.Printf("[connector] skipping %s: bad plugin.yaml: %v", entry.Name(), err)
			continue
		}

		if strings.TrimSpace(manifest.SHA256) == "" {
			log.Printf("[SECURITY] refusing plugin %s: plugin.yaml missing required sha256 field", entry.Name())
			continue
		}

		soPath := filepath.Join(pluginDir, manifest.Entry)

		if err := validatePluginPath(soPath, realDir); err != nil {
			log.Printf("[SECURITY] refusing plugin %s: path validation failed: %v", manifest.Name, err)
			continue
		}

		if err := validatePluginPermissions(soPath); err != nil {
			log.Printf("[SECURITY] refusing plugin %s: permission check failed: %v", manifest.Name, err)
			continue
		}

		if err := validatePluginHash(soPath, manifest.SHA256); err != nil {
			log.Printf("[SECURITY] refusing plugin %s: hash verification failed: %v", manifest.Name, err)
			continue
		}

		c, err := loadPluginSO(soPath)
		if err != nil {
			log.Printf("[connector] skipping %s: load failed: %v", manifest.Name, err)
			continue
		}

		connectors = append(connectors, c)
		log.Printf("[SECURITY] loaded plugin: %s v%s (sha256=%s)", manifest.Name, manifest.Version, manifest.SHA256[:16]+"...")
	}

	return connectors, nil
}

// validatePluginPath ensures the .so file resolves to a real path inside the
// allowed root directory, blocking symlink escapes and path traversal.
func validatePluginPath(soPath, allowedRoot string) error {
	realPath, err := filepath.EvalSymlinks(soPath)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", soPath, err)
	}
	realRoot, err := filepath.EvalSymlinks(allowedRoot)
	if err != nil {
		return fmt.Errorf("resolve root %s: %w", allowedRoot, err)
	}
	if !strings.HasPrefix(realPath, realRoot+string(filepath.Separator)) {
		return fmt.Errorf("resolved path %s escapes allowed root %s", realPath, realRoot)
	}
	return nil
}

// validatePluginPermissions refuses .so files that are group-writable or
// world-writable. On Windows this check is skipped (file modes are not
// meaningful).
func validatePluginPermissions(soPath string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Lstat(soPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", soPath, err)
	}
	mode := info.Mode().Perm()
	if mode&0o022 != 0 {
		return fmt.Errorf("%s is group-writable or world-writable (mode %04o)", soPath, mode)
	}
	return nil
}

// validatePluginHash computes the SHA-256 digest of the file and compares it
// against the expected hex string from the manifest.
func validatePluginHash(soPath, expectedHex string) error {
	f, err := os.Open(soPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", soPath, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("hash %s: %w", soPath, err)
	}

	actual := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(actual, strings.TrimSpace(expectedHex)) {
		return fmt.Errorf("sha256 mismatch: manifest=%s actual=%s", expectedHex, actual)
	}
	return nil
}

// loadPluginSO opens a compiled Go shared library and looks up the
// NewConnector symbol.
func loadPluginSO(path string) (Connector, error) {
	p, err := plugin.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open plugin %s: %w", path, err)
	}

	sym, err := p.Lookup("NewConnector")
	if err != nil {
		return nil, fmt.Errorf("lookup NewConnector in %s: %w", path, err)
	}

	newFn, ok := sym.(func() (Connector, error))
	if !ok {
		return nil, fmt.Errorf("NewConnector in %s has wrong signature (want func() (Connector, error))", path)
	}

	return newFn()
}
