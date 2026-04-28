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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"plugin"
	"runtime"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"
)

// PluginAuditEmitter is the callback contract the gateway wires up so
// the plugin loader can emit audit-pipeline events on rejection without
// the connector package importing gatewaylog (which would create a
// dependency cycle once handlers move into this package per Phase C1).
//
// Implementations forward to gatewaylog.Event{EventType: EventError,
// Subsystem: SubsystemPlugin, Code: ...} via the same writer choke
// point as emitGatewayError. When unset, the loader falls back to
// log.Printf so a built-in run with no audit pipeline still surfaces
// the rejection. Plan B3 / S0.1 invariant: every refusal MUST land in
// the audit log when the pipeline is wired.
type PluginAuditEmitter func(ctx context.Context, code, msg, soPath string, cause error)

var pluginAuditEmitter PluginAuditEmitter

// SetPluginAuditEmitter wires the audit-pipeline emitter callback. The
// gateway calls this exactly once at boot, before any plugin discovery
// runs. Calling with nil restores the log-only fallback (used by
// tests that want to inspect rejections without setting up the full
// audit machinery).
func SetPluginAuditEmitter(e PluginAuditEmitter) {
	pluginAuditEmitter = e
}

// pluginGetUID is overridable for tests. Returns the effective UID of
// the running process. The default delegates to os.Getuid().
var pluginGetUID = os.Getuid

func emitPluginRejection(code, msg, soPath string, cause error) {
	if pluginAuditEmitter != nil {
		pluginAuditEmitter(context.Background(), code, msg, soPath, cause)
		return
	}
	if cause != nil {
		log.Printf("[SECURITY] %s: %s (so=%s): %v", code, msg, soPath, cause)
	} else {
		log.Printf("[SECURITY] %s: %s (so=%s)", code, msg, soPath)
	}
}

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
			emitPluginRejection("PLUGIN_MANIFEST_INVALID",
				fmt.Sprintf("plugin %s: plugin.yaml missing required sha256 field", entry.Name()),
				manifestPath, nil)
			continue
		}

		soPath := filepath.Join(pluginDir, manifest.Entry)

		if err := validatePluginPath(soPath, realDir); err != nil {
			emitPluginRejection("PLUGIN_PATH_REJECTED",
				fmt.Sprintf("plugin %s: path validation failed", manifest.Name), soPath, err)
			continue
		}

		if err := validatePluginPermissions(soPath); err != nil {
			emitPluginRejection("PLUGIN_PERMISSION_DENIED",
				fmt.Sprintf("plugin %s: permission check failed", manifest.Name), soPath, err)
			continue
		}

		if err := validatePluginOwner(soPath); err != nil {
			emitPluginRejection("PLUGIN_OWNER_MISMATCH",
				fmt.Sprintf("plugin %s: owner check failed", manifest.Name), soPath, err)
			continue
		}

		if err := validatePluginHash(soPath, manifest.SHA256); err != nil {
			emitPluginRejection("PLUGIN_HASH_MISMATCH",
				fmt.Sprintf("plugin %s: hash verification failed", manifest.Name), soPath, err)
			continue
		}

		c, err := loadPluginSO(soPath)
		if err != nil {
			emitPluginRejection("PLUGIN_LOAD_FAILED",
				fmt.Sprintf("plugin %s: load failed", manifest.Name), soPath, err)
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

// validatePluginOwner refuses .so files that are not owned by the
// running process's UID. The previous permission gate covered
// "world-writable" but not "world-readable + owned-by-attacker": a
// hostile user on a shared host could drop a plugin in a directory
// the gateway daemon reads, set mode 0o755, and have it loaded with
// the daemon's privileges. This gate closes that path.
//
// Plan B3 / S0.1: skipped on Windows (file ownership semantics differ
// and the code path uses syscall.Stat_t which is unix-only).
func validatePluginOwner(soPath string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Lstat(soPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", soPath, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("could not extract owner UID from FileInfo (non-unix FS?)")
	}
	want := uint32(pluginGetUID())
	if stat.Uid != want {
		return fmt.Errorf("%s owner uid=%d does not match running process uid=%d", soPath, stat.Uid, want)
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
