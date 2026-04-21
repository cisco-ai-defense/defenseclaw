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

package plugins

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Registry manages plugin scanners discovered from the filesystem.
type Registry struct {
	scanners []Scanner
}

func NewRegistry() *Registry {
	return &Registry{}
}

// Register adds a scanner to the registry.
func (r *Registry) Register(s Scanner) {
	r.scanners = append(r.scanners, s)
}

// Discover searches a directory for plugin manifests (plugin.yaml files).
// Each discovered plugin is validated but not loaded — the scanner interface
// must be implemented by the plugin binary and registered via Register().
func (r *Registry) Discover(dir string) ([]string, error) {
	if dir == "" {
		return nil, fmt.Errorf("plugins: discover requires a non-empty directory path")
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("plugins: discover %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("plugins: %s is not a directory", dir)
	}

	var found []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("plugins: read dir %s: %w", dir, err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		manifest := filepath.Join(dir, e.Name(), "plugin.yaml")
		if _, err := os.Stat(manifest); err == nil {
			found = append(found, e.Name())
		}
	}
	return found, nil
}

// Get returns the scanner with the given name, or nil if not found.
func (r *Registry) Get(name string) Scanner {
	for _, s := range r.scanners {
		if strings.EqualFold(s.Name(), name) {
			return s
		}
	}
	return nil
}

func (r *Registry) Scanners() []Scanner {
	return r.scanners
}
