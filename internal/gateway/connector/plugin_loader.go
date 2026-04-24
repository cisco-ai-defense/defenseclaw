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
	"fmt"
	"log"
	"os"
	"path/filepath"
	"plugin"

	"gopkg.in/yaml.v3"
)

// pluginManifest is the structure of plugin.yaml in each connector plugin dir.
type pluginManifest struct {
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	Description string `yaml:"description"`
	Entry       string `yaml:"entry"`
}

// LoadPlugins scans a directory for connector plugin subdirectories, each
// containing a plugin.yaml manifest and a compiled Go .so file. Returns
// all successfully loaded connectors.
func LoadPlugins(dir string) ([]Connector, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read plugin dir %s: %w", dir, err)
	}

	var connectors []Connector
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pluginDir := filepath.Join(dir, entry.Name())
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

		soPath := filepath.Join(pluginDir, manifest.Entry)
		c, err := loadPluginSO(soPath)
		if err != nil {
			log.Printf("[connector] skipping %s: load failed: %v", manifest.Name, err)
			continue
		}

		connectors = append(connectors, c)
		log.Printf("[connector] loaded plugin: %s v%s", manifest.Name, manifest.Version)
	}

	return connectors, nil
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
