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
	"sort"
	"sync"
)

// ConnectorInfo is the metadata returned by Registry.Available() for the
// setup menu.
type ConnectorInfo struct {
	Name               string
	Description        string
	Source             string // "built-in" or "plugin"
	ToolInspectionMode ToolInspectionMode
	SubprocessPolicy   SubprocessPolicy
}

// Registry holds all available connectors (built-in + discovered plugins).
type Registry struct {
	mu       sync.RWMutex
	builtins map[string]Connector
	plugins  map[string]Connector
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		builtins: make(map[string]Connector),
		plugins:  make(map[string]Connector),
	}
}

// RegisterBuiltin adds a built-in connector.
func (r *Registry) RegisterBuiltin(c Connector) {
	r.mu.Lock()
	r.builtins[c.Name()] = c
	r.mu.Unlock()
}

// RegisterPlugin adds an externally-loaded connector.
func (r *Registry) RegisterPlugin(c Connector) {
	r.mu.Lock()
	r.plugins[c.Name()] = c
	r.mu.Unlock()
}

// Get returns a connector by name, searching builtins first then plugins.
func (r *Registry) Get(name string) (Connector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if c, ok := r.builtins[name]; ok {
		return c, true
	}
	if c, ok := r.plugins[name]; ok {
		return c, true
	}
	return nil, false
}

// GetAll resolves a list of connector names to concrete instances.
// Returns an error if any name is not found.
func (r *Registry) GetAll(names []string) ([]Connector, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Connector, 0, len(names))
	for _, name := range names {
		if c, ok := r.builtins[name]; ok {
			out = append(out, c)
			continue
		}
		if c, ok := r.plugins[name]; ok {
			out = append(out, c)
			continue
		}
		return nil, fmt.Errorf("unknown connector %q — run 'defenseclaw setup' first", name)
	}
	return out, nil
}

// Available returns metadata for all registered connectors, sorted by name.
// Built-in connectors appear before plugins.
func (r *Registry) Available() []ConnectorInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]ConnectorInfo, 0, len(r.builtins)+len(r.plugins))
	for _, c := range r.builtins {
		out = append(out, ConnectorInfo{
			Name:               c.Name(),
			Description:        c.Description(),
			Source:             "built-in",
			ToolInspectionMode: c.ToolInspectionMode(),
			SubprocessPolicy:   c.SubprocessPolicy(),
		})
	}
	for _, c := range r.plugins {
		out = append(out, ConnectorInfo{
			Name:               c.Name(),
			Description:        c.Description(),
			Source:             "plugin",
			ToolInspectionMode: c.ToolInspectionMode(),
			SubprocessPolicy:   c.SubprocessPolicy(),
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source == "built-in"
		}
		return out[i].Name < out[j].Name
	})

	return out
}

// Len returns the total number of registered connectors.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.builtins) + len(r.plugins)
}

// Names returns a sorted list of all registered connector names.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.builtins)+len(r.plugins))
	for n := range r.builtins {
		names = append(names, n)
	}
	for n := range r.plugins {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// NewDefaultRegistry creates a registry pre-loaded with all built-in connectors.
func NewDefaultRegistry() *Registry {
	r := NewRegistry()
	r.RegisterBuiltin(NewOpenClawConnector())
	r.RegisterBuiltin(NewZeptoClawConnector())
	r.RegisterBuiltin(NewClaudeCodeConnector())
	r.RegisterBuiltin(NewCodexConnector())
	return r
}

// DiscoverPlugins scans a directory for Go plugin .so files and loads them.
func (r *Registry) DiscoverPlugins(dir string) error {
	connectors, err := LoadPlugins(dir)
	if err != nil {
		return fmt.Errorf("discover plugins in %s: %w", dir, err)
	}
	for _, c := range connectors {
		r.RegisterPlugin(c)
	}
	return nil
}
