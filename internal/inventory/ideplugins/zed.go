// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package ideplugins

import (
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

const zedMaxExtensions = 1024

// scanZed lists Zed's installed extensions. Zed has no disabled state: an
// installed extension is always enabled.
func (s *scanner) scanZed() {
	var dir string
	switch s.goos {
	case "darwin":
		dir = filepath.Join(s.layout.appSupport, "Zed")
	case "windows":
		dir = filepath.Join(s.layout.localData, "Zed")
	default:
		dir = filepath.Join(s.layout.localData, "zed")
	}
	installed := filepath.Join(dir, "extensions", "installed")
	if !s.isDir(installed) {
		return
	}
	inst := Install{Family: FamilyZed, Product: "zed", Channel: "stable", Root: installed}
	for _, name := range s.subdirs(installed, zedMaxExtensions) {
		if !safeName(name) || strings.HasPrefix(name, ".") {
			continue
		}
		path := filepath.Join(installed, name)
		p := Plugin{ID: clean(name), Scope: ScopeUser, Path: path, Enabled: EnabledOn, EnabledSource: SourceAlways}
		if data, ok := s.readFileLimit(filepath.Join(path, "extension.toml"), 256<<10); ok {
			var meta struct {
				ID      string   `toml:"id"`
				Name    string   `toml:"name"`
				Version string   `toml:"version"`
				Authors []string `toml:"authors"`
			}
			if toml.Unmarshal(data, &meta) == nil {
				if id := clean(meta.ID); id != "" {
					p.ID = id
				}
				p.DisplayName, p.Version = clean(meta.Name), clean(meta.Version)
				if len(meta.Authors) > 0 {
					author, _, _ := strings.Cut(meta.Authors[0], "<")
					p.Publisher = clean(author)
				}
			}
		}
		inst.Plugins = append(inst.Plugins, p)
	}
	s.add(inst)
}
