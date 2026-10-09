// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package ideplugins

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
)

const (
	vimMaxPacks   = 64
	vimMaxPlugins = 2048
)

// scanVim lists Neovim and Vim plugins: lazy.nvim's lazy-lock.json (its
// enabled state is not recorded there), native packages (pack/*/start is
// loaded, pack/*/opt is not until :packadd) and vim-plug's plugged folder.
func (s *scanner) scanVim() {
	home := s.layout.home
	nvimConfig := filepath.Join(s.layout.appSupport, "nvim")
	nvimData := filepath.Join(s.layout.localData, "nvim")
	vimDir := filepath.Join(home, ".vim")
	if s.goos == "windows" {
		nvimConfig = filepath.Join(s.layout.localData, "nvim")
		nvimData = filepath.Join(s.layout.localData, "nvim-data")
		vimDir = filepath.Join(home, "vimfiles")
	} else if s.goos == "darwin" {
		// Neovim follows XDG on macOS too.
		nvimConfig = filepath.Join(home, ".config", "nvim")
		nvimData = filepath.Join(home, ".local", "share", "nvim")
	}

	neovim := Install{Family: FamilyVim, Product: "neovim", Channel: "stable", Root: nvimConfig}
	seen := map[string]bool{}
	addPlugin := func(inst *Install, p Plugin) {
		key := strings.ToLower(p.ID)
		if p.ID == "" || seen[inst.Product+"\x00"+key] {
			return
		}
		if len(inst.Plugins) >= vimMaxPlugins {
			inst.Partial = true
			return
		}
		seen[inst.Product+"\x00"+key] = true
		inst.Plugins = append(inst.Plugins, p)
	}
	if data, ok := s.readFile(filepath.Join(nvimConfig, "lazy-lock.json")); ok {
		var lock map[string]struct {
			Commit string `json:"commit"`
		}
		if json.Unmarshal(data, &lock) == nil {
			names := make([]string, 0, len(lock))
			for name := range lock {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				commit := clean(lock[name].Commit)
				if len(commit) > 12 {
					commit = commit[:12]
				}
				addPlugin(&neovim, Plugin{
					ID: clean(name), Version: commit, Scope: ScopeUser,
					Enabled: EnabledUnknown, EnabledSource: SourceLockfile,
					Path: filepath.Join(nvimData, "lazy", name),
				})
			}
		}
	}
	for _, root := range []string{filepath.Join(nvimConfig, "pack"), filepath.Join(nvimData, "site", "pack")} {
		s.scanVimPack(root, &neovim, addPlugin)
	}
	s.scanVimPlugged(filepath.Join(nvimData, "plugged"), &neovim, addPlugin)
	if len(neovim.Plugins) > 0 || s.isDir(nvimConfig) {
		if !s.isDir(nvimConfig) {
			neovim.Root = nvimData
		}
		s.add(neovim)
	}

	vim := Install{Family: FamilyVim, Product: "vim", Channel: "stable", Root: vimDir}
	s.scanVimPack(filepath.Join(vimDir, "pack"), &vim, addPlugin)
	s.scanVimPlugged(filepath.Join(vimDir, "plugged"), &vim, addPlugin)
	if len(vim.Plugins) > 0 {
		s.add(vim)
	}
}

func (s *scanner) scanVimPack(root string, inst *Install, add func(*Install, Plugin)) {
	for _, pack := range s.subdirs(root, vimMaxPacks) {
		if !safeName(pack) {
			continue
		}
		for _, kind := range []string{"start", "opt"} {
			dir := filepath.Join(root, pack, kind)
			for _, name := range s.subdirs(dir, vimMaxPlugins) {
				if !safeName(name) || strings.HasPrefix(name, ".") {
					continue
				}
				p := Plugin{ID: clean(name), Scope: ScopeUser, Path: filepath.Join(dir, name), Enabled: EnabledOn, EnabledSource: SourcePackStart}
				if kind == "opt" {
					p.Enabled, p.EnabledSource = EnabledOff, SourcePackOpt
				}
				add(inst, p)
			}
		}
	}
}

func (s *scanner) scanVimPlugged(dir string, inst *Install, add func(*Install, Plugin)) {
	for _, name := range s.subdirs(dir, vimMaxPlugins) {
		if !safeName(name) || strings.HasPrefix(name, ".") {
			continue
		}
		add(inst, Plugin{ID: clean(name), Scope: ScopeUser, Path: filepath.Join(dir, name), Enabled: EnabledUnknown, EnabledSource: SourcePluginDir})
	}
}
