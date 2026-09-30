// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Devin plugins ship hooks that register in every local session, the Devin
// CLI and Devin Local inside Devin Desktop, and can rewrite tool input
// (https://docs.devin.ai/cli/extensibility/plugins/overview). Installed
// plugins live in the Devin CLI's data directory, <data>/devin/cli/plugins:
// <XDG_DATA_HOME or ~/.local/share> (observed with Devin CLI 3000.11.3 on
// Linux) and %LOCALAPPDATA% on Windows, where the CLI keeps its releases
// under devin\cli\_versions. The store's inner layout is not documented, so
// the guard walks it for plugin roots: a directory holding
// .devin-plugin/plugin.json, .claude-plugin/plugin.json, plugin.json or
// hooks.json. A plugin installed with --local links to its source folder;
// a link in the store, or an absolute folder path recorded in the store's
// lock.json or discovered.json, is followed to that folder. The cleanup
// reports plugin hooks and leaves them in place: the user uninstalls the
// plugin.

// formatDevinPlugins is Devin's installed-plugin store.
const formatDevinPlugins = "devin-plugins"

// devinPluginWalkDepth bounds how far below the store the walk looks for
// plugin roots; it does not descend into a plugin root.
const devinPluginWalkDepth = 6

// devinPluginLinkLimit bounds the linked folders followed from one store.
const devinPluginLinkLimit = 64

// devinPluginManifests are the manifest locations in the order Devin reads
// them; the first one present is used.
var devinPluginManifests = []string{
	filepath.Join(".devin-plugin", "plugin.json"),
	filepath.Join(".claude-plugin", "plugin.json"),
	"plugin.json",
}

// devinPluginStores returns the plugin store directories under home.
func devinPluginStores(req GuardRequest, home string) []string {
	if home == "" {
		return nil
	}
	var stores []string
	if req.goos() == "windows" {
		if local := req.getenv("LOCALAPPDATA"); local != "" {
			stores = append(stores, filepath.Join(local, "devin", "cli", "plugins"))
		}
		return append(stores, filepath.Join(home, "AppData", "Local", "devin", "cli", "plugins"))
	}
	if data := req.getenv("XDG_DATA_HOME"); data != "" {
		stores = append(stores, filepath.Join(data, "devin", "cli", "plugins"))
	}
	stores = append(stores, filepath.Join(home, ".local", "share", "devin", "cli", "plugins"))
	if req.goos() == "darwin" {
		stores = append(stores, filepath.Join(home, "Library", "Application Support", "devin", "cli", "plugins"))
	}
	return stores
}

type devinPluginWalk struct {
	s     *guardScan
	store hookSource
	roots []string
	links int
}

func (s *guardScan) scanDevinPlugins(store hookSource) []Finding {
	w := &devinPluginWalk{s: s, store: store}
	return w.walk(store.path, 0)
}

func (w *devinPluginWalk) walk(dir string, depth int) []Finding {
	s := w.s
	entries, exists, err := s.readDir(dir)
	if err != nil {
		return []Finding{s.unreadable(w.store.child(dir, formatDevinPlugins), err)}
	}
	if !exists {
		return nil
	}
	if depth > 0 && devinPluginRoot(entries) {
		return w.root(dir)
	}
	var findings []Finding
	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join(dir, name)
		switch {
		case name == ".git" || name == "node_modules":
		case entry.Type()&(fs.ModeSymlink|fs.ModeIrregular) != 0:
			findings = append(findings, w.linked(path)...)
		case entry.IsDir():
			if depth < devinPluginWalkDepth {
				findings = append(findings, w.walk(path, depth+1)...)
			}
		case depth == 0 && (name == "lock.json" || name == "discovered.json"):
			findings = append(findings, w.recorded(path)...)
		}
		if s.exceeded != nil {
			break
		}
	}
	return findings
}

func devinPluginRoot(entries []fs.DirEntry) bool {
	for _, entry := range entries {
		switch entry.Name() {
		case ".devin-plugin", ".claude-plugin":
			if entry.IsDir() {
				return true
			}
		case "plugin.json", "hooks.json":
			if entry.Type().IsRegular() {
				return true
			}
		}
	}
	return false
}

// linked follows a link in the store to the folder it names. A dangling
// link loads nothing.
func (w *devinPluginWalk) linked(path string) []Finding {
	target, err := filepath.EvalSymlinks(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return []Finding{w.s.unreadable(w.store.child(path, formatDevinPlugins), err)}
	}
	return w.folder(path, target)
}

// recorded follows every absolute folder path a store record names.
func (w *devinPluginWalk) recorded(path string) []Finding {
	s := w.s
	source := w.store.child(path, formatDevinPlugins)
	data, exists, err := s.readFile(path)
	if err != nil {
		return []Finding{s.unreadable(source, err)}
	}
	if !exists || strings.TrimSpace(string(data)) == "" {
		return nil
	}
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		return []Finding{s.unreadable(source, fmt.Errorf("decode Devin plugin record: %w", err))}
	}
	paths := absolutePathStrings(doc, nil)
	sort.Strings(paths)
	var findings []Finding
	for _, value := range paths {
		info, err := os.Stat(value)
		if err != nil || !info.IsDir() {
			// A recorded path that is gone, or names a file, holds no plugin.
			continue
		}
		target, err := filepath.EvalSymlinks(value)
		if err != nil {
			findings = append(findings, s.unreadable(w.store.child(value, formatDevinPlugins), err))
			continue
		}
		if rel, err := filepath.Rel(w.store.path, target); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			// The walk covers folders inside the store.
			continue
		}
		findings = append(findings, w.folder(value, target)...)
		if s.exceeded != nil {
			break
		}
	}
	return findings
}

// folder scans a linked folder when it is a plugin root.
func (w *devinPluginWalk) folder(ref, target string) []Finding {
	s := w.s
	source := w.store.child(ref, formatDevinPlugins)
	if w.links++; w.links > devinPluginLinkLimit {
		return []Finding{s.unreadable(source, guardLimit("%s links more than %d plugin folders", w.store.path, devinPluginLinkLimit))}
	}
	// Probe the markers rather than list the folder: a record may name a
	// large folder that is not a plugin.
	for _, marker := range []string{".devin-plugin", ".claude-plugin", "plugin.json", "hooks.json"} {
		info, err := os.Lstat(filepath.Join(target, marker))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return []Finding{s.unreadable(source, err)}
		}
		if info.IsDir() == strings.HasPrefix(marker, ".") && (info.IsDir() || info.Mode().IsRegular()) {
			return w.root(target)
		}
	}
	return nil
}

func (w *devinPluginWalk) root(dir string) []Finding {
	if containsPath(w.roots, dir) {
		return nil
	}
	w.roots = append(w.roots, dir)
	return w.s.scanPluginHooks(w.store, dir, devinPluginManifests, []string{"hooks.json", filepath.Join("hooks", "hooks.json")}, formatHooksObject)
}

// absolutePathStrings collects the distinct absolute paths among value's
// strings.
func absolutePathStrings(value any, out []string) []string {
	switch v := value.(type) {
	case string:
		if filepath.IsAbs(v) && !containsPath(out, v) {
			out = append(out, filepath.Clean(v))
		}
	case []any:
		for _, item := range v {
			out = absolutePathStrings(item, out)
		}
	case map[string]any:
		for _, item := range v {
			out = absolutePathStrings(item, out)
		}
	}
	return out
}
