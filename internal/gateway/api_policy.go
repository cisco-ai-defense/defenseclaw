// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Policy bundle endpoints — read-only stage (REM-9).
//
// The operator's policy overlay tree lives under cfg.PolicyDir
// (default ~/.defenseclaw/policies). Files we surface:
//
//   *.rego                                              → kind=rego
//   guardrail/<profile>/rules/*.yaml                    → kind=guardrail-rule
//   guardrail/<profile>/suppressions.yaml               → kind=suppression
//   scanners/*.yaml                                     → kind=scanner
//   data*.json | *.json                                 → kind=data
//   *.yaml (anything else)                              → kind=yaml
//
// Edit + test endpoints (PUT / POST) land in the next REM-9 stage.

type policyBundleEntry struct {
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	RelPath  string `json:"rel_path"`
	Size     int64  `json:"size"`
	Modified string `json:"modified"`
}

// handleV1PolicyBundles walks PolicyDir and returns a flat list of bundles.
//
// Returns an empty list (not an error) when the dir doesn't exist yet —
// fresh installs haven't seeded the overlay tree until the first
// `defenseclaw setup …` mutation.
func (a *APIServer) handleV1PolicyBundles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.scannerCfg == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "config not loaded"})
		return
	}
	a.cfgMu.RLock()
	dir := a.scannerCfg.PolicyDir
	a.cfgMu.RUnlock()

	entries, err := walkPolicyTree(dir)
	if err != nil {
		if os.IsNotExist(err) {
			a.writeJSON(w, http.StatusOK, map[string]any{
				"dir":     dir,
				"bundles": []policyBundleEntry{},
				"note":    "policy overlay dir does not exist yet",
			})
			return
		}
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Kind != entries[j].Kind {
			return entries[i].Kind < entries[j].Kind
		}
		return entries[i].RelPath < entries[j].RelPath
	})
	a.writeJSON(w, http.StatusOK, map[string]any{
		"dir":     dir,
		"bundles": entries,
		"count":   len(entries),
	})
}

// handleV1PolicyBundle reads a single bundle file. Path is taken from
// ?path=<rel> and validated to live inside PolicyDir (no `..` escape).
func (a *APIServer) handleV1PolicyBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.scannerCfg == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "config not loaded"})
		return
	}
	rel := strings.TrimSpace(r.URL.Query().Get("path"))
	if rel == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "?path= is required"})
		return
	}

	a.cfgMu.RLock()
	dir := a.scannerCfg.PolicyDir
	a.cfgMu.RUnlock()

	abs, err := safeJoin(dir, rel)
	if err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	stat, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such file"})
			return
		}
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if stat.IsDir() {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "path is a directory"})
		return
	}

	data, err := os.ReadFile(abs)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	a.writeJSON(w, http.StatusOK, map[string]any{
		"rel_path": rel,
		"abs_path": abs,
		"kind":     classifyBundle(rel),
		"size":     stat.Size(),
		"modified": stat.ModTime().UTC().Format(time.RFC3339),
		"content":  string(data),
	})
}

// safeJoin resolves rel against base and rejects results that escape base.
// Symlinks are resolved before the containment check so a symlink pointing
// out of the tree is also rejected.
func safeJoin(base, rel string) (string, error) {
	if strings.Contains(rel, "\x00") {
		return "", fs.ErrInvalid
	}
	clean := filepath.Clean("/" + rel) // forces absolute, drops `..`
	candidate := filepath.Join(base, clean)
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		// Fall back to the unresolved path; os.Stat will surface NOT_EXIST.
		resolved = candidate
	}
	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}
	rel2, err := filepath.Rel(absBase, resolved)
	if err != nil || strings.HasPrefix(rel2, "..") {
		return "", fs.ErrPermission
	}
	return resolved, nil
}

func walkPolicyTree(dir string) ([]policyBundleEntry, error) {
	stat, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !stat.IsDir() {
		return nil, fs.ErrInvalid
	}
	out := []policyBundleEntry{}
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// Skip unreadable subtrees but keep walking.
			return nil
		}
		if d.IsDir() {
			// Ignore hidden + node_modules-like subdirs.
			if strings.HasPrefix(d.Name(), ".") {
				return fs.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext != ".rego" && ext != ".yaml" && ext != ".yml" && ext != ".json" {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		out = append(out, policyBundleEntry{
			Kind:     classifyBundle(rel),
			Name:     d.Name(),
			RelPath:  rel,
			Size:     info.Size(),
			Modified: info.ModTime().UTC().Format(time.RFC3339),
		})
		return nil
	})
	return out, err
}

// classifyBundle picks a kind label from a path relative to PolicyDir.
// Order matters: more-specific patterns first.
func classifyBundle(rel string) string {
	rel = filepath.ToSlash(rel)
	ext := strings.ToLower(filepath.Ext(rel))
	switch {
	case ext == ".rego":
		return "rego"
	case strings.HasPrefix(rel, "guardrail/") && strings.HasSuffix(rel, "/suppressions.yaml"):
		return "suppression"
	case strings.HasPrefix(rel, "guardrail/") && strings.Contains(rel, "/rules/") && (ext == ".yaml" || ext == ".yml"):
		return "guardrail-rule"
	case strings.HasPrefix(rel, "scanners/") && (ext == ".yaml" || ext == ".yml"):
		return "scanner"
	case ext == ".json":
		return "data"
	case ext == ".yaml" || ext == ".yml":
		return "yaml"
	default:
		return "other"
	}
}
