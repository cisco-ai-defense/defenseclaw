// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

func codexLinkedPathIsNonSkillResource(path string) bool {
	path = strings.TrimSpace(path)
	return strings.HasPrefix(path, "app://") ||
		strings.HasPrefix(path, "mcp://") ||
		strings.HasPrefix(path, "plugin://")
}

type codexLinkedSkillIndex struct {
	byManifest map[string]map[string]string
	invalid    map[string]bool
	err        error
}

// buildCodexLinkedSkillIndex snapshots durable connector-scoped provenance
// once per prompt. Codex 0.144.0 gives an exact linked SKILL.md path
// precedence over the display label, including in active sessions whose skill
// directory was subsequently isolated. Prompt paths are used only for
// in-memory comparison and must never be copied into telemetry.
func (a *APIServer) buildCodexLinkedSkillIndex() codexLinkedSkillIndex {
	index := codexLinkedSkillIndex{
		byManifest: make(map[string]map[string]string),
		invalid:    make(map[string]bool),
	}
	if a == nil || a.store == nil {
		return index
	}
	entries, err := a.store.ListActionsByType("skill")
	if err != nil {
		index.err = fmt.Errorf("list skill identities: %w", err)
		return index
	}
	for _, entry := range entries {
		connector := strings.ToLower(strings.TrimSpace(entry.Connector))
		if connector != "" && connector != "codex" {
			continue
		}
		source := strings.TrimSpace(entry.SourcePath)
		if source == "" {
			continue
		}
		manifest := source
		if !strings.EqualFold(filepath.Base(source), "SKILL.md") {
			manifest = filepath.Join(source, "SKILL.md")
		}
		if !codexCanonicalSkillIdentity(entry.TargetName) {
			index.invalid[manifest] = true
			continue
		}
		if index.byManifest[manifest] == nil {
			index.byManifest[manifest] = make(map[string]string)
		}
		index.byManifest[manifest][entry.TargetName] = source
	}
	return index
}

func codexCanonicalSkillIdentity(name string) bool {
	// Linked mentions are path-authoritative in Codex 0.144.0. Unlike plain
	// $name tokens, their metadata identity may contain Unicode, spaces, or
	// punctuation. Mirror the loader's single-line whitespace normalization
	// and qualified-name character bound without broadening prompt parsing.
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 128 {
		return false
	}
	if strings.Join(strings.Fields(name), " ") != name {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func (index codexLinkedSkillIndex) resolve(linkedPath string) (name, trustedSource string, known bool, err error) {
	if index.err != nil {
		return "", "", false, index.err
	}
	linkedPath = strings.TrimSpace(linkedPath)
	linkedPath = strings.TrimPrefix(linkedPath, "skill://")
	if linkedPath == "" {
		return "", "", false, nil
	}
	// Match exactly, as Codex does against SkillMetadata.path_to_skills_md.
	// Do not clean, absolutize, case-fold, or otherwise broaden a prompt path.
	if index.invalid[linkedPath] {
		return "", "", false, fmt.Errorf("linked skill path has non-canonical provenance identity")
	}
	matches := index.byManifest[linkedPath]
	if len(matches) == 0 {
		return "", "", false, nil
	}
	if len(matches) != 1 {
		return "", "", false, fmt.Errorf("linked skill path maps to %d canonical identities", len(matches))
	}
	for name, source := range matches {
		return name, source, true, nil
	}
	return "", "", false, nil
}
