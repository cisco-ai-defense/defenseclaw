// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// detectClaudeProjectSkills uses only projects named by this user's Claude
// state. A project outside the home, a linked path, or a path the user cannot
// read is skipped and makes the detector visibly partial.
func (s *ContinuousDiscoveryService) detectClaudeProjectSkills() ([]AISignal, error) {
	if s.opts.SecureClient || len(s.opts.homeOwners) != 0 {
		return nil, nil // managed Windows already has its own project-root scan
	}
	var claude *AISignature
	for i := range s.catalog {
		if s.catalog[i].ID == "claudecode" {
			claude = &s.catalog[i]
			break
		}
	}
	if claude == nil {
		return nil, nil
	}
	home := filepath.Clean(s.opts.HomeDir)
	statePath := filepath.Join(home, ".claude.json")
	if _, err := os.Lstat(statePath); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	_, projects, err := readClaudeDiscoveryState(statePath)
	if err != nil {
		return nil, errors.New("Claude project state unavailable or outside the 256 MiB read limit")
	}
	var out []AISignal
	skipped := false
	for i, project := range projects {
		if i >= 128 {
			skipped = true
			break
		}
		path := filepath.Join(project, ".claude", "skills")
		rel, relErr := filepath.Rel(home, path)
		if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			skipped = true
			continue
		}
		// Check each ancestor before EvalSymlinks: a link in an otherwise
		// readable project can resolve into a TCC-protected home folder.
		if !s.claudeProjectExplicit(path) {
			blocked := false
			ancestor := home
			for _, part := range strings.Split(rel, string(filepath.Separator)) {
				ancestor = filepath.Join(ancestor, part)
				if s.macOSTCCSkipped(ancestor) || s.modelLinkPrivacySkipped(ancestor) {
					blocked = true
					break
				}
			}
			if blocked {
				skipped = true
				continue
			}
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				skipped = true
			}
			continue
		}
		if !s.claudeProjectExplicit(path) && s.macOSTCCSkipped(resolved) {
			skipped = true
			continue
		}
		if filepath.Clean(resolved) != path {
			skipped = true
			continue
		}
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			skipped = true
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			skipped = true
			continue
		}
		entries, readErr := f.ReadDir(1)
		_ = f.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			skipped = true
			continue
		}
		if len(entries) == 0 {
			continue
		}
		out = append(out, s.signalFromDirectoryChildren(*claude, SignalSkill, "skill", path))
	}
	if skipped {
		return out, errors.New("Claude project skills skipped: project outside home, unreadable, linked, or over limit")
	}
	return out, nil
}

// An exact project root or skills directory in scan_roots is deliberate
// consent; the default broad home root is not.
func (s *ContinuousDiscoveryService) claudeProjectExplicit(path string) bool {
	project := filepath.Dir(filepath.Dir(path))
	for _, root := range s.opts.ScanRoots {
		for _, candidate := range s.expandCandidatePath(root) {
			candidate = filepath.Clean(candidate)
			if candidate == project || candidate == path {
				return true
			}
		}
	}
	return false
}
