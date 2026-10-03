// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RemoveUserUVCacheEntries removes DefenseClaw's entries from the account's
// default uv cache (<home>/.cache/uv), which per-user installers before 1.0.2
// filled with one DefenseClaw wheel per install (GAP-1411, GAP-1947): the
// unpacked archives that hold only DefenseClaw (archive-v*/<id>, including an
// editable build's .pth), the wheel pointers (wheels-v*/.../defenseclaw) and
// the editable builds (sdists-v*/editable/<source>). It is what the per-user
// `uninstall --all --binaries` does with `uv cache clean defenseclaw`, without
// needing uv. Only real folders the account owns go, never through a link;
// the rest of the cache stays. It returns the paths it removed. Run it as the
// account.
func RemoveUserUVCacheEntries(home string, uid int) ([]string, error) {
	cache := filepath.Join(home, ".cache", "uv")
	ownedDir := func(path string) bool {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() {
			return false
		}
		ok, _ := fileOwnerMatches(path, uid)
		return ok
	}
	if !ownedDir(filepath.Dir(cache)) || !ownedDir(cache) {
		return nil, nil
	}
	realCache, err := filepath.EvalSymlinks(cache)
	if err != nil {
		return nil, nil
	}
	// inCache reports whether path is reached without any link below the
	// cache folder, so a linked archive-v* or wheels-v* names nothing outside.
	inCache := func(path string) bool {
		rel, err := filepath.Rel(cache, path)
		if err != nil {
			return false
		}
		resolved, err := filepath.EvalSymlinks(path)
		return err == nil && resolved == filepath.Join(realCache, rel)
	}
	// onlyDefenseClaw reports whether dir holds at least one entry matching
	// pattern and all of them start with "defenseclaw-".
	onlyDefenseClaw := func(dir, pattern string) bool {
		matches, _ := filepath.Glob(filepath.Join(dir, pattern))
		for _, match := range matches {
			if !strings.HasPrefix(filepath.Base(match), "defenseclaw-") {
				return false
			}
		}
		return len(matches) > 0
	}
	var candidates []string
	add := func(pattern string, keep func(string) bool) {
		matches, _ := filepath.Glob(filepath.Join(cache, filepath.FromSlash(pattern)))
		for _, match := range matches {
			if keep == nil || keep(match) {
				candidates = append(candidates, match)
			}
		}
	}
	add("archive-v*/*", func(dir string) bool { return onlyDefenseClaw(dir, "*.dist-info") })
	add("wheels-v*/*/defenseclaw", nil)
	add("wheels-v*/*/*/defenseclaw", nil)
	add("sdists-v*/editable/*", func(dir string) bool { return onlyDefenseClaw(dir, "*/*.whl") })

	var removed []string
	var errs []error
	for _, path := range candidates {
		if !ownedDir(path) || !inCache(path) {
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			errs = append(errs, err)
			continue
		}
		removed = append(removed, path)
	}
	if len(errs) > 0 {
		return removed, fmt.Errorf("enterprise hooks: remove DefenseClaw's entries from the uv cache: %w", errors.Join(errs...))
	}
	return removed, nil
}
