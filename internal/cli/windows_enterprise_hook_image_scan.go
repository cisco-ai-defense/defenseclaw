// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// Which launch folders (GAP-0751) a DefenseClaw-written file still names.
// Prune keeps every folder a config, selector, state file or journal names,
// and retire waits until none does. The decisions are OS-independent; the
// Windows file list is windowsHookImageConfigFiles.

// windowsHookImageConfigScan is the result of one scan.
type windowsHookImageConfigScan struct {
	// Named maps a launch folder name (16 lowercase hex digits) to the files
	// that name an image in it.
	Named map[string][]string
	// Incomplete lists "<file>: <error>" for each file that exists but could
	// not be read. A scan with any entry here proves nothing about the
	// folders, so prune removes none.
	Incomplete []string
}

// scanWindowsHookImageConfigFiles reads each file (a missing one is
// skipped) and records the launch folders it names.
func scanWindowsHookImageConfigFiles(files []string, read func(string) ([]byte, error)) windowsHookImageConfigScan {
	scan := windowsHookImageConfigScan{Named: map[string][]string{}}
	seen := map[string]bool{}
	for _, file := range files {
		key := strings.ToLower(strings.TrimSpace(file))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		body, err := read(file)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			scan.Incomplete = append(scan.Incomplete, fmt.Sprintf("%s: %v", file, err))
			continue
		}
		for _, folder := range windowsHookImageFoldersNamedIn(body) {
			scan.Named[folder] = append(scan.Named[folder], file)
		}
	}
	return scan
}

// windowsHookImageFoldersNamedIn returns the launch folders an image path in
// body names: ...\hooks\<16 hex>\defenseclaw-hook.exe (or -guard.exe), in a
// plain Windows path, a JSON or TOML string (backslashes doubled) or with
// forward slashes, in any case. It does not insist on the install root
// spelling (an 8.3 name, a different drive letter case): any match keeps the
// folder, which errs on the side of the session that starts it.
func windowsHookImageFoldersNamedIn(body []byte) []string {
	text := strings.ReplaceAll(strings.ToLower(string(body)), "/", `\`)
	for strings.Contains(text, `\\`) {
		text = strings.ReplaceAll(text, `\\`, `\`)
	}
	const marker = `\` + winpath.EnterpriseHookImagesDirName + `\`
	found := map[string]bool{}
	for index := 0; ; {
		at := strings.Index(text[index:], marker)
		if at < 0 {
			break
		}
		start := index + at + len(marker)
		index = start
		if start+16 > len(text) {
			break
		}
		name := text[start : start+16]
		if winpath.IsEnterpriseHookImageDirName(name) && strings.HasPrefix(text[start+16:], `\defenseclaw-hook`) {
			found[name] = true
		}
	}
	out := make([]string, 0, len(found))
	for name := range found {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// windowsHookImageStageTimes is the time each launch folder of root was
// staged: the modification time of its hook image, which stage writes new.
// A folder whose hook cannot be read has no entry.
func windowsHookImageStageTimes(fsys windowsHookImageFS, root string, entries []fs.DirEntry) map[string]time.Time {
	staged := map[string]time.Time{}
	for _, entry := range entries {
		name := strings.ToLower(entry.Name())
		if !winpath.IsEnterpriseHookImageDirName(name) || !entry.IsDir() {
			continue
		}
		info, err := fsys.Lstat(windowsHookImageJoin(root, entry.Name(), winpath.EnterpriseHookImageName))
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		staged[name] = info.ModTime()
	}
	return staged
}

// windowsHookImageRetainReason says why prune keeps the launch folder name
// (neither current nor kept), or "" when it may go. A folder is superseded
// when the first folder staged after it was staged; a folder no later one
// followed (a stage that failed to start) counts from its own stage time.
func windowsHookImageRetainReason(name string, staged map[string]time.Time, policy windowsHookImagePrunePolicy) string {
	if len(policy.Scan.Incomplete) > 0 {
		return "scan_incomplete"
	}
	if files := policy.Scan.Named[name]; len(files) > 0 {
		return "named_by:" + files[0]
	}
	own, ok := staged[name]
	if !ok {
		return "superseded_recently:unknown"
	}
	superseded := time.Time{}
	for other, at := range staged {
		if other == name || !at.After(own) {
			continue
		}
		if superseded.IsZero() || at.Before(superseded) {
			superseded = at
		}
	}
	if superseded.IsZero() {
		superseded = own
	}
	if policy.Now.Sub(superseded) < hookImageRetainAfterSupersede {
		return "superseded_recently:" + superseded.UTC().Format(time.RFC3339)
	}
	return ""
}

// clearWindowsHookImagesRetired removes the retire marker once this
// release's launch set is staged and started again: an administrator who
// retired the folders and then ran this release's Setup un-retires them.
func clearWindowsHookImagesRetired(fsys windowsHookImageFS, root string) []string {
	marker := windowsHookImageJoin(root, winpath.EnterpriseHookImagesRetiredMarker)
	info, err := fsys.Lstat(marker)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return []string{fmt.Sprintf("inspect the retire marker %s: %v", marker, err)}
	}
	if !info.Mode().IsRegular() {
		return []string{fmt.Sprintf("left %s: not a file", marker)}
	}
	if err := fsys.RemoveAll(marker); err != nil {
		return []string{fmt.Sprintf("the retire marker %s stays: %v", marker, err)}
	}
	return []string{"removed the retire marker " + marker + ": agent configs name the launch set again"}
}
