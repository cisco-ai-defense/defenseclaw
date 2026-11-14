// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// The pathname pattern walk (hookpaths actionExpandGlob) adopts the bound
// rule: past its directory-read bound (64, hookpaths
// TestGAP0401GlobWalkCapsAreBounded pins it) the call is TRUNCATED with cap
// paths (rel-1-0-10:GAP-0401). size is the number of directories the walk
// reads: the pattern folder and size-1 empty subfolders, all under the
// home, so no text shortcut decides the pattern.
const gap0401GlobReadBound = 64

func init() {
	registerBoundedLane(boundedLaneCap{lane: "s7/glob-static pattern walk", cap: bounded.Paths,
		limit: gap0401GlobReadBound, gen: gap0401GlobWalkCall, seen: boundedShellSeenCall})
}

var gap0401GlobFolders sync.Map // home and size -> folder

// gap0401GlobFolder is a folder under the lane home ($HOME, set by
// boundedLaneEnv) with size-1 empty subfolders.
func gap0401GlobFolder(size int) (string, bool) {
	home := os.Getenv("HOME")
	if !filepath.IsAbs(home) || size < 1 {
		return "", false
	}
	key := fmt.Sprintf("%s|%d", home, size)
	if dir, ok := gap0401GlobFolders.Load(key); ok {
		return dir.(string), true
	}
	dir := filepath.Join(home, "project", fmt.Sprintf("globwalk-%d", size))
	for i := 1; i < size; i++ {
		if err := os.MkdirAll(filepath.Join(dir, fmt.Sprintf("d%04d", i)), 0o700); err != nil {
			return "", false
		}
	}
	gap0401GlobFolders.Store(key, dir)
	return dir, true
}

func gap0401GlobWalkCall(size int, shape boundedShape) (boundedLaneCall, bool) {
	if shape.nested || shape.multi {
		return boundedLaneCall{}, false
	}
	dir, ok := gap0401GlobFolder(size)
	if !ok {
		return boundedLaneCall{}, false
	}
	command := "cp payload " + dir + "/*/*/notes.txt"
	if shape.seen {
		command = boundedShellSeen + "; " + command
	}
	if shape.seenAfter {
		command += "; " + boundedShellSeen
	}
	return boundedShellCommand(command), true
}
