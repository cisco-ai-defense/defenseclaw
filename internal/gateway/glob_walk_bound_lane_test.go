// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// globWalkBoundReads is the read bound of the target scan's pattern walk
// (hookpaths actionGlobMaxReads).
const globWalkBoundReads = 64

var globWalkTrees struct {
	sync.Mutex
	root  string
	sizes map[int]string
}

// globWalkTree is a folder of size-1 empty folders: the pattern
// <tree>/b*/c* reads the folder and each of them, size directory reads. The
// trees live in one temporary folder for the test binary.
func globWalkTree(size int) string {
	globWalkTrees.Lock()
	defer globWalkTrees.Unlock()
	if tree, ok := globWalkTrees.sizes[size]; ok {
		return tree
	}
	if globWalkTrees.root == "" {
		root, err := os.MkdirTemp("", "dc-glob-walk-lane-")
		if err != nil {
			panic(err)
		}
		globWalkTrees.root, globWalkTrees.sizes = root, map[int]string{}
	}
	tree := filepath.Join(globWalkTrees.root, fmt.Sprintf("s%d", size))
	for index := 0; index < size-1; index++ {
		if err := os.MkdirAll(filepath.Join(tree, fmt.Sprintf("b%04d", index)), 0o755); err != nil {
			panic(err)
		}
	}
	globWalkTrees.sizes[size] = tree
	return tree
}

// The property test of the bound rule (TestBoundRuleEveryLaneCap) covers the
// read bound of the target scan's pattern walk in the five tiers
// (rel-1-0-10:GAP-1324): an ls of <tree>/b*/c* beside a cp is read whole and
// allowed at the bound; past it the walk stops with no protected match read,
// which was the CRITICAL authorized-keys block in every tier and is now
// TRUNCATED, cap paths (the unknown tier, the judge still asked). A write
// into the capped pattern keeps the rel/1.0.10 protected target
// (rel-1-0-10:GAP-2300, TestGAP1324GlobWalkCapIsTruncated).
func init() {
	walk := func(size int) string { return "ls " + globWalkTree(size) + "/b*/c*; cp a.txt b.txt" }
	registerBoundedLane(boundedLaneCap{lane: "target scan glob walk", cap: bounded.Paths, limit: globWalkBoundReads,
		gen: func(size int, shape boundedShape) (boundedLaneCall, bool) {
			if shape.multi {
				return boundedLaneCall{}, false
			}
			return boundedShellLane(walk, walk)(size, shape)
		},
		seen: boundedShellSeenCall})
}
