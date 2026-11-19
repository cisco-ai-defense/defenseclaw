// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// The write-operand resolver's candidate bound (hookpaths.MaxResolvedCandidates,
// cap paths) in the cross-lane property test (rel-1-0-10 GAP-0438). The
// generator makes a folder of exactly size files in the call's project folder
// and a call that writes every one of them by one glob.
func init() {
	registerBoundedLane(boundedLaneCap{lane: "shell write operand paths", cap: bounded.Paths,
		limit: hookpaths.MaxResolvedCandidates, gen: boundedResolverPathsLane, seen: boundedShellSeenCall})
}

func boundedResolverPathsLane(size int, shape boundedShape) (boundedLaneCall, bool) {
	if shape.multi {
		return boundedLaneCall{}, false // the bound is per word: no second cap to hit
	}
	folder := filepath.Join(os.Getenv("HOME"), "project", fmt.Sprintf("fan%d", size))
	if _, err := os.Stat(folder); err != nil {
		if err := os.MkdirAll(folder, 0o700); err != nil {
			panic(err)
		}
		for i := range size {
			if err := os.WriteFile(filepath.Join(folder, fmt.Sprintf("f%d", i)), nil, 0o600); err != nil {
				panic(err)
			}
		}
	}
	command := "touch " + filepath.Base(folder) + "/*"
	if shape.nested {
		command = "bash -c '" + command + "'"
	}
	if shape.seen {
		command = boundedShellSeen + "; " + command
	}
	if shape.seenAfter {
		command += "; " + boundedShellSeen
	}
	return boundedShellCommand(strings.TrimSpace(command)), true
}
