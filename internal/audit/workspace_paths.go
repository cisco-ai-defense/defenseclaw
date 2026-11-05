// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"strings"
	"unicode/utf8"
)

// Bounds of Event.WorkspaceHostPaths in a v8 record body (the hook already
// bounds them the same way; this keeps a record valid whatever the caller).
const (
	maxWorkspaceHostPaths     = 16
	maxWorkspaceHostPathBytes = 1024
)

// boundedWorkspaceHostPaths is the list of connected Cowork folders a v8
// body carries: at most maxWorkspaceHostPaths valid UTF-8 paths without
// control characters, each within maxWorkspaceHostPathBytes. A path outside
// the bounds is left out, never rewritten.
func boundedWorkspaceHostPaths(paths []string) []any {
	var out []any
	for _, path := range paths {
		if len(out) == maxWorkspaceHostPaths {
			break
		}
		if path == "" || len(path) > maxWorkspaceHostPathBytes || !utf8.ValidString(path) ||
			strings.IndexFunc(path, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			continue
		}
		out = append(out, path)
	}
	return out
}
