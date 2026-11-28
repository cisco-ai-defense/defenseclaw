// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package workspace

import (
	"cmp"
	"slices"
	"strings"
)

// CopySummary measures the working-tree files selected for an upload.
type CopySummary struct {
	Files int
	Bytes int64
	dirs  map[string]int64
}

// CopyDirSize is the selected size of a top-level directory.
type CopyDirSize struct {
	Path  string
	Bytes int64
}

// Add records one selected file with a slash-separated path.
func (s *CopySummary) Add(relative string, size int64) {
	s.Files++
	s.Bytes += size
	if dir, _, ok := strings.Cut(relative, "/"); ok {
		if s.dirs == nil {
			s.dirs = make(map[string]int64)
		}
		s.dirs[dir] += size
	}
}

// BiggestDirs returns at most n top-level directories in descending size order.
func (s *CopySummary) BiggestDirs(n int) []CopyDirSize {
	dirs := make([]CopyDirSize, 0, len(s.dirs))
	for name, size := range s.dirs {
		dirs = append(dirs, CopyDirSize{Path: name, Bytes: size})
	}
	slices.SortFunc(dirs, func(a, b CopyDirSize) int {
		if c := cmp.Compare(b.Bytes, a.Bytes); c != 0 {
			return c
		}
		return cmp.Compare(a.Path, b.Path)
	})
	return dirs[:min(n, len(dirs))]
}
