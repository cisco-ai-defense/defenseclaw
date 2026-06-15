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

package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// csTextExtensions is the set of file extensions scanned by text-based ClawShield scanners.
var csTextExtensions = map[string]bool{
	// code
	".py": true, ".js": true, ".ts": true, ".go": true,
	".java": true, ".rb": true, ".php": true, ".sh": true,
	".c": true, ".cpp": true, ".h": true, ".rs": true,
	// config / data
	".yaml": true, ".yml": true, ".json": true, ".toml": true, ".xml": true,
	".env": true, ".ini": true, ".cfg": true, ".conf": true,
	// docs / templates
	".md": true, ".txt": true, ".rst": true, ".html": true, ".jinja": true,
}

// csCollectTextFiles returns all text-extension files under root.
func csCollectTextFiles(root string) ([]string, error) {
	return csCollectFiles(root, func(path string) bool {
		return csTextExtensions[filepath.Ext(path)]
	})
}

// csCollectAllFiles returns all non-directory files under root (for binary-aware scanning).
func csCollectAllFiles(root string) ([]string, error) {
	return csCollectFiles(root, func(string) bool { return true })
}

func csCollectFiles(root string, include func(string) bool) ([]string, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to scan symlink %s", root)
	}
	if !info.IsDir() {
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("refusing to scan non-regular file %s", root)
		}
		return []string{root}, nil
	}

	absRoot, _ := filepath.Abs(root)
	var files []string
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == "__pycache__" || name == ".venv" || name == "venv" {
				return filepath.SkipDir
			}
			return nil
		}
		info, lerr := os.Lstat(path)
		if lerr != nil {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil
		}
		if absRoot != "" {
			abs, aerr := filepath.Abs(path)
			if aerr != nil {
				return nil
			}
			rel, rerr := filepath.Rel(absRoot, abs)
			if rerr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				return nil
			}
		}
		if !include(path) {
			return nil
		}
		files = append(files, path)
		return nil
	})
	return files, err
}

// csOffsetToLine returns the 1-based line number for a byte offset in content.
func csOffsetToLine(content []byte, offset int) int {
	if offset > len(content) {
		offset = len(content)
	}
	line := 1
	for i := 0; i < offset; i++ {
		if content[i] == '\n' {
			line++
		}
	}
	return line
}

// csTruncateMatch caps a match string at 100 chars for display.
func csTruncateMatch(s string) string {
	if len(s) > 100 {
		return s[:100] + "..."
	}
	return s
}

// csLocation formats a file:line location string.
func csLocation(path string, content []byte, offset int) string {
	return fmt.Sprintf("%s:%d", path, csOffsetToLine(content, offset))
}
