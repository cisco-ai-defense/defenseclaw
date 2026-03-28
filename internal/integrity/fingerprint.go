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

package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// FingerprintDir computes a deterministic SHA-256 over the directory tree.
// Symlinks are recorded as link targets (not followed for directory traversal).
// Skips .git, __pycache__, and .DS_Store.
func FingerprintDir(root string) (fingerprint string, fileCount int, err error) {
	root, err = filepath.Abs(filepath.Clean(root))
	if err != nil {
		return "", 0, fmt.Errorf("integrity: abs path: %w", err)
	}
	fi, err := os.Stat(root)
	if err != nil {
		return "", 0, fmt.Errorf("integrity: stat root: %w", err)
	}
	if !fi.IsDir() {
		return "", 0, fmt.Errorf("integrity: root is not a directory")
	}

	var relFiles []string
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		li, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if li.Mode()&os.ModeSymlink != 0 {
			relFiles = append(relFiles, rel+"\x00symlink")
			return filepath.SkipDir
		}
		if li.IsDir() {
			if shouldSkipIntegrityDir(rel) {
				return filepath.SkipDir
			}
			return nil
		}
		if shouldSkipIntegrityFile(rel, li) {
			return nil
		}
		if !li.Mode().IsRegular() {
			return nil
		}
		relFiles = append(relFiles, rel+"\x00file")
		return nil
	})
	if err != nil {
		return "", 0, fmt.Errorf("integrity: walk: %w", err)
	}

	sort.Strings(relFiles)

	h := sha256.New()
	nFiles := 0
	for _, tagged := range relFiles {
		idx := strings.IndexByte(tagged, 0)
		if idx < 0 {
			continue
		}
		rel := tagged[:idx]
		kind := tagged[idx+1:]
		full := filepath.Join(root, rel)

		switch kind {
		case "symlink":
			target, err := os.Readlink(full)
			if err != nil {
				return "", 0, fmt.Errorf("integrity: readlink %s: %w", full, err)
			}
			fmt.Fprintf(h, "L:%s:%s\n", rel, target)
		case "file":
			f, err := os.Open(full)
			if err != nil {
				return "", 0, fmt.Errorf("integrity: open %s: %w", full, err)
			}
			fmt.Fprintf(h, "F:%s\n", rel)
			if _, err := io.Copy(h, f); err != nil {
				f.Close()
				return "", 0, fmt.Errorf("integrity: hash %s: %w", full, err)
			}
			f.Close()
			nFiles++
		}
	}

	return hex.EncodeToString(h.Sum(nil)), nFiles, nil
}

func shouldSkipIntegrityDir(rel string) bool {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for _, p := range parts {
		switch p {
		case ".git", "__pycache__", "node_modules":
			return true
		}
	}
	return false
}

func shouldSkipIntegrityFile(rel string, fi os.FileInfo) bool {
	if fi.Name() == ".DS_Store" {
		return true
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for _, p := range parts {
		switch p {
		case ".git", "__pycache__", "node_modules":
			return true
		}
	}
	return false
}

// FingerprintMCPServer returns a stable hash of the resolved MCP server definition.
func FingerprintMCPServer(e config.MCPServerEntry) (string, error) {
	payload := struct {
		Name      string            `json:"name"`
		Command   string            `json:"command,omitempty"`
		Args      []string          `json:"args,omitempty"`
		EnvKeys   []string          `json:"env_keys,omitempty"`
		Env       map[string]string `json:"env,omitempty"`
		URL       string            `json:"url,omitempty"`
		Transport string            `json:"transport,omitempty"`
	}{
		Name:      e.Name,
		Command:   e.Command,
		Args:      append([]string(nil), e.Args...),
		URL:       e.URL,
		Transport: e.Transport,
	}
	if len(e.Env) > 0 {
		keys := make([]string, 0, len(e.Env))
		for k := range e.Env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		payload.EnvKeys = keys
		payload.Env = make(map[string]string, len(e.Env))
		for _, k := range keys {
			payload.Env[k] = e.Env[k]
		}
	}
	sort.Strings(payload.Args)
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("integrity: marshal mcp: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
