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

package watcher

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// TargetSnapshot captures the hashed state of a skill/MCP directory
// for baseline comparison during periodic re-scans.
type TargetSnapshot struct {
	ContentHash      string            `json:"content_hash"`
	DependencyHashes map[string]string `json:"dependency_hashes"`
	ConfigHashes     map[string]string `json:"config_hashes"`
	NetworkEndpoints []string          `json:"network_endpoints"`
	Timestamp        time.Time         `json:"timestamp"`
}

var dependencyFiles = map[string]bool{
	"requirements.txt": true,
	"package.json":     true,
	"package-lock.json": true,
	"pyproject.toml":   true,
	"go.mod":           true,
	"go.sum":           true,
	"Gemfile":          true,
	"Gemfile.lock":     true,
	"Cargo.toml":       true,
	"Cargo.lock":       true,
}

var configFiles = map[string]bool{
	"skill.yaml":    true,
	"skill.yml":     true,
	"mcp.json":      true,
	"mcp.yaml":      true,
	"config.yaml":   true,
	"config.yml":    true,
	"config.json":   true,
	"manifest.json": true,
	".env":          true,
	".env.local":    true,
}

var codeExtensions = map[string]bool{
	".py": true, ".js": true, ".ts": true, ".go": true, ".rb": true,
	".java": true, ".rs": true, ".php": true, ".sh": true, ".bash": true,
}

// Matches http(s) URLs and common IP:port patterns in source code.
var urlPattern = regexp.MustCompile(
	`https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+` +
		`|` +
		`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{1,5})?\b`,
)

// Well-known non-actionable URL prefixes excluded from endpoint drift detection.
var ignoredPrefixes = []string{
	"http://localhost",
	"https://localhost",
	"http://127.0.0.1",
	"https://127.0.0.1",
	"http://example.com",
	"https://example.com",
	"http://0.0.0.0",
}

func isIgnoredEndpoint(url string) bool {
	for _, prefix := range ignoredPrefixes {
		if strings.HasPrefix(url, prefix) {
			return true
		}
	}
	return false
}

// SnapshotTarget walks a directory and captures hashed state for drift detection.
func SnapshotTarget(root string) (*TargetSnapshot, error) {
	snap := &TargetSnapshot{
		DependencyHashes: make(map[string]string),
		ConfigHashes:     make(map[string]string),
		Timestamp:        time.Now().UTC(),
	}

	endpointSet := make(map[string]bool)
	var allHashes []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := info.Name()
			if base == ".git" || base == "node_modules" || base == "__pycache__" || base == ".venv" || base == "venv" {
				return filepath.SkipDir
			}
			return nil
		}

		rel, _ := filepath.Rel(root, path)
		base := filepath.Base(path)
		ext := strings.ToLower(filepath.Ext(path))

		h, hashErr := hashFile(path)
		if hashErr != nil {
			return nil
		}
		allHashes = append(allHashes, rel+":"+h)

		if dependencyFiles[base] {
			snap.DependencyHashes[rel] = h
		}
		if configFiles[base] {
			snap.ConfigHashes[rel] = h
		}

		if codeExtensions[ext] {
			endpoints := extractEndpoints(path)
			for _, ep := range endpoints {
				endpointSet[ep] = true
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Strings(allHashes)
	overall := sha256.New()
	for _, entry := range allHashes {
		overall.Write([]byte(entry + "\n"))
	}
	snap.ContentHash = hex.EncodeToString(overall.Sum(nil))

	snap.NetworkEndpoints = make([]string, 0, len(endpointSet))
	for ep := range endpointSet {
		snap.NetworkEndpoints = append(snap.NetworkEndpoints, ep)
	}
	sort.Strings(snap.NetworkEndpoints)

	return snap, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func extractEndpoints(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	const maxScanSize = 512 * 1024
	if len(data) > maxScanSize {
		data = data[:maxScanSize]
	}

	matches := urlPattern.FindAllString(string(data), -1)
	seen := make(map[string]bool)
	var result []string
	for _, m := range matches {
		normalized := strings.TrimRight(m, ".,;:\"')")
		if isIgnoredEndpoint(normalized) || seen[normalized] {
			continue
		}
		seen[normalized] = true
		result = append(result, normalized)
	}
	return result
}
