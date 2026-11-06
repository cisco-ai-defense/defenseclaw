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
	"fmt"
	"io"
	"net"
	neturl "net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
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
	"requirements.txt":  true,
	"package.json":      true,
	"package-lock.json": true,
	"pyproject.toml":    true,
	"go.mod":            true,
	"go.sum":            true,
	"Gemfile":           true,
	"Gemfile.lock":      true,
	"Cargo.toml":        true,
	"Cargo.lock":        true,
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
var urlPattern = lazyregexp.New(
	`https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+` +
		`|` +
		`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{1,5})?\b`,
)

// Well-known non-actionable hostnames excluded from endpoint drift
// detection. ("Endpoint ignore list uses unsafe
// string-prefix matching"): the legacy implementation tested
// strings.HasPrefix against `http://localhost`, so URLs like
// `http://localhost@attacker.example/...` and
// `http://localhost.attacker.example/...` were silently swallowed
// even though they targeted external hosts. We now parse the URL
// and ignore only when the host is one of these *exact* hostnames
// or a loopback IP literal.
var ignoredHostnames = map[string]struct{}{
	"localhost":       {},
	"example.com":     {},
	"www.example.com": {},
	"127.0.0.1":       {},
	"::1":             {},
	"0.0.0.0":         {},
}

func isIgnoredEndpoint(raw string) bool {
	parsed, err := neturl.Parse(raw)
	if err != nil || parsed.Host == "" {
		return false
	}
	// Userinfo-bearing URLs are never "non-actionable" -- the
	// hostname after the @ is the real destination. Refuse them
	// outright so DriftNewEndpoint sees them.
	if parsed.User != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	if _, ok := ignoredHostnames[host]; ok {
		return true
	}
	// Treat the entire 127.0.0.0/8 loopback range as ignorable.
	if literal := net.ParseIP(host); literal != nil && literal.IsLoopback() {
		return true
	}
	return false
}

// SnapshotTarget walks a directory and captures hashed state for drift detection.
func SnapshotTarget(root string) (*TargetSnapshot, error) {
	return snapshotTarget(root, false)
}

// snapshotTarget includes every in-root entry for plugins because their
// published identity covers bundled dependencies and otherwise skipped files.
func snapshotTarget(root string, fullTree bool) (*TargetSnapshot, error) {
	snap := &TargetSnapshot{
		DependencyHashes: make(map[string]string),
		ConfigHashes:     make(map[string]string),
		Timestamp:        time.Now().UTC(),
	}

	endpointSet := make(map[string]bool)
	var allHashes []string

	realRoot, _ := filepath.EvalSymlinks(root)
	if realRoot == "" {
		realRoot = root
	}

	var walkErrors int
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if fullTree {
				// An unreadable entry is part of this snapshot. If it becomes
				// readable, the hash changes and the plugin is scanned again.
				allHashes = append(allHashes, path+":walk-error:"+err.Error())
				return nil
			}
			walkErrors++
			if walkErrors <= 5 {
				fmt.Fprintf(os.Stderr, "[snapshot] walk error %s: %v\n", path, err)
			}
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if fullTree {
				rel, relErr := filepath.Rel(root, path)
				if relErr != nil {
					return relErr
				}
				target, readErr := os.Readlink(path)
				if readErr != nil {
					allHashes = append(allHashes, rel+":link-error:"+readErr.Error())
					return nil
				}
				allHashes = append(allHashes, rel+":link:"+target+":resolves:"+linkResolution(path, target))
			}
			return nil
		}
		if info.IsDir() {
			base := info.Name()
			if !fullTree && snapshotSkippedDir(base) {
				return filepath.SkipDir
			}
			if path != root {
				realDir, linkErr := filepath.EvalSymlinks(path)
				if linkErr == nil && !strings.HasPrefix(realDir, realRoot+string(filepath.Separator)) && realDir != realRoot {
					return filepath.SkipDir
				}
			}
			return nil
		}

		rel, _ := filepath.Rel(root, path)
		base := filepath.Base(path)
		ext := strings.ToLower(filepath.Ext(path))
		if !info.Mode().IsRegular() {
			if fullTree {
				// A special entry can wait for a peer when opened. Keep its mode
				// in the plugin snapshot without changing the legacy scope. A
				// reparse entry that is not reported as a symlink, such as a
				// Windows junction (ModeIrregular), still names a target:
				// record it like a symlink, so a retarget changes the snapshot.
				entry := rel + ":special:" + info.Mode().String()
				if target, readErr := os.Readlink(path); readErr == nil {
					entry += ":link:" + target + ":resolves:" + linkResolution(path, target)
				}
				allHashes = append(allHashes, entry)
			}
			return nil
		}

		h, hashErr := hashFile(path)
		if hashErr != nil {
			if fullTree {
				allHashes = append(allHashes, rel+":hash-error:"+hashErr.Error())
				return nil
			}
			walkErrors++
			if walkErrors <= 5 {
				fmt.Fprintf(os.Stderr, "[snapshot] hash error %s: %v\n", path, hashErr)
			}
			return nil
		}
		allHashes = append(allHashes, rel+":"+h)

		if dependencyFiles[base] {
			snap.DependencyHashes[rel] = h
		}
		if configFiles[base] {
			snap.ConfigHashes[rel] = h
		}

		if codeExtensions[ext] && (!fullTree || !snapshotUnderSkippedDir(rel)) {
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

// Bounds that match the plugin admission walk of a link target.
const (
	linkResolutionMaxSteps = 256
	linkResolutionMaxLinks = 40
)

// linkResolution describes everything plugin admission reads to validate a
// link in the plugin tree: the text of every link on the way to its target,
// including links outside the plugin root, the final location with its volume
// and file ID, and the package manifest there. A change to any of them
// changes the plugin snapshot, so an allowed baseline is not reused for a
// link whose validated resolution changed, even when a different directory
// takes the place of the validated one.
func linkResolution(link, target string) string {
	var out strings.Builder
	current := filepath.Dir(link)
	if filepath.IsAbs(target) {
		current = linkPathAnchor(target)
	}
	pending := linkPathNames(target)
	for steps, links := 0, 0; len(pending) > 0; {
		if steps++; steps > linkResolutionMaxSteps {
			out.WriteString("|too-deep")
			break
		}
		name := pending[0]
		pending = pending[1:]
		switch name {
		case ".":
			continue
		case "..":
			current = filepath.Dir(current)
			continue
		}
		current = filepath.Join(current, name)
		next, err := os.Readlink(current)
		if err != nil {
			continue
		}
		if links++; links > linkResolutionMaxLinks {
			out.WriteString("|too-many-links")
			break
		}
		out.WriteString("|" + current + "->" + next)
		if filepath.IsAbs(next) {
			current = linkPathAnchor(next)
		} else {
			current = filepath.Dir(current)
		}
		pending = append(linkPathNames(next), pending...)
	}
	resolved, err := filepath.EvalSymlinks(link)
	if err != nil {
		out.WriteString("|resolve-error:" + err.Error())
		return out.String()
	}
	out.WriteString("|resolved:" + resolved)
	if id, idErr := snapshotFileIdentity(resolved); idErr == nil {
		out.WriteString("|id:" + id)
	} else {
		out.WriteString("|id-error:" + idErr.Error())
	}
	if info, statErr := os.Stat(resolved); statErr == nil && info.IsDir() {
		if h, hashErr := hashFile(filepath.Join(resolved, "package.json")); hashErr == nil {
			out.WriteString("|manifest:" + h)
		} else {
			out.WriteString("|manifest-error:" + hashErr.Error())
		}
	}
	return out.String()
}

// linkPathAnchor returns the volume and root of an absolute path.
func linkPathAnchor(path string) string {
	return filepath.VolumeName(path) + string(filepath.Separator)
}

// linkPathNames returns the names after the volume and root, unchanged, so
// a name followed by ".." is still walked.
func linkPathNames(path string) []string {
	return strings.FieldsFunc(path[len(filepath.VolumeName(path)):], func(r rune) bool {
		return r < 0x80 && os.IsPathSeparator(uint8(r))
	})
}

func snapshotSkippedDir(name string) bool {
	return name == ".git" || name == "node_modules" || name == "__pycache__" || name == ".venv" || name == "venv"
}

func snapshotUnderSkippedDir(rel string) bool {
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if snapshotSkippedDir(part) {
			return true
		}
	}
	return false
}

func hashFile(path string) (string, error) {
	f, err := openSnapshotFile(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("snapshot entry is not a regular file: %s", path)
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func extractEndpoints(path string) []string {
	f, err := openSnapshotFile(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}

	const maxScanSize = 512 * 1024
	data, err := io.ReadAll(io.LimitReader(f, maxScanSize))
	if err != nil {
		return nil
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
