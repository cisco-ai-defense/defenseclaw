// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// OpenCode V2 runs a background server per account on 127.0.0.1. On the
// release channel its port is 49374 for every account, so on a computer with
// several users only the first one's server starts (gas-ux-r1 GAP-0053). Each
// account gets a port of its own, written as "port" in OpenCode's own
// service.json. The CLI (cli/defenseclaw/opencode_service.py) uses the same
// scheme for per-user installs; the guardian uses it for managed ones.
const (
	// OpenCodeDefaultServicePort is OpenCode 2.2.5's port for the latest,
	// dev, beta and next channels.
	OpenCodeDefaultServicePort = 49374
	// OpenCodeAccountPortBase and OpenCodeAccountPortSpan: an account's port
	// is base + (id mod span), below Linux's ephemeral range.
	OpenCodeAccountPortBase = 24000
	OpenCodeAccountPortSpan = 8000
	// openCodeServiceConfigLimit bounds the service.json read.
	openCodeServiceConfigLimit = 64 * 1024
)

// OpenCodeServiceConfigPath is OpenCode's service.json under home: OpenCode
// keeps it in the XDG config folder, ~/.config/opencode on every OS.
func OpenCodeServiceConfigPath(home string) string {
	return filepath.Join(home, ".config", "opencode", "service.json")
}

// OpenCodeAccountPort is the first port tried for account id (a uid, or the
// RID of a Windows SID).
func OpenCodeAccountPort(id uint64) int {
	return OpenCodeAccountPortBase + int(id%OpenCodeAccountPortSpan)
}

// AssignOpenCodeServicePorts gives every id a distinct port. An id in kept
// keeps its port (the one already in its service.json, or the one an earlier
// pass gave it), so ports stay the same across passes, upgrades and new
// accounts. Every other id, in ascending order, takes the first port from
// its own OpenCodeAccountPort that no other id holds.
func AssignOpenCodeServicePorts(ids []int, kept map[int]int) map[int]int {
	sorted := append([]int(nil), ids...)
	sort.Ints(sorted)
	assigned := make(map[int]int, len(sorted))
	taken := map[int]bool{}
	for _, id := range sorted {
		if port, ok := kept[id]; ok && port > 0 && !taken[port] {
			assigned[id] = port
			taken[port] = true
		}
	}
	for _, id := range sorted {
		if _, ok := assigned[id]; ok || id < 0 {
			continue
		}
		start := OpenCodeAccountPort(uint64(id))
		for step := 0; step < OpenCodeAccountPortSpan; step++ {
			port := OpenCodeAccountPortBase + (start-OpenCodeAccountPortBase+step)%OpenCodeAccountPortSpan
			if !taken[port] {
				assigned[id] = port
				taken[port] = true
				break
			}
		}
	}
	return assigned
}

// AssignOpenCodeServicePortsByAccountWithClaims uses the same candidate range
// for accounts whose numeric ids can collide. On Windows the id is a SID's
// RID, while the full SID remains the assignment key across domains and
// passes. Callers include every account from the protected record even when
// it is no longer eligible or Windows cannot currently resolve it. A claim
// owned by another account, including an unreadable claim, excludes that
// port from a new assignment;
// it never displaces an existing reservation.
func AssignOpenCodeServicePortsByAccountWithClaims(ids map[string]uint64, kept map[string]int, claims map[int]string) map[string]int {
	keys := make([]string, 0, len(ids))
	for key := range ids {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	assigned := make(map[string]int, len(keys))
	taken := make(map[int]bool, len(keys))
	for _, key := range keys {
		if port := kept[key]; port > 0 && port <= 65535 && !taken[port] {
			assigned[key] = port
			taken[port] = true
		}
	}
	for _, key := range keys {
		if assigned[key] != 0 {
			continue
		}
		start := OpenCodeAccountPort(ids[key]) - OpenCodeAccountPortBase
		for step := 0; step < OpenCodeAccountPortSpan; step++ {
			port := OpenCodeAccountPortBase + (start+step)%OpenCodeAccountPortSpan
			if !taken[port] && (claims[port] == "" || claims[port] == key) {
				assigned[key] = port
				taken[port] = true
				break
			}
		}
	}
	return assigned
}

// ReadOpenCodeServicePort is the port the service.json under home names, or 0
// (no file, a link, not a regular file, no port, unreadable). The guardian
// reads it as root before it assigns ports, so a new port never takes one
// an account set itself; it never writes as root.
func ReadOpenCodeServicePort(home string) int {
	home = strings.TrimSpace(home)
	if home == "" || !filepath.IsAbs(home) {
		return 0
	}
	home = filepath.Clean(home)
	// Read through real folders only: a link the account put in place of
	// ~/.config or ~/.config/opencode would point the root read elsewhere.
	for _, dir := range []string{filepath.Join(home, ".config"), filepath.Join(home, ".config", "opencode")} {
		if info, err := os.Lstat(dir); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !openCodeServiceDirIsReal(dir) {
			return 0
		}
	}
	data, exists, regular, err := readUserFile(OpenCodeServiceConfigPath(home), openCodeServiceConfigLimit)
	if err != nil || !exists || !regular {
		return 0
	}
	var doc struct {
		Port json.RawMessage `json:"port"`
	}
	if json.Unmarshal(data, &doc) != nil || len(doc.Port) == 0 {
		return 0
	}
	var port int
	if json.Unmarshal(doc.Port, &port) != nil || port <= 0 || port > 65535 {
		return 0
	}
	return port
}

// OpenCodeServicePortResult is what EnsureOpenCodeServicePort found or did.
type OpenCodeServicePortResult struct {
	// Port is the port the account's service.json names after the call (0
	// when it names none).
	Port int
	// Changed reports that this call wrote the port.
	Changed bool
	// CreatedDirs are the folders below home the write created.
	CreatedDirs []string
}

// EnsureOpenCodeServicePort writes port as "port" into the account's
// service.json, as the account (the guardian's per-user worker). A port the
// file already names is kept, whoever set it; the other keys (OpenCode's
// password) are kept. A missing file is created at 0600; OpenCode adds its
// password on the next start (checked with 2.2.5). A link, a non-regular
// file or a file that is not a JSON object is left alone with an error.
func EnsureOpenCodeServicePort(home string, port int) (OpenCodeServicePortResult, error) {
	var result OpenCodeServicePortResult
	home = strings.TrimSpace(home)
	if home == "" || !filepath.IsAbs(home) {
		return result, fmt.Errorf("opencode service port: home %q is not absolute", home)
	}
	home = filepath.Clean(home)
	if port <= 0 || port > 65535 {
		return result, fmt.Errorf("opencode service port: %d is not a port", port)
	}
	path := OpenCodeServiceConfigPath(home)
	current, exists, regular, err := readUserFile(path, openCodeServiceConfigLimit)
	if err != nil {
		return result, fmt.Errorf("opencode service port: read %s: %w", path, err)
	}
	doc := map[string]json.RawMessage{}
	if exists {
		if !regular {
			return result, fmt.Errorf("opencode service port: %s is not a regular file; left in place", path)
		}
		if len(strings.TrimSpace(string(current))) > 0 {
			if err := json.Unmarshal(current, &doc); err != nil || doc == nil {
				return result, fmt.Errorf("opencode service port: %s is not a JSON object; left in place", path)
			}
		}
		if raw, ok := doc["port"]; ok {
			var existing int
			if err := json.Unmarshal(raw, &existing); err != nil || existing <= 0 || existing > 65535 {
				return result, fmt.Errorf("opencode service port: %s names a port that is not a number; left in place", path)
			}
			result.Port = existing
			return result, nil
		}
	}
	encoded, _ := json.Marshal(port)
	doc["port"] = encoded
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return result, err
	}
	missing := missingDirsBelow(home, path)
	if err := writeOpenCodeServiceConfig(home, path, append(data, '\n')); err != nil {
		return result, fmt.Errorf("opencode service port: write %s: %w", path, err)
	}
	result.Port, result.Changed, result.CreatedDirs = port, true, missing
	return result, nil
}
