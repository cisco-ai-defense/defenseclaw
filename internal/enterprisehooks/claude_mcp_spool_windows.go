// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	gatewayconnector "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// maxClaudeStateBytes bounds the ~/.claude.json read; the file holds the
// history of every project and can grow to several megabytes.
const maxClaudeStateBytes = 32 << 20

// maxClaudeProjectMCPBytes bounds a project .mcp.json read.
const maxClaudeProjectMCPBytes = 1 << 20

// WriteWindowsClaudeMCPSpool publishes, for every user the manifest enrolls
// for Claude Code, the MCP servers of that user (ClaudeMCPSpoolDirName). It
// reads ~/.claude.json, and the .mcp.json of each project inside the
// profile, without following a link or junction below the profile, so a
// user cannot point the LocalSystem read anywhere else. A record is rewritten
// only when its servers change; records of users no longer enrolled are
// removed. An unreadable state file keeps the last record.
func WriteWindowsClaudeMCPSpool(dir string, manifest Manifest, setOwnership func(string) error, logf func(string, ...any)) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create claude mcp spool: %w", err)
	}
	if setOwnership != nil {
		if err := setOwnership(dir); err != nil {
			return fmt.Errorf("set claude mcp spool protection: %w", err)
		}
	}
	keep := map[string]bool{}
	for _, target := range manifest.Targets {
		if !strings.EqualFold(strings.TrimSpace(target.Connector), "claudecode") || (target.Enabled != nil && !*target.Enabled) {
			continue
		}
		key := strings.ToUpper(strings.TrimSpace(target.SID))
		home := filepath.Clean(strings.TrimSpace(target.UserHome))
		name := key + ".json"
		if !strings.HasPrefix(key, "S-1-") || !validIdentitySpoolKey(key) || !filepath.IsAbs(home) || keep[strings.ToLower(name)] {
			continue
		}
		keep[strings.ToLower(name)] = true
		servers, err := windowsClaudeStateServers(home)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) && logf != nil {
				logf("[hook-enumerator] WARN Claude Code MCP servers for %s: %v", key, err)
			}
			if !errors.Is(err, os.ErrNotExist) {
				continue // keep the last record
			}
		}
		data, err := MarshalClaudeMCPSpoolRecord(key, servers)
		if err != nil {
			continue
		}
		if current, readErr := os.ReadFile(filepath.Join(dir, name)); readErr == nil && bytes.Equal(current, data) {
			continue
		}
		if err := writeSpoolBytes(dir, name, ".claude-mcp-*", data, setOwnership); err != nil && logf != nil {
			logf("[hook-enumerator] WARN publish Claude Code MCP servers for %s: %v", key, err)
		}
	}
	if entries, err := os.ReadDir(dir); err == nil {
		for _, entry := range entries {
			if !keep[strings.ToLower(entry.Name())] {
				_ = os.RemoveAll(filepath.Join(dir, entry.Name()))
			}
		}
	}
	return nil
}

// windowsClaudeStateServers reads the Claude Code MCP servers of the user
// whose profile is home.
func windowsClaudeStateServers(home string) ([]config.MCPServerEntry, error) {
	data, err := readWindowsProfileFile(home, ".claude.json", maxClaudeStateBytes)
	if err != nil {
		return nil, err
	}
	return config.ClaudeStateMCPServers(data, func(project string) ([]byte, error) {
		rel, err := filepath.Rel(home, filepath.Clean(project))
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			return nil, os.ErrNotExist // only projects inside the profile
		}
		return readWindowsProfileFile(home, filepath.Join(rel, ".mcp.json"), maxClaudeProjectMCPBytes)
	})
}

// readWindowsProfileFile reads home\rel when no element below home is a
// link or other reparse point and the file is stable while it is read.
func readWindowsProfileFile(home, rel string, limit int64) ([]byte, error) {
	if err := inventoryDACLRejectLinkBelow(home, rel); err != nil {
		return nil, err
	}
	path := filepath.Join(home, rel)
	if _, err := os.Lstat(path); err != nil {
		return nil, err
	}
	data, ok := gatewayconnector.ReadStableInventoryFile(path, limit)
	if !ok {
		return nil, fmt.Errorf("%s is unreadable, changing, a link or larger than %d bytes", filepath.Base(path), limit)
	}
	return data, nil
}
