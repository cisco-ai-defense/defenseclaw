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
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// maxClaudeStateBytes bounds the ~/.claude.json read; the file holds the
// history of every project and can grow to several megabytes.
const maxClaudeStateBytes = 32 << 20

// maxClaudeProjectMCPBytes bounds a project .mcp.json read.
const maxClaudeProjectMCPBytes = 1 << 20

// WriteWindowsClaudeMCPSpool publishes, for every user the manifest enrolls
// for Claude Code, the MCP servers of that user (ClaudeMCPSpoolDirName). It
// reads ~/.claude.json and the .mcp.json of each project named there,
// including projects outside the profile, without following reparse points.
// A record is rewritten only when its servers change; records of users no
// longer enrolled are removed. A user whose state is unreadable or malformed
// gets a record that says so, without servers: an old definition is never
// presented as the current state, and the gateway fails closed for that
// user's Claude Code MCP servers (GAP-0829).
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
		servers, unreadablePath, err := windowsClaudeStateServers(home)
		var data []byte
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			if logf != nil {
				logf("[hook-enumerator] WARN Claude Code MCP servers for %s: %v", key, err)
			}
			data, err = MarshalClaudeMCPSpoolUnreadable(key, ClaudeStateUnreadable{
				User: strings.TrimSpace(target.User), Home: home, Path: unreadablePath, Reason: err.Error(),
			})
		} else {
			data, err = MarshalClaudeMCPSpoolRecord(key, servers)
		}
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
func windowsClaudeStateServers(home string) ([]config.MCPServerEntry, string, error) {
	statePath := filepath.Join(home, ".claude.json")
	data, err := readWindowsProfileFile(home, ".claude.json", maxClaudeStateBytes)
	if err != nil {
		return nil, statePath, err
	}
	var projectErr error
	var projectPath string
	servers, err := config.ClaudeStateMCPServers(data, func(project string) ([]byte, error) {
		data, readErr := readWindowsClaudeProjectMCP(project)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) && projectErr == nil {
			projectPath = filepath.Join(project, ".mcp.json")
			projectErr = fmt.Errorf("read Claude Code project MCP file %s: %w", projectPath, readErr)
		}
		return data, readErr
	})
	if err != nil {
		return nil, statePath, err
	}
	if projectErr != nil {
		return nil, projectPath, projectErr
	}
	return servers, "", nil
}

// Project keys are user-controlled. Reject UNC, device, mapped and substituted
// drives before any filesystem access to the project, since the enumerator
// runs as LocalSystem and must never connect to a user-selected network path.
func readWindowsClaudeProjectMCP(project string) ([]byte, error) {
	project = filepath.Clean(project)
	if _, err := winpath.ValidateFixedNTFSMountedPath(project); err != nil {
		return nil, err
	}
	if err := rejectWindowsReparseChain(project); err != nil {
		return nil, err
	}
	return readWindowsProfileFile(project, ".mcp.json", maxClaudeProjectMCPBytes)
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
