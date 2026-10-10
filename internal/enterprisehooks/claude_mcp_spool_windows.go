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
	"golang.org/x/sys/windows"
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
	var homes []string
	for _, target := range manifest.Targets {
		if home := strings.TrimSpace(target.UserHome); filepath.IsAbs(home) {
			homes = append(homes, filepath.Clean(home))
		}
	}
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
			vetClaudeMCPWorkDirs(servers, home, otherWindowsHomes(homes, home), windowsClaudeMCPWorkDirChecks)
			data, err = MarshalClaudeMCPSpoolRecord(key, servers)
			if err == nil && len(data) > maxClaudeMCPSpoolRecordBytes {
				if logf != nil {
					logf("[hook-enumerator] WARN Claude Code MCP spool for %s exceeds %d bytes", key, maxClaudeMCPSpoolRecordBytes)
				}
				data, err = MarshalClaudeMCPSpoolUnreadable(key, ClaudeStateUnreadable{
					User: strings.TrimSpace(target.User), Home: home, Path: filepath.Join(home, ".claude.json"),
					Reason: "Claude Code MCP server inventory exceeds the spool size limit",
				})
			}
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

// otherWindowsHomes is homes without home.
func otherWindowsHomes(homes []string, home string) []string {
	var out []string
	for _, other := range homes {
		if !strings.EqualFold(other, home) {
			out = append(out, other)
		}
	}
	return out
}

// windowsClaudeMCPWorkDirChecks check a server working folder as the
// enumerator, which runs as LocalSystem and can read every profile.
var windowsClaudeMCPWorkDirChecks = claudeMCPWorkDirChecks{
	volume: func(path string) error {
		_, err := winpath.ValidateFixedNTFSMountedPath(path)
		return err
	},
	noLinks: func(path string) error {
		if err := rejectWindowsReparseChain(path); err != nil {
			return errors.New("a folder on the way is a link or reparse point")
		}
		return nil
	},
	final: windowsWorkDirFinalPath,
}

// windowsWorkDirFinalPath opens the folder itself (never what a reparse
// point names) and returns the path Windows reports for the open folder,
// which expands short names and shows a folder replaced after the walk.
func windowsWorkDirFinalPath(path string) (string, error) {
	ptr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return "", err
	}
	handle, err := windows.CreateFile(ptr, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return "", fmt.Errorf("the folder cannot be opened: %w", err)
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return "", err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return "", errors.New("the folder is a link or reparse point")
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return "", errors.New("the path is not a folder")
	}
	final, err := inventoryDACLFinalPath(handle)
	if err != nil {
		return "", err
	}
	if trimmed, ok := strings.CutPrefix(final, `\\?\`); ok && !strings.HasPrefix(strings.ToUpper(trimmed), `UNC\`) {
		return trimmed, nil
	}
	return "", fmt.Errorf("the folder opens as %s, not a local drive path", final)
}
