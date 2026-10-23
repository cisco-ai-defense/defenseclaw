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

// maxKiroMCPBytes bounds the ~/.kiro/settings/mcp.json read.
const maxKiroMCPBytes = 1 << 20

// windowsMCPSpoolSource is the MCP server file of one connector that the
// enumerator publishes for each user it enrolls for that connector.
type windowsMCPSpoolSource struct {
	connector, label, tmpPattern string
	// file is the file below the user home that holds the servers.
	file string
	// read returns the servers of the user whose profile is home, and the
	// path of the file that failed when err is set.
	read func(sid, home string, logf func(string, ...any)) ([]config.MCPServerEntry, string, error)
}

var windowsClaudeMCPSpoolSource = windowsMCPSpoolSource{
	connector: "claudecode", label: "Claude Code", tmpPattern: ".claude-mcp-*", file: ".claude.json",
	read: windowsClaudeStateServers,
}

var windowsKiroMCPSpoolSource = windowsMCPSpoolSource{
	connector: "kiro", label: "Kiro", tmpPattern: ".kiro-mcp-*", file: `.kiro\settings\mcp.json`,
	read: func(_, home string, _ func(string, ...any)) ([]config.MCPServerEntry, string, error) {
		path := filepath.Join(home, ".kiro", "settings", "mcp.json")
		data, err := readWindowsProfileFile(home, `.kiro\settings\mcp.json`, maxKiroMCPBytes)
		if err != nil {
			return nil, path, err
		}
		servers, err := config.ParseKiroUserMCPServers(data, path)
		if err != nil {
			return nil, path, fmt.Errorf("parse %s: %w", path, err)
		}
		return servers, "", nil
	},
}

// WriteWindowsClaudeMCPSpool publishes, for every user the manifest enrolls
// for Claude Code, the MCP servers of that user (ClaudeMCPSpoolDirName). It
// reads ~/.claude.json and the .mcp.json of each project named there,
// including projects outside the profile, without following reparse points.
// A record is rewritten only when its servers change; records of users no
// longer enrolled are removed. A user whose state is unreadable or malformed
// gets a record that says so, without servers: an old definition is never
// presented as the current state, and the gateway fails closed for that
// user's Claude Code MCP servers (GAP-0829). A record that cannot be
// updated is withdrawn for the same reason, and the error names it
// (GAP-1405): each such record is an *MCPSpoolRecordError
// (MCPSpoolRecordFailures), any other error is the folder's.
func WriteWindowsClaudeMCPSpool(dir string, manifest Manifest, setOwnership func(string) error, logf func(string, ...any)) error {
	return writeWindowsMCPSpool(dir, manifest, windowsClaudeMCPSpoolSource, setOwnership, logf)
}

// WriteWindowsKiroMCPSpool publishes, the same way, the user MCP servers
// (~/.kiro/settings/mcp.json) of every user the manifest enrolls for Kiro
// (KiroMCPSpoolDirName): the guardian protects that user's .kiro, so the
// gateway service cannot read the file and admitted none of its servers
// (GAP-1468).
func WriteWindowsKiroMCPSpool(dir string, manifest Manifest, setOwnership func(string) error, logf func(string, ...any)) error {
	return writeWindowsMCPSpool(dir, manifest, windowsKiroMCPSpoolSource, setOwnership, logf)
}

func writeWindowsMCPSpool(dir string, manifest Manifest, source windowsMCPSpoolSource, setOwnership func(string) error, logf func(string, ...any)) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create %s mcp spool: %w", source.connector, err)
	}
	if setOwnership != nil {
		if err := setOwnership(dir); err != nil {
			return fmt.Errorf("set %s mcp spool protection: %w", source.connector, err)
		}
	}
	keep := map[string]bool{}
	var failed error
	for _, target := range manifest.Targets {
		if !strings.EqualFold(strings.TrimSpace(target.Connector), source.connector) || (target.Enabled != nil && !*target.Enabled) {
			continue
		}
		key := strings.ToUpper(strings.TrimSpace(target.SID))
		home := filepath.Clean(strings.TrimSpace(target.UserHome))
		name := key + ".json"
		if !strings.HasPrefix(key, "S-1-") || !validIdentitySpoolKey(key) || !filepath.IsAbs(home) || keep[strings.ToLower(name)] {
			continue
		}
		keep[strings.ToLower(name)] = true
		servers, unreadablePath, err := source.read(key, home, logf)
		var data []byte
		unreadable := false
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			unreadable = true
			if logf != nil {
				logf("[hook-enumerator] WARN %s MCP servers for %s: %v", source.label, key, err)
			}
			data, err = MarshalClaudeMCPSpoolUnreadable(key, ClaudeStateUnreadable{
				User: strings.TrimSpace(target.User), Home: home, Path: unreadablePath, Reason: err.Error(),
			})
		} else {
			data, err = MarshalClaudeMCPSpoolRecord(key, servers)
			if err == nil && len(data) > maxClaudeMCPSpoolRecordBytes {
				unreadable = true
				if logf != nil {
					logf("[hook-enumerator] WARN %s MCP spool for %s exceeds %d bytes", source.label, key, maxClaudeMCPSpoolRecordBytes)
				}
				data, err = MarshalClaudeMCPSpoolUnreadable(key, ClaudeStateUnreadable{
					User: strings.TrimSpace(target.User), Home: home, Path: filepath.Join(home, source.file),
					Reason: source.label + " MCP server inventory exceeds the spool size limit",
				})
			}
		}
		if err != nil {
			failed = errors.Join(failed, &MCPSpoolRecordError{
				Connector: source.connector, SID: key, Home: home, Err: withdrawMCPSpoolRecord(dir, name, err),
			})
			continue
		}
		if current, readErr := os.ReadFile(filepath.Join(dir, name)); readErr == nil && bytes.Equal(current, data) {
			continue
		}
		if err := windowsMCPSpoolWrite(dir, name, source.tmpPattern, data, setOwnership); err != nil {
			if logf != nil {
				logf("[hook-enumerator] WARN publish %s MCP servers for %s: %v", source.label, key, err)
			}
			failed = errors.Join(failed, &MCPSpoolRecordError{
				Connector: source.connector, SID: key, Home: home, Err: withdrawMCPSpoolRecord(dir, name, err),
			})
		} else if logf != nil {
			// What the gateway admits for the user, so a server that never
			// reached admission can be traced to the record (GAP-0219).
			logf("[hook-enumerator] published %s MCP servers for %s: %s", source.label, key, mcpSpoolPublishedSummary(servers, unreadable))
		}
	}
	if entries, err := os.ReadDir(dir); err == nil {
		for _, entry := range entries {
			if !keep[strings.ToLower(entry.Name())] {
				_ = os.RemoveAll(filepath.Join(dir, entry.Name()))
			}
		}
	}
	return failed
}

// windowsMCPSpoolWrite is writeSpoolBytes; tests replace it.
var windowsMCPSpoolWrite = writeSpoolBytes

// withdrawMCPSpoolRecord takes back the record name after its update failed
// with cause. Left in place it would present the user's old servers as
// current; the gateway reads a missing or unparsable record as unreadable
// state and admits none of that user's servers. A record that cannot be
// removed (the gateway holds it open) is emptied in place.
func withdrawMCPSpoolRecord(dir, name string, cause error) error {
	path := filepath.Join(dir, name)
	removeErr := os.Remove(path)
	if removeErr == nil || errors.Is(removeErr, os.ErrNotExist) {
		return fmt.Errorf("%s not updated, previous record withdrawn: %w", name, cause)
	}
	if truncateErr := os.Truncate(path, 0); truncateErr != nil {
		return fmt.Errorf("%s not updated and its previous record could not be withdrawn (%v): %w",
			name, errors.Join(removeErr, truncateErr), cause)
	}
	return fmt.Errorf("%s not updated, previous record emptied: %w", name, cause)
}

// windowsClaudeStateServers reads the Claude Code MCP servers of the user
// whose profile is home.
func windowsClaudeStateServers(sid, home string, logf func(string, ...any)) ([]config.MCPServerEntry, string, error) {
	statePath := filepath.Join(home, ".claude.json")
	data, err := readWindowsProfileFile(home, ".claude.json", maxClaudeStateBytes)
	if err != nil {
		return nil, statePath, err
	}
	var projectErr error
	var projectPath string
	refused := map[string]bool{}
	target, err := validateWindowsEnterpriseTargetSID(sid)
	if err != nil {
		return nil, statePath, err
	}
	var servers []config.MCPServerEntry
	var parseErr error
	err = windowsClaudeProjectWithUserToken(target, home, func() error {
		servers, parseErr = config.ClaudeStateMCPServers(data, func(project string) ([]byte, error) {
			data, accessErr, readErr := windowsClaudeProjectRead(project)
			switch decideClaudeProjectRead(accessErr, readErr) {
			case claudeProjectRefused:
				refused[filepath.Clean(project)] = true
				if logf != nil {
					logf("[hook-enumerator] WARN skip Claude Code MCP project %s for %s: %v", project, sid, accessErr)
				}
				return nil, accessErr
			case claudeProjectUnreadable:
				if projectErr == nil {
					projectPath = filepath.Join(project, ".mcp.json")
					cause := readErr
					if accessErr != nil {
						cause = accessErr
					}
					projectErr = fmt.Errorf("read Claude Code project MCP file %s: %w", projectPath, cause)
				}
			}
			return data, readErr
		})
		return nil
	})
	if err != nil {
		// Token and profile failures must never look like a missing .claude.json.
		return nil, statePath, fmt.Errorf("read Claude Code projects as enrolled user: %v", err)
	}
	if parseErr != nil {
		// A project .mcp.json that does not parse is named; the user's
		// servers are unknown either way (GAP-0219).
		path := statePath
		var fileErr *config.MCPFileParseError
		if errors.As(parseErr, &fileErr) {
			path = fileErr.Path
		}
		return nil, path, parseErr
	}
	if projectErr != nil {
		return nil, projectPath, projectErr
	}
	out := servers[:0]
	for _, server := range servers {
		if !refused[server.Project] {
			out = append(out, server)
		}
	}
	return out, "", nil
}

// Resolve one validated token for all projects of this user. A disconnected
// session remains signed in and must keep its MCP inventory visible.
var windowsClaudeProjectWithUserToken = withWindowsEnterpriseSessionImpersonation

// Tests replace the project open to exercise access decisions without relying
// on the test runner's Windows token or project ACL.
var windowsClaudeProjectRead = readWindowsClaudeProjectMCP

// Project keys are user-controlled. Reject UNC, device, mapped and substituted
// drives before any filesystem access to the project, since the enumerator
// runs as LocalSystem and must never connect to a user-selected network path.
// The directory and file are then opened under the validated enrolled-user
// token. A missing file leaves local-scope servers intact. Only an explicit
// access denial refuses the project.
func readWindowsClaudeProjectMCP(project string) (data []byte, accessErr, readErr error) {
	project = filepath.Clean(project)
	if _, err := winpath.ValidateFixedNTFSMountedPath(project); err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return nil, fmt.Errorf("%w: validate project path: %w", errClaudeProjectAccessDenied, err), nil
		}
		return nil, nil, err
	}
	if err := rejectWindowsReparseChain(project); err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return nil, fmt.Errorf("%w: check project path for reparse points: %w", errClaudeProjectAccessDenied, err), nil
		}
		return nil, nil, err
	}
	ptr, err := winpath.UTF16Ptr(project)
	if err != nil {
		return nil, nil, err
	}
	dir, err := windows.CreateFile(ptr, windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		wrapped := fmt.Errorf("open project directory as enrolled user: %w", err)
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return nil, fmt.Errorf("%w: %w", errClaudeProjectAccessDenied, wrapped), nil
		}
		return nil, nil, wrapped
	}
	windows.CloseHandle(dir)
	file, err := os.Open(filepath.Join(project, ".mcp.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	if err != nil {
		wrapped := fmt.Errorf("open project MCP file as enrolled user: %w", err)
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return nil, fmt.Errorf("%w: %w", errClaudeProjectAccessDenied, wrapped), nil
		}
		return nil, nil, wrapped
	}
	file.Close()
	data, readErr = readWindowsProfileFile(project, ".mcp.json", maxClaudeProjectMCPBytes)
	return data, nil, readErr
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

// windowsClaudeMCPWorkDirChecks check a server working folder. The
// enumerator runs them while it impersonates the server's user
// (WindowsMCPAsUserStarter), so the user's own access decides.
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

// mcpSpoolPublishedSummary is the published record in the enumerator log:
// the server count and names (at most 20), or that the state is unreadable.
func mcpSpoolPublishedSummary(servers []config.MCPServerEntry, unreadable bool) string {
	if unreadable {
		return "state unreadable, no servers (the warning above says why)"
	}
	names := make([]string, 0, len(servers))
	for i, server := range servers {
		if i == 20 {
			names = append(names, fmt.Sprintf("and %d more", len(servers)-20))
			break
		}
		names = append(names, server.Name)
	}
	return fmt.Sprintf("%d servers %v", len(servers), names)
}
