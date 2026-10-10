// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// ClaudeMCPSpoolDirName is the folder, beside the identity spool, where the
// managed Windows enumerator publishes the Claude Code MCP servers of each
// enrolled user. Claude Code keeps user-scope and local-scope servers in
// ~/.claude.json, in the profile root, and replaces that file on every save,
// so a read grant for the gateway service account would not last: the
// enumerator, which runs as LocalSystem, reads it and publishes the servers
// where the gateway can read them (GAP-0424).
const ClaudeMCPSpoolDirName = "claude-mcp"

// ClaudeMCPSpoolRecordVersion is the record format version.
const ClaudeMCPSpoolRecordVersion = 1

const maxClaudeMCPSpoolRecordBytes = 4 << 20

// ClaudeMCPSpoolServer is one server of a record and the project folder
// whose local scope or .mcp.json lists it (empty for the user scope).
type ClaudeMCPSpoolServer struct {
	Server  config.MCPServerEntry `json:"server"`
	Project string                `json:"project,omitempty"`
	// WorkDir is the folder a local stdio server starts in, which the
	// enumerator checked as LocalSystem, where the profile is readable; the
	// gateway service account cannot read the profile and so cannot check it
	// (GAP-1317). WorkDirRefused is the folder it did not accept and why.
	WorkDir        string `json:"work_dir,omitempty"`
	WorkDirRefused string `json:"work_dir_refused,omitempty"`
}

// ClaudeMCPSpoolRecord lists the Claude Code MCP servers of one account.
type ClaudeMCPSpoolRecord struct {
	Version int `json:"version"`
	// Key is the SID of the account; it must match the file name.
	Key     string                 `json:"key"`
	Servers []ClaudeMCPSpoolServer `json:"servers"`
	// Unreadable is set when the enumerator could not read or parse the
	// account's Claude Code state; Servers is then empty.
	Unreadable *ClaudeStateUnreadable `json:"unreadable,omitempty"`
}

// ClaudeStateUnreadable is an enrolled account whose Claude Code state
// (~/.claude.json) the enumerator could not read or parse. Its servers are
// unknown, so none of them can be admitted: the gateway refuses that
// account's Claude Code MCP tool calls and status names the account and the
// file until it can be read again (GAP-0829).
type ClaudeStateUnreadable struct {
	User   string `json:"user,omitempty"`
	Home   string `json:"home"`
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Account is how status and the refusal name the account.
func (u ClaudeStateUnreadable) Account() string {
	if strings.TrimSpace(u.User) != "" {
		return u.User
	}
	return u.Home
}

// ClaudeMCPSpoolDir is the spool folder below the hook guardian
// authorization folder.
func ClaudeMCPSpoolDir(authorizationDir string) string {
	if strings.TrimSpace(authorizationDir) == "" {
		return ""
	}
	return filepath.Join(authorizationDir, ClaudeMCPSpoolDirName)
}

// MarshalClaudeMCPSpoolRecord serializes the record of sid for servers.
func MarshalClaudeMCPSpoolRecord(sid string, servers []config.MCPServerEntry) ([]byte, error) {
	record := ClaudeMCPSpoolRecord{Version: ClaudeMCPSpoolRecordVersion, Key: sid, Servers: []ClaudeMCPSpoolServer{}}
	for _, server := range servers {
		record.Servers = append(record.Servers, ClaudeMCPSpoolServer{
			Server: server, Project: server.Project, WorkDir: server.WorkDir, WorkDirRefused: server.WorkDirRefused,
		})
	}
	return json.Marshal(record)
}

// MarshalClaudeMCPSpoolUnreadable serializes the record of sid whose Claude
// Code state could not be read.
func MarshalClaudeMCPSpoolUnreadable(sid string, unreadable ClaudeStateUnreadable) ([]byte, error) {
	return json.Marshal(ClaudeMCPSpoolRecord{
		Version: ClaudeMCPSpoolRecordVersion, Key: sid, Servers: []ClaudeMCPSpoolServer{}, Unreadable: &unreadable,
	})
}

// ReadClaudeMCPSpool returns the Claude Code MCP servers published for sid,
// tagged claudecode, after trust validates the record file, and the marker
// of a state the enumerator could not read.
func ReadClaudeMCPSpool(dir, sid string, trust func(path, label string) error) ([]config.MCPServerEntry, *ClaudeStateUnreadable, error) {
	key := strings.ToUpper(strings.TrimSpace(sid))
	if dir == "" || !strings.HasPrefix(key, "S-1-") || !validIdentitySpoolKey(key) {
		return nil, nil, os.ErrNotExist
	}
	path := filepath.Join(dir, key+".json")
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxClaudeMCPSpoolRecordBytes {
		return nil, nil, errors.New("claude mcp spool record is not a regular file within the size limit")
	}
	if trust != nil {
		if err := trust(path, "claude mcp spool record"); err != nil {
			return nil, nil, err
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxClaudeMCPSpoolRecordBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if len(data) > maxClaudeMCPSpoolRecordBytes {
		return nil, nil, errors.New("claude mcp spool record exceeds the size limit")
	}
	var record ClaudeMCPSpoolRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return nil, nil, fmt.Errorf("parse claude mcp spool record: %w", err)
	}
	if record.Version != ClaudeMCPSpoolRecordVersion {
		return nil, nil, fmt.Errorf("unsupported claude mcp spool record version %d", record.Version)
	}
	if !strings.EqualFold(record.Key, key) {
		return nil, nil, errors.New("claude mcp spool record names another account")
	}
	out := make([]config.MCPServerEntry, 0, len(record.Servers))
	for _, server := range record.Servers {
		entry := server.Server
		entry.Connector, entry.Project = "claudecode", server.Project
		// The working folder is the enumerator result only when trust has
		// proved the record is the enumerator one.
		if trust != nil {
			entry.WorkDir, entry.WorkDirRefused = server.WorkDir, server.WorkDirRefused
		}
		out = append(out, entry)
	}
	return out, record.Unreadable, nil
}

// ReadClaudeStateUnreadable lists the accounts whose Claude Code state the
// enumerator could not read, from the records in dir.
func ReadClaudeStateUnreadable(dir string) []ClaudeStateUnreadable {
	entries, err := os.ReadDir(dir)
	if dir == "" || err != nil {
		return nil
	}
	var out []ClaudeStateUnreadable
	for _, entry := range entries {
		sid, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok {
			continue
		}
		if _, unreadable, err := ReadClaudeMCPSpool(dir, sid, nil); err == nil && unreadable != nil {
			out = append(out, *unreadable)
		}
	}
	return out
}

// claudeMCPWorkDirChecks are the file system checks of a server working
// folder, made by the enumerator where the user profile is readable.
type claudeMCPWorkDirChecks struct {
	// volume fails for a path that is not on a fixed local volume (UNC,
	// device, mapped or substituted drive).
	volume func(path string) error
	// noLinks fails when any folder of path is a link or reparse point.
	noLinks func(path string) error
	// final opens the folder itself, never what a link names, and returns
	// the path the system reports for it; it fails for a missing folder,
	// a file and a folder that cannot be opened.
	final func(path string) (string, error)
}

// vetClaudeMCPWorkDirs sets WorkDir and WorkDirRefused of each local stdio
// server of the account whose profile is home (GAP-1317).
func vetClaudeMCPWorkDirs(servers []config.MCPServerEntry, home string, otherHomes []string, checks claudeMCPWorkDirChecks) {
	for i := range servers {
		servers[i].WorkDir, servers[i].WorkDirRefused = vetClaudeMCPWorkDir(servers[i], home, otherHomes, checks)
	}
}

// vetClaudeMCPWorkDir is the folder a local stdio server starts in, as its
// agent starts it: the entry cwd, else the project that lists the server.
// A folder is accepted only when it is absolute, on a fixed local volume,
// inside the project or the user home and in no other user profile, no
// folder of it is a link or reparse point, and the opened folder has the
// same path (no short-name, junction or other alias). The returned folder
// is the opened one. refused names the first folder not accepted and why.
func vetClaudeMCPWorkDir(entry config.MCPServerEntry, home string, otherHomes []string, checks claudeMCPWorkDirChecks) (dir, refused string) {
	if entry.Command == "" || entry.URL != "" {
		return "", ""
	}
	var roots []string
	for _, root := range []string{entry.Project, home} {
		if root != "" && filepath.IsAbs(root) && !strings.ContainsRune(root, 0) {
			roots = append(roots, filepath.Clean(root))
		}
	}
	for _, candidate := range []string{entry.CWD, entry.Project} {
		if candidate == "" {
			continue
		}
		vetted, err := vetClaudeMCPWorkDirCandidate(candidate, home, roots, otherHomes, checks)
		if err == nil {
			return vetted, refused
		}
		if refused == "" {
			refused = candidate + ": " + err.Error()
		}
	}
	return "", refused
}

func vetClaudeMCPWorkDirCandidate(dir, home string, roots, otherHomes []string, checks claudeMCPWorkDirChecks) (string, error) {
	if !filepath.IsAbs(dir) || strings.ContainsRune(dir, 0) {
		return "", errors.New("the folder is not an absolute path")
	}
	dir = filepath.Clean(dir)
	if checks.volume != nil {
		if err := checks.volume(dir); err != nil {
			return "", err
		}
	}
	if err := claudeMCPWorkDirPlacement(dir, home, roots, otherHomes); err != nil {
		return "", err
	}
	if checks.noLinks != nil {
		if err := checks.noLinks(dir); err != nil {
			return "", err
		}
	}
	if checks.final == nil {
		return "", errors.New("the folder cannot be opened")
	}
	final, err := checks.final(dir)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(filepath.Clean(final), dir) {
		return "", fmt.Errorf("the folder opens as %s (a link, short name or other alias)", final)
	}
	return filepath.Clean(final), nil
}

// claudeMCPWorkDirPlacement fails for a folder outside every root or in
// another user profile: an enrolled user, or any folder beside home in the
// profiles folder.
func claudeMCPWorkDirPlacement(dir, home string, roots, otherHomes []string) error {
	inside := false
	for _, root := range roots {
		if claudeMCPPathWithin(dir, root) {
			inside = true
			break
		}
	}
	if !inside {
		return errors.New("the folder is outside the project and the user home folder")
	}
	if home != "" && claudeMCPPathWithin(dir, home) {
		return nil
	}
	profiles := []string{}
	if home != "" {
		profiles = append(profiles, filepath.Dir(filepath.Clean(home)))
	}
	for _, other := range append(profiles, otherHomes...) {
		if other != "" && claudeMCPPathWithin(dir, filepath.Clean(other)) {
			return errors.New("the folder is in another user profile")
		}
	}
	return nil
}

// claudeMCPPathWithin reports whether path is root or below it. Windows
// paths compare without case.
func claudeMCPPathWithin(path, root string) bool {
	path, root = strings.ToLower(filepath.Clean(path)), strings.ToLower(filepath.Clean(root))
	if path == root {
		return true
	}
	return strings.HasPrefix(path, strings.TrimRight(root, string(filepath.Separator))+string(filepath.Separator))
}
