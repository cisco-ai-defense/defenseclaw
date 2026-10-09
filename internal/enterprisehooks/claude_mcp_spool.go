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
		record.Servers = append(record.Servers, ClaudeMCPSpoolServer{Server: server, Project: server.Project})
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
