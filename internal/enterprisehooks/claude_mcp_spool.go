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

// ReadClaudeMCPSpool returns the Claude Code MCP servers published for sid,
// tagged claudecode, after trust validates the record file.
func ReadClaudeMCPSpool(dir, sid string, trust func(path, label string) error) ([]config.MCPServerEntry, error) {
	key := strings.ToUpper(strings.TrimSpace(sid))
	if dir == "" || !strings.HasPrefix(key, "S-1-") || !validIdentitySpoolKey(key) {
		return nil, os.ErrNotExist
	}
	path := filepath.Join(dir, key+".json")
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxClaudeMCPSpoolRecordBytes {
		return nil, errors.New("claude mcp spool record is not a regular file within the size limit")
	}
	if trust != nil {
		if err := trust(path, "claude mcp spool record"); err != nil {
			return nil, err
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxClaudeMCPSpoolRecordBytes+1))
	if err != nil {
		return nil, err
	}
	var record ClaudeMCPSpoolRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return nil, fmt.Errorf("parse claude mcp spool record: %w", err)
	}
	if record.Version != ClaudeMCPSpoolRecordVersion {
		return nil, fmt.Errorf("unsupported claude mcp spool record version %d", record.Version)
	}
	if !strings.EqualFold(record.Key, key) {
		return nil, errors.New("claude mcp spool record names another account")
	}
	out := make([]config.MCPServerEntry, 0, len(record.Servers))
	for _, server := range record.Servers {
		entry := server.Server
		entry.Connector, entry.Project = "claudecode", server.Project
		out = append(out, entry)
	}
	return out, nil
}
