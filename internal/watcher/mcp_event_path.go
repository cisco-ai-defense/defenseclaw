// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

const mcpEventPathPrefix = "mcp:v2:"

// MCPEventPath is the durable key for an MCP server's event, snapshot and
// enrolled-account journal. Each tuple field is length-prefixed and hex
// encoded, so punctuation in a name or folder cannot be read as scope.
func MCPEventPath(server config.MCPServerEntry) string {
	var key strings.Builder
	key.WriteString(mcpEventPathPrefix)
	for _, field := range []string{server.Name, server.Connector, server.Home, server.Project} {
		key.WriteString(strconv.Itoa(len(field)))
		key.WriteByte(':')
		key.WriteString(hex.EncodeToString([]byte(field)))
	}
	return key.String()
}

func decodeMCPEventPath(path string) (mcpSnapshotIdentity, bool) {
	var identity mcpSnapshotIdentity
	rest, ok := strings.CutPrefix(path, mcpEventPathPrefix)
	if !ok {
		return identity, false
	}
	fields := []*string{&identity.Name, &identity.Connector, &identity.Home, &identity.Project}
	for _, field := range fields {
		colon := strings.IndexByte(rest, ':')
		if colon < 1 {
			return mcpSnapshotIdentity{}, false
		}
		n, err := strconv.Atoi(rest[:colon])
		if err != nil || n < 0 || strconv.Itoa(n) != rest[:colon] || n > (len(rest)-colon-1)/2 {
			return mcpSnapshotIdentity{}, false
		}
		raw, err := hex.DecodeString(rest[colon+1 : colon+1+2*n])
		if err != nil {
			return mcpSnapshotIdentity{}, false
		}
		*field = string(raw)
		rest = rest[colon+1+2*n:]
	}
	return identity, rest == ""
}

// legacyMCPEventPath names snapshots written before the versioned tuple key.
// It is used only to read and retire an old row for an exact known server.
func legacyMCPEventPath(server config.MCPServerEntry) string {
	key := server.Name
	switch {
	case server.Home != "":
		key += "@" + server.Connector + ":" + server.Home
	case server.Connector != "" && server.Project == "":
		key += "@" + server.Connector
	}
	if server.Project != "" {
		key += "@" + server.Connector + "#" + server.Project
	}
	return key
}
