// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/mcpkey"
)

// MCPEventPath is the durable key for an MCP server's event, snapshot and
// enrolled-account journal. Each tuple field is length-prefixed and hex
// encoded, so punctuation in a name or folder cannot be read as scope.
func MCPEventPath(server config.MCPServerEntry) string {
	return mcpkey.Encode(mcpkey.Identity(mcpIdentityForServer(server)))
}

func decodeMCPEventPath(path string) (mcpSnapshotIdentity, bool) {
	identity, ok := mcpkey.Decode(path)
	return mcpSnapshotIdentity(identity), ok
}
